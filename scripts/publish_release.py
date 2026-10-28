"""Publish a built release to the per-region vendor artifact buckets (plan.md section 9.2).

For each supported region, ensures bucket ``<prefix>-<region>`` exists with
versioning, Block Public Access, default encryption, and a TLS-only policy
that grants ``s3:GetObject`` on ``releases/*`` to the allowlisted accounts.
Then uploads every file in ``release/<version>/`` under
``releases/<version>/`` with an S3-verified SHA-256 checksum.

Released keys are immutable: re-publishing identical content is a no-op, and
publishing different content to an existing key fails.

Usage:
    python scripts/publish_release.py --version 1.0.0 \\
        --bucket-prefix sovereign-shield-releases-<account> \\
        --reader-accounts 111111111111,222222222222 [--profile default]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "cdk"))

from stacks.sovereign_shield_stack import SUPPORTED_REGIONS, ReleaseArtifacts  # noqa: E402

CONTENT_TYPES = {
    ".yaml": "application/x-yaml",
    ".json": "application/json",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".zip": "application/zip",
}


class ImmutableKeyError(RuntimeError):
    """Raised when a released key already holds different content."""


def bucket_policy(bucket: str, reader_accounts: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowlistedAccountsReadReleases",
                "Effect": "Allow",
                "Principal": {"AWS": [f"arn:aws:iam::{account}:root" for account in reader_accounts]},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/releases/*",
            },
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }


def ensure_bucket(s3: Any, bucket: str, region: str, reader_accounts: list[str]) -> None:
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception as exc:  # noqa: BLE001 - 404 means create; anything else is a real error
        if _error_code(exc) not in {"404", "NoSuchBucket", "NotFound"}:
            raise
        request: dict[str, Any] = {"Bucket": bucket, "ObjectOwnership": "BucketOwnerEnforced"}
        if region != "us-east-1":
            request["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**request)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    # SSE-S3, not SSE-KMS: customer accounts read these objects without key grants.
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy(bucket, reader_accounts)))


def publish_file(s3: Any, bucket: str, key: str, path: Path) -> str:
    """Upload one artifact immutably; returns 'uploaded' or 'unchanged'."""

    body = path.read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    try:
        existing = s3.head_object(Bucket=bucket, Key=key)
    except Exception as exc:  # noqa: BLE001
        if _error_code(exc) not in {"404", "NoSuchKey", "NotFound"}:
            raise
        existing = None
    if existing is not None:
        if existing.get("Metadata", {}).get("sha256") == digest:
            return "unchanged"
        raise ImmutableKeyError(f"s3://{bucket}/{key} already holds a different release artifact.")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType=CONTENT_TYPES.get(path.suffix, "application/octet-stream"),
        ChecksumSHA256=base64.b64encode(bytes.fromhex(digest)).decode(),
        Metadata={"sha256": digest},
    )
    return "uploaded"


def main() -> int:
    import boto3

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--bucket-prefix", required=True)
    parser.add_argument("--reader-accounts", required=True, help="Comma-separated 12-digit account IDs.")
    parser.add_argument("--regions", default=",".join(SUPPORTED_REGIONS))
    parser.add_argument("--profile")
    args = parser.parse_args()

    artifacts = ReleaseArtifacts(version=args.version, bucket_prefix=args.bucket_prefix)
    readers = [account.strip() for account in args.reader_accounts.split(",") if account.strip()]
    if not readers or not all(re.fullmatch(r"\d{12}", account) for account in readers):
        raise SystemExit("--reader-accounts must list 12-digit AWS account IDs.")
    regions = [region.strip() for region in args.regions.split(",") if region.strip()]
    if not set(regions) <= set(SUPPORTED_REGIONS):
        raise SystemExit(f"Regions must be within the release support matrix: {', '.join(SUPPORTED_REGIONS)}.")

    release_dir = PROJECT_ROOT / "release" / artifacts.version
    manifest = json.loads((release_dir / "manifest.json").read_text(encoding="utf-8"))
    expected = {entry["file"]: entry["sha256"] for entry in manifest["artifacts"]}
    for name, digest in expected.items():
        if hashlib.sha256((release_dir / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"{name} does not match manifest.json; rebuild the release.")
    files = [release_dir / name for name in expected] + [release_dir / "manifest.json"]

    session = boto3.Session(profile_name=args.profile)
    for region in regions:
        bucket = f"{artifacts.bucket_prefix}-{region}"
        s3 = session.client("s3", region_name=region)
        ensure_bucket(s3, bucket, region, readers)
        for path in files:
            outcome = publish_file(s3, bucket, artifacts.key(path.name), path)
            print(f"{region}: {outcome:9} s3://{bucket}/{artifacts.key(path.name)}")
    print(f"\nPublished {artifacts.version}. Quick Create links: release/{artifacts.version}/RELEASE_NOTES.md")
    return 0


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", {})
    return str(response.get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""


if __name__ == "__main__":
    sys.exit(main())
