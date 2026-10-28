"""Tests for release publishing rules: immutability, checksums, and bucket policy."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("aws_cdk")

_SPEC = importlib.util.spec_from_file_location(
    "publish_release", Path(__file__).resolve().parent.parent / "scripts" / "publish_release.py"
)
publish_release = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(publish_release)


class _Missing(Exception):
    response = {"Error": {"Code": "404"}}


class _FakeS3:
    def __init__(self, objects: dict[str, dict] | None = None, bucket_exists: bool = True) -> None:
        self.objects = objects or {}
        self.bucket_exists = bucket_exists
        self.calls: list[tuple[str, dict]] = []

    def head_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise _Missing()
        return {"Metadata": self.objects[Key]["Metadata"]}

    def put_object(self, **kwargs):
        self.calls.append(("put_object", kwargs))
        self.objects[kwargs["Key"]] = kwargs

    def head_bucket(self, *, Bucket):
        if not self.bucket_exists:
            raise _Missing()

    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))

        return call


def _artifact(tmp_path: Path, body: bytes = b"artifact") -> Path:
    path = tmp_path / "lambda_package.zip"
    path.write_bytes(body)
    return path


def test_publish_uploads_with_s3_verified_checksum(tmp_path):
    s3 = _FakeS3()
    path = _artifact(tmp_path)

    assert publish_release.publish_file(s3, "bucket", "releases/1.0.0/lambda_package.zip", path) == "uploaded"

    put = dict(s3.calls)["put_object"]
    digest = hashlib.sha256(b"artifact").digest()
    assert put["ChecksumSHA256"] == base64.b64encode(digest).decode()
    assert put["Metadata"]["sha256"] == digest.hex()


def test_republishing_identical_content_is_a_no_op(tmp_path):
    path = _artifact(tmp_path)
    s3 = _FakeS3({"k": {"Metadata": {"sha256": hashlib.sha256(b"artifact").hexdigest()}}})

    assert publish_release.publish_file(s3, "bucket", "k", path) == "unchanged"
    assert s3.calls == []


def test_released_keys_are_never_overwritten_with_different_content(tmp_path):
    path = _artifact(tmp_path, b"new build")
    s3 = _FakeS3({"k": {"Metadata": {"sha256": hashlib.sha256(b"original").hexdigest()}}})

    with pytest.raises(publish_release.ImmutableKeyError):
        publish_release.publish_file(s3, "bucket", "k", path)
    assert s3.calls == []


def test_bucket_policy_grants_only_allowlisted_accounts_read_on_releases():
    policy = publish_release.bucket_policy("vendor-eu-west-1", ["111111111111"])
    allow, deny = policy["Statement"]

    assert allow["Principal"] == {"AWS": ["arn:aws:iam::111111111111:root"]}
    assert allow["Action"] == "s3:GetObject"
    assert allow["Resource"] == "arn:aws:s3:::vendor-eu-west-1/releases/*"
    assert deny["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    assert "*" not in json.dumps(allow["Principal"])


def test_new_buckets_block_public_access_and_are_versioned():
    s3 = _FakeS3(bucket_exists=False)

    publish_release.ensure_bucket(s3, "vendor-eu-west-1", "eu-west-1", ["111111111111"])

    calls = dict(s3.calls)
    assert calls["create_bucket"]["CreateBucketConfiguration"] == {"LocationConstraint": "eu-west-1"}
    assert all(calls["put_public_access_block"]["PublicAccessBlockConfiguration"].values())
    assert calls["put_bucket_versioning"]["VersioningConfiguration"] == {"Status": "Enabled"}


def test_us_east_1_buckets_omit_the_location_constraint():
    s3 = _FakeS3(bucket_exists=False)

    publish_release.ensure_bucket(s3, "vendor-us-east-1", "us-east-1", ["111111111111"])

    assert "CreateBucketConfiguration" not in dict(s3.calls)["create_bucket"]
