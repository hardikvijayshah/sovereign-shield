"""CloudFormation custom resources owned by the product.

Release templates cannot use CDK's bootstrap-dependent helper functions, so
this handler, shipped in the same versioned Lambda package, performs the two
deploy-time tasks the stack needs:

- ``ConsolePublication``: copies the versioned console bundle (a zip) into the
  private console bucket, writes the stack-specific ``config.json``, removes
  files from previous releases, and invalidates the CloudFront cache. On stack
  deletion it empties the console bucket, which holds no customer data.
- ``BucketEmptier``: on stack deletion only, deletes every object version in a
  bucket so CloudFormation can delete it. Used only by the non-production
  template, whose data resources are deleted with the stack.

It never touches scanned resources.
"""

from __future__ import annotations

import io
import json
import logging
import mimetypes
import time
import urllib.request
import zipfile
from typing import Any, Callable

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
_REVALIDATE_CACHE = "no-cache"
_MAX_BUNDLE_BYTES = 50 * 1024 * 1024


def handler(event: dict[str, Any], context: Any) -> None:
    """Dispatch one custom-resource request and always report the outcome."""

    physical_id = event.get("PhysicalResourceId") or f"{event['LogicalResourceId']}-{event['RequestId']}"
    try:
        resource_type = event["ResourceType"]
        properties = event.get("ResourceProperties", {})
        if resource_type == "Custom::ConsolePublication":
            data = _console_publication(event["RequestType"], properties)
        elif resource_type == "Custom::BucketEmptier":
            data = _bucket_emptier(event["RequestType"], properties)
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")
        _respond(event, "SUCCESS", physical_id, data=data)
    except Exception as exc:  # noqa: BLE001 - CloudFormation must always receive a response
        logger.exception("Custom resource request failed")
        # Deleting a resource that never created anything must not block stack rollback.
        status = "SUCCESS" if event.get("RequestType") == "Delete" and _is_missing_bucket(exc) else "FAILED"
        _respond(event, status, physical_id, reason=f"{type(exc).__name__}: {exc}"[:500])


def _console_publication(request_type: str, properties: dict[str, Any], *, clients: Any = None) -> dict[str, str]:
    s3, cloudfront = clients or (_client("s3"), _client("cloudfront"))
    target_bucket = properties["TargetBucket"]
    if request_type == "Delete":
        _empty_bucket(s3, target_bucket)
        return {}

    bundle = s3.get_object(Bucket=properties["SourceBucket"], Key=properties["SourceKey"])["Body"].read()
    if len(bundle) > _MAX_BUNDLE_BYTES:
        raise ValueError("Console bundle exceeds the size limit.")
    published = publish_bundle(s3, target_bucket, bundle, json.loads(properties["Config"]))
    cloudfront.create_invalidation(
        DistributionId=properties["DistributionId"],
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/*"]},
            "CallerReference": f"sovereign-shield-{int(time.time() * 1000)}",
        },
    )
    return {"PublishedObjects": str(len(published))}


def publish_bundle(s3: Any, bucket: str, bundle: bytes, config: dict[str, Any]) -> set[str]:
    """Upload a console zip plus config.json, then prune keys not in this release."""

    published: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            key = _safe_key(info.filename)
            content_type = mimetypes.guess_type(key)[0] or "application/octet-stream"
            # Vite emits content-hashed names under assets/; everything else must revalidate.
            cache = _IMMUTABLE_CACHE if key.startswith("assets/") else _REVALIDATE_CACHE
            s3.put_object(
                Bucket=bucket, Key=key, Body=archive.read(info), ContentType=content_type, CacheControl=cache
            )
            published.add(key)
    s3.put_object(
        Bucket=bucket,
        Key="config.json",
        Body=json.dumps(config, separators=(",", ":")).encode("utf-8"),
        ContentType="application/json",
        CacheControl=_REVALIDATE_CACHE,
    )
    published.add("config.json")
    for key in _list_keys(s3, bucket):
        if key not in published:
            s3.delete_object(Bucket=bucket, Key=key)
    return published


def _bucket_emptier(request_type: str, properties: dict[str, Any], *, s3: Any = None) -> dict[str, str]:
    if request_type == "Delete":
        _empty_bucket(s3 or _client("s3"), properties["BucketName"])
    return {}


def _empty_bucket(s3: Any, bucket: str) -> None:
    """Delete every object version and delete marker, so the bucket can be deleted."""

    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objects = [
            {"Key": entry["Key"], "VersionId": entry["VersionId"]}
            for entry in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        for start in range(0, len(objects), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects[start : start + 1000], "Quiet": True})


def _list_keys(s3: Any, bucket: str) -> list[str]:
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(entry["Key"] for entry in page.get("Contents", []))
    return keys


def _safe_key(name: str) -> str:
    """Reject zip entries that would escape the bucket root (absolute or ``..`` paths)."""

    parts = name.replace("\\", "/").split("/")
    if name.startswith(("/", "\\")) or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"Unsafe path in console bundle: {name!r}")
    return "/".join(parts)


def _is_missing_bucket(exc: Exception) -> bool:
    response = getattr(exc, "response", {})
    code = response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""
    return code in {"NoSuchBucket", "404"}


def _respond(
    event: dict[str, Any],
    status: str,
    physical_id: str,
    *,
    data: dict[str, str] | None = None,
    reason: str = "",
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> None:
    body = json.dumps(
        {
            "Status": status,
            "Reason": reason or "See the deployment function's CloudWatch logs.",
            "PhysicalResourceId": physical_id,
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "Data": data or {},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        event["ResponseURL"],
        data=body,
        method="PUT",
        headers={"Content-Type": "", "Content-Length": str(len(body))},
    )
    with opener(request, timeout=30):
        pass


def _client(service: str) -> Any:
    import boto3

    return boto3.client(service)
