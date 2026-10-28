"""Live acceptance tests run with ONLY the release's installer policy (plan.md sections 9.3 and 12.2).

Creates a temporary IAM role holding just ``installer-policy.json`` (trusted only by
the caller's own identity), then performs each step with that role's credentials:

  upgrade   Upgrade an existing release stack by change set; refuse if any data
            resource (tables, buckets, key, user pool) would be replaced.
  rollback  Submit an update that must fail (a sign-in domain prefix containing the
            reserved word "aws") and require UPDATE_ROLLBACK_COMPLETE.
  install   Create a fresh non-production stack, then delete it, with the same role.
  removal   For each template: create, populate with the smoke test, delete, and check
            that exactly the documented resources survive. For the production template,
            then run the documented decommissioning and check nothing is left.

The temporary role is deleted at the end, whatever the outcome.

Usage:
    python scripts/live_acceptance.py --version 1.1.0 --region eu-west-1 --stack SovereignShieldRelease \\
        --bucket-prefix sovereign-shield-releases-<account> --steps upgrade,rollback,install [--profile default]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ROLE_NAME = "SovereignShieldInstallerAcceptance"
DATA_RESOURCE_TYPES = {"AWS::DynamoDB::Table", "AWS::S3::Bucket", "AWS::KMS::Key", "AWS::Cognito::UserPool"}
ACKNOWLEDGEMENT = "DELETE_ALL_SOVEREIGN_SHIELD_DATA_WITH_THE_STACK"


class AcceptanceFailure(RuntimeError):
    pass


def installer_policy(account_id: str, bucket_prefix: str) -> str:
    """Render the published policy for any stack named SovereignShield* with an ss-* prefix."""

    text = (PROJECT_ROOT / "infrastructure" / "policies" / "installer-policy.json").read_text(encoding="utf-8")
    for placeholder, value in {
        "${AccountId}": account_id,
        "${StackName}": "SovereignShield*",
        "${StackNameLowercase}": "sovereignshield*",
        "${DeploymentPrefix}": "ss-*",
        "${ArtifactBucketPrefix}": bucket_prefix,
    }.items():
        text = text.replace(placeholder, value)
    return text


def create_role(iam: Any, caller_arn: str, policy: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": caller_arn}, "Action": "sts:AssumeRole"}],
    }
    try:
        role = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Temporary: Sovereign Shield installer-policy acceptance test",
            MaxSessionDuration=3600 * 4,
        )["Role"]
    except iam.exceptions.EntityAlreadyExistsException:
        role = iam.get_role(RoleName=ROLE_NAME)["Role"]
    iam.put_role_policy(RoleName=ROLE_NAME, PolicyName="InstallerPolicy", PolicyDocument=policy)
    return role["Arn"]


def delete_role(iam: Any) -> None:
    try:
        iam.delete_role_policy(RoleName=ROLE_NAME, PolicyName="InstallerPolicy")
        iam.delete_role(RoleName=ROLE_NAME)
        print(f"Deleted temporary role {ROLE_NAME}")
    except iam.exceptions.NoSuchEntityException:
        pass


def installer_session(boto3: Any, base: Any, role_arn: str, region: str) -> Any:
    sts = base.client("sts", region_name=region, endpoint_url=f"https://sts.{region}.amazonaws.com")
    for attempt in range(12):  # new roles take a few seconds to become assumable
        try:
            credentials = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="installer-acceptance", DurationSeconds=3600 * 4
            )["Credentials"]
            break
        except Exception:  # noqa: BLE001
            if attempt == 11:
                raise
            time.sleep(5)
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


def template_url(bucket_prefix: str, region: str, version: str, template: str) -> str:
    return f"https://{bucket_prefix}-{region}.s3.{region}.amazonaws.com/releases/{version}/{template}"


def wait_for(cfn: Any, stack: str, terminal: set[str], timeout: int = 3600) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status in terminal or status.endswith("_FAILED") or status == "ROLLBACK_COMPLETE":
            return status
        time.sleep(20)
    raise AcceptanceFailure(f"{stack} did not settle within {timeout}s")


def first_failure(cfn: Any, stack: str) -> str:
    for event in cfn.describe_stack_events(StackName=stack)["StackEvents"]:
        reason = event.get("ResourceStatusReason", "")
        if "FAILED" in event["ResourceStatus"] and "cancelled" not in reason.lower():
            return f"{event['LogicalResourceId']}: {reason[:300]}"
    return "no failure event found"


def previous_parameters(cfn: Any, stack: str, overrides: dict[str, str] | None = None) -> list[dict[str, Any]]:
    current = cfn.describe_stacks(StackName=stack)["Stacks"][0]["Parameters"]
    overrides = overrides or {}
    return [
        {"ParameterKey": p["ParameterKey"], "ParameterValue": overrides[p["ParameterKey"]]}
        if p["ParameterKey"] in overrides
        else {"ParameterKey": p["ParameterKey"], "UsePreviousValue": True}
        for p in current
    ]


def step_upgrade(cfn: Any, args: argparse.Namespace) -> None:
    before = cfn.describe_stacks(StackName=args.stack)["Stacks"][0]
    before_version = {o["OutputKey"]: o["OutputValue"] for o in before.get("Outputs", [])}.get("ReleaseVersion")
    name = f"upgrade-{args.version.replace('.', '-')}-{uuid.uuid4().hex[:6]}"
    cfn.create_change_set(
        StackName=args.stack,
        ChangeSetName=name,
        ChangeSetType="UPDATE",
        TemplateURL=template_url(args.bucket_prefix, args.region, args.version, "sovereign-shield-nonprod.yaml"),
        Parameters=previous_parameters(cfn, args.stack),
        Capabilities=["CAPABILITY_IAM"],
    )
    cfn.get_waiter("change_set_create_complete").wait(
        StackName=args.stack, ChangeSetName=name, WaiterConfig={"Delay": 10, "MaxAttempts": 90}
    )
    changes = cfn.describe_change_set(StackName=args.stack, ChangeSetName=name)["Changes"]
    replaced_data = [
        c["ResourceChange"]["LogicalResourceId"]
        for c in changes
        if c["ResourceChange"]["ResourceType"] in DATA_RESOURCE_TYPES
        and (c["ResourceChange"].get("Replacement") == "True" or c["ResourceChange"]["Action"] == "Remove")
    ]
    print(f"upgrade: change set {name}: {len(changes)} changes; data resources replaced/removed: {replaced_data}")
    if replaced_data:
        cfn.delete_change_set(StackName=args.stack, ChangeSetName=name)
        raise AcceptanceFailure(f"Upgrade would replace data resources: {replaced_data}")
    cfn.execute_change_set(StackName=args.stack, ChangeSetName=name)
    status = wait_for(cfn, args.stack, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"})
    after = cfn.describe_stacks(StackName=args.stack)["Stacks"][0]
    after_version = {o["OutputKey"]: o["OutputValue"] for o in after.get("Outputs", [])}.get("ReleaseVersion")
    print(f"upgrade: {status}; release {before_version} -> {after_version}")
    if status != "UPDATE_COMPLETE" or after_version != args.version:
        raise AcceptanceFailure(f"Upgrade ended {status}: {first_failure(cfn, args.stack)}")


def step_rollback(cfn: Any, args: argparse.Namespace) -> None:
    before = cfn.describe_stacks(StackName=args.stack)["Stacks"][0]
    before_prefix = next(p["ParameterValue"] for p in before["Parameters"] if p["ParameterKey"] == "DeploymentPrefix")
    # Valid for the template's pattern, but Cognito rejects domain prefixes containing "aws".
    cfn.update_stack(
        StackName=args.stack,
        UsePreviousTemplate=True,
        Parameters=previous_parameters(cfn, args.stack, {"DeploymentPrefix": "ss-aws-rollback"}),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = wait_for(cfn, args.stack, {"UPDATE_ROLLBACK_COMPLETE", "UPDATE_COMPLETE"})
    after = cfn.describe_stacks(StackName=args.stack)["Stacks"][0]
    after_prefix = next(p["ParameterValue"] for p in after["Parameters"] if p["ParameterKey"] == "DeploymentPrefix")
    trigger = first_failure(cfn, args.stack)
    print(f"rollback: {status}; trigger: {trigger}")
    if status != "UPDATE_ROLLBACK_COMPLETE" or after_prefix != before_prefix:
        raise AcceptanceFailure(f"Expected a clean rollback to prefix {before_prefix}; got {status} / {after_prefix}")
    # Any other trigger (e.g. a permission gap) means the planned failure was never exercised,
    # and resources created before it may have been orphaned by a failed cleanup.
    if not trigger.startswith("UserPoolHostedSignInDomain"):
        raise AcceptanceFailure(f"Rollback was triggered by an unexpected failure: {trigger}")


def step_install(cfn: Any, args: argparse.Namespace) -> None:
    stack = f"SovereignShieldInstallTest{uuid.uuid4().hex[:6]}"
    cfn.create_stack(
        StackName=stack,
        TemplateURL=template_url(args.bucket_prefix, args.region, args.version, "sovereign-shield-nonprod.yaml"),
        Parameters=[
            {"ParameterKey": "DeploymentPrefix", "ParameterValue": f"ss-install-{uuid.uuid4().hex[:4]}"},
            {"ParameterKey": "AcknowledgeDataDeletion", "ParameterValue": ACKNOWLEDGEMENT},
            {"ParameterKey": "Environment", "ParameterValue": "installer-acceptance"},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )
    status = wait_for(cfn, stack, {"CREATE_COMPLETE"})
    print(f"install: {stack} {status}")
    created_ok = status == "CREATE_COMPLETE"
    failure = "" if created_ok else first_failure(cfn, stack)
    cfn.delete_stack(StackName=stack)
    try:
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack, WaiterConfig={"Delay": 20, "MaxAttempts": 180})
        print(f"install: {stack} deleted with the installer role")
    except Exception as exc:  # noqa: BLE001
        raise AcceptanceFailure(f"Delete with the installer role failed: {first_failure(cfn, stack)}") from exc
    if not created_ok:
        raise AcceptanceFailure(f"Fresh install ended {status}: {failure}")


RETAINED_TYPES = {
    "AWS::DynamoDB::Table",
    "AWS::S3::Bucket",
    "AWS::KMS::Key",
    "AWS::Cognito::UserPool",
    "AWS::Logs::LogGroup",
}


def step_removal(cfn: Any, admin: Any, args: argparse.Namespace) -> None:
    """Delete populated stacks of both templates and check what survives (OPERATIONS.md, Decommissioning)."""

    for template, retains in (("sovereign-shield-nonprod.yaml", False), ("sovereign-shield.yaml", True)):
        stack = f"SovereignShieldRemoval{uuid.uuid4().hex[:6]}"
        parameters = [
            {"ParameterKey": "DeploymentPrefix", "ParameterValue": f"ss-rm-{uuid.uuid4().hex[:4]}"},
            {"ParameterKey": "Environment", "ParameterValue": "removal-acceptance"},
        ]
        if not retains:
            parameters.append({"ParameterKey": "AcknowledgeDataDeletion", "ParameterValue": ACKNOWLEDGEMENT})
        cfn.create_stack(
            StackName=stack,
            Parameters=parameters,
            Capabilities=["CAPABILITY_IAM"],
            TemplateURL=template_url(args.bucket_prefix, args.region, args.version, template),
        )
        status = wait_for(cfn, stack, {"CREATE_COMPLETE"})
        print(f"removal: {template}: {stack} {status}")
        reads = admin.client("cloudformation")
        stack_id = reads.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
        try:
            if status != "CREATE_COMPLETE":
                raise AcceptanceFailure(f"Create ended {status}: {first_failure(cfn, stack)}")
            seed_with_smoke_test(reads, stack, args)
            resources = data_resources(reads, stack_id)
            items, objects = stored_data(admin, resources)
            print(f"removal: {stack} holds {items} table items and {objects} report objects")
            if not items or not objects:
                raise AcceptanceFailure("The smoke test did not leave data to remove")
        finally:
            cfn.delete_stack(StackName=stack)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack, WaiterConfig={"Delay": 20, "MaxAttempts": 180}
            )
            print(f"removal: {stack} deleted with the installer role")

        surviving = {r["LogicalResourceId"]: r for r in resources if resource_exists(admin, r)}
        expected = {r["LogicalResourceId"] for r in resources if retains and not is_console_bucket(r)}
        print(f"removal: retained after delete: {sorted(surviving)}")
        if set(surviving) != expected:
            raise AcceptanceFailure(
                f"{template}: unexpectedly retained {sorted(set(surviving) - expected)}; "
                f"unexpectedly deleted {sorted(expected - set(surviving))}"
            )
        if retains:
            decommission(admin, list(surviving.values()))
            left = [r["LogicalResourceId"] for r in resources if resource_exists(admin, r)]
            if left:
                raise AcceptanceFailure(f"Documented decommissioning left {left}")
            print("removal: documented decommissioning removed every retained resource")


def seed_with_smoke_test(reads: Any, stack: str, args: argparse.Namespace) -> None:
    """Populate the stack the way a customer would: scans, findings, reports, and audit entries."""

    import subprocess
    import tempfile

    outputs = {o["OutputKey"]: o["OutputValue"] for o in reads.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "outputs.json"
        path.write_text(json.dumps({stack: outputs}), encoding="utf-8")
        command = [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "smoke_test.py"),
            "--outputs",
            str(path),
            "--stack",
            stack,
            "--region",
            args.region,
            "--scan-regions",
            args.region,
        ]
        if args.profile:
            command += ["--profile", args.profile]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    summary = (result.stdout.strip().splitlines() or ["no output"])[-1]
    print(f"removal: smoke test on {stack}: {summary}")
    if result.returncode != 0:
        raise AcceptanceFailure(f"Smoke test failed before removal: {summary}")


def data_resources(reads: Any, stack_id: str) -> list[dict[str, Any]]:
    pages = reads.get_paginator("list_stack_resources").paginate(StackName=stack_id)
    return [r for page in pages for r in page["StackResourceSummaries"] if r["ResourceType"] in RETAINED_TYPES]


def is_console_bucket(resource: dict[str, Any]) -> bool:
    # The console bucket only holds the published UI, so both templates delete it.
    return resource["ResourceType"] == "AWS::S3::Bucket" and "Console" in resource["LogicalResourceId"]


def stored_data(admin: Any, resources: list[dict[str, Any]]) -> tuple[int, int]:
    dynamodb, s3 = admin.client("dynamodb"), admin.client("s3")
    items = sum(
        dynamodb.scan(TableName=r["PhysicalResourceId"], Limit=10)["Count"]
        for r in resources
        if r["ResourceType"] == "AWS::DynamoDB::Table"
    )
    objects = sum(
        s3.list_objects_v2(Bucket=r["PhysicalResourceId"], MaxKeys=10)["KeyCount"]
        for r in resources
        if r["ResourceType"] == "AWS::S3::Bucket" and not is_console_bucket(r)
    )
    return items, objects


def resource_exists(admin: Any, resource: dict[str, Any]) -> bool:
    from botocore.exceptions import ClientError

    kind, name = resource["ResourceType"], resource["PhysicalResourceId"]
    try:
        if kind == "AWS::DynamoDB::Table":
            admin.client("dynamodb").describe_table(TableName=name)
        elif kind == "AWS::S3::Bucket":
            admin.client("s3").head_bucket(Bucket=name)
        elif kind == "AWS::KMS::Key":
            return admin.client("kms").describe_key(KeyId=name)["KeyMetadata"]["KeyState"] != "PendingDeletion"
        elif kind == "AWS::Cognito::UserPool":
            admin.client("cognito-idp").describe_user_pool(UserPoolId=name)
        elif kind == "AWS::Logs::LogGroup":
            groups = admin.client("logs").describe_log_groups(logGroupNamePrefix=name)["logGroups"]
            return any(group["logGroupName"] == name for group in groups)
        return True
    except ClientError as error:
        code = error.response["Error"]["Code"]
        if code in {"ResourceNotFoundException", "404", "NoSuchBucket", "NotFoundException"}:
            return False
        raise


def decommission(admin: Any, resources: list[dict[str, Any]]) -> None:
    """The customer's manual cleanup after deleting a production stack (OPERATIONS.md)."""

    by_type: dict[str, list[str]] = {}
    for resource in resources:
        by_type.setdefault(resource["ResourceType"], []).append(resource["PhysicalResourceId"])
    dynamodb, s3 = admin.client("dynamodb"), admin.client("s3")
    for table in by_type.get("AWS::DynamoDB::Table", []):
        dynamodb.delete_table(TableName=table)
        dynamodb.get_waiter("table_not_exists").wait(TableName=table)
    for bucket in by_type.get("AWS::S3::Bucket", []):
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            versions = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if versions:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": versions, "Quiet": True})
        s3.delete_bucket(Bucket=bucket)
    for pool in by_type.get("AWS::Cognito::UserPool", []):
        admin.client("cognito-idp").delete_user_pool(UserPoolId=pool)
    for group in by_type.get("AWS::Logs::LogGroup", []):
        admin.client("logs").delete_log_group(logGroupName=group)
    for key in by_type.get("AWS::KMS::Key", []):
        admin.client("kms").schedule_key_deletion(KeyId=key, PendingWindowInDays=7)


def main() -> int:
    import boto3

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--stack", required=True)
    parser.add_argument("--bucket-prefix", required=True)
    parser.add_argument("--steps", default="upgrade,rollback,install")
    parser.add_argument("--profile")
    args = parser.parse_args()

    base = boto3.Session(profile_name=args.profile, region_name=args.region)
    identity = base.client("sts").get_caller_identity()
    iam = base.client("iam")
    role_arn = create_role(iam, identity["Arn"], installer_policy(identity["Account"], args.bucket_prefix))
    print(f"Temporary installer role: {role_arn}")
    results: list[tuple[str, bool, str]] = []
    try:
        cfn = installer_session(boto3, base, role_arn, args.region).client("cloudformation")
        steps = {
            "upgrade": lambda: step_upgrade(cfn, args),
            "rollback": lambda: step_rollback(cfn, args),
            "install": lambda: step_install(cfn, args),
            "removal": lambda: step_removal(cfn, base, args),
        }
        for name in [step.strip() for step in args.steps.split(",") if step.strip()]:
            try:
                steps[name]()
                results.append((name, True, ""))
            except Exception as exc:  # noqa: BLE001 - report every step
                results.append((name, False, f"{type(exc).__name__}: {exc}"))
                if name == "upgrade":
                    break  # later steps assume the upgraded release
    finally:
        delete_role(iam)

    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    return 0 if results and all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
