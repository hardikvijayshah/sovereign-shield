"""State-machine failure-path checks for a deployed Sovereign Shield stack.

Run after scripts/smoke_test.py, from the repository root:
    python scripts/failure_checks.py

Verifies scheduled-run admission, disabled/missing schedule rejection,
terminal-outcome preservation on re-execution, clean failure for unknown runs,
KMS report encryption, and reports-bucket public access blocking. Uses the
sandbox profile/region below and dist/stack-outputs.json; temporary Cognito
users and schedules are deleted afterwards.
"""

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke_test import ADMINISTRATORS, SmokeTest

parser = argparse.ArgumentParser(description="State-machine failure-path checks")
parser.add_argument("--outputs", default="dist/stack-outputs.json")
parser.add_argument("--stack", default="SovereignShieldStack")
parser.add_argument("--region", default="eu-central-1")
parser.add_argument("--profile", default="default")
args = parser.parse_args()
outputs = json.loads(Path(args.outputs).read_text())[args.stack]
session = boto3.Session(profile_name=args.profile, region_name=args.region)
sfn = session.client("stepfunctions")
ddb = session.resource("dynamodb").Table(outputs["ScanRunTableName"])
sm = outputs["ScanStateMachineArn"]
t = SmokeTest(outputs, session)


def execute(payload):
    arn = sfn.start_execution(stateMachineArn=sm, name=f"check-{uuid.uuid4().hex[:12]}", input=json.dumps(payload))[
        "executionArn"
    ]
    while True:
        d = sfn.describe_execution(executionArn=arn)
        if d["status"] != "RUNNING":
            return d
        time.sleep(3)


def run_record(run_id):
    return ddb.get_item(Key={"pk": f"RUN#{run_id}", "sk": "RUN"}).get("Item")


try:
    admin = t._token_for(ADMINISTRATORS)
    request = {
        "scanRegions": [args.region],
        "services": ["s3"],
        "regulations": ["gdpr"],
        "dataCategories": ["personal_data"],
    }
    status, sched = t._call(
        "POST",
        "/v1/schedules",
        {"name": "check-admission", "scheduleExpression": "cron(0 3 1 1 ? 2099)", "scanRequest": request},
        token=admin,
    )
    sid = sched["scheduleId"]
    try:
        d = execute({"scheduleId": sid})
        out = json.loads(d.get("output") or "{}")
        rec = run_record(out.get("scanRunId", "none")) or {}
        t.check(
            "Scheduled execution admits and completes a run",
            d["status"] == "SUCCEEDED" and rec.get("status") == "complete",
            f"exec={d['status']} run={rec.get('status')} "
            f"requester_is_schedule_creator={bool(rec.get('requester_subject'))}",
        )
        completed_run = out.get("scanRunId")
        scheduled_execution_arn = d["executionArn"]

        status, _ = t._call("PATCH", f"/v1/schedules/{sid}", {"enabled": False}, token=admin)
        d = execute({"scheduleId": sid})
        t.check(
            "Disabled schedule is rejected",
            d["status"] == "FAILED" and d.get("error") == "ScheduledRunRejected",
            f"exec={d['status']} error={d.get('error')}",
        )
    finally:
        t._call("DELETE", f"/v1/schedules/{sid}", token=admin)

    d = execute({"scheduleId": str(uuid.uuid4())})
    t.check(
        "Missing schedule is rejected",
        d["status"] == "FAILED" and d.get("error") == "ScheduledRunRejected",
        f"error={d.get('error')}",
    )

    before = run_record(completed_run)
    d = execute({"scanRunId": completed_run})
    after = run_record(completed_run)
    t.check(
        "Re-executing a completed run fails without overwriting its outcome",
        d["status"] == "FAILED" and after["status"] == "complete" and after["updated_at"] == before["updated_at"],
        f"exec={d['status']} run={after['status']}",
    )

    d = execute({"scanRunId": str(uuid.uuid4())})
    t.check(
        "Unknown run ID fails cleanly",
        d["status"] == "FAILED" and d.get("error") == "ScanFailed",
        f"error={d.get('error')}",
    )

    s3 = session.client("s3")
    rec = run_record(completed_run)
    progress = rec["progress"]
    unit_key = f"work/{completed_run}/{rec['account_id'] or 'deployment'}/{args.region}/s3.json"
    unit_head = s3.head_object(Bucket=outputs["ReportsBucketName"], Key=unit_key)
    t.check(
        "Fan-out stored the unit result under work/ with the stack KMS key",
        unit_head.get("SSEKMSKeyId") == outputs["KmsKeyArn"]
        and progress["planned_units"] == progress["completed_units"]
        and progress["failed_units"] == 0,
        f"progress={progress}",
    )
    history = sfn.get_execution_history(executionArn=scheduled_execution_arn, maxResults=500)["events"]
    iterations = sum(event["type"] == "MapIterationSucceeded" for event in history)
    t.check(
        "Scan executed through the Map state, one iteration per unit",
        any(event["type"] == "MapStateStarted" for event in history) and iterations == progress["planned_units"],
        f"iterations={iterations}",
    )

    key = (rec.get("report") or {}).get("object_key")
    head = s3.head_object(Bucket=outputs["ReportsBucketName"], Key=key)
    t.check(
        "Report object is encrypted with the stack KMS key",
        head.get("ServerSideEncryption") == "aws:kms" and head.get("SSEKMSKeyId") == outputs["KmsKeyArn"],
        head.get("ServerSideEncryption"),
    )
    pab = s3.get_public_access_block(Bucket=outputs["ReportsBucketName"])["PublicAccessBlockConfiguration"]
    t.check("Reports bucket blocks all public access", all(pab.values()))
finally:
    t._delete_users()

users = session.client("cognito-idp").list_users(UserPoolId=outputs["UserPoolId"])["Users"]
t.check(
    "Only the bootstrap administrator remains in the user pool",
    [u["Username"] for u in users if "smoke" in str(u["Attributes"])] == [],
    f"users={len(users)}",
)
print(f"\n{sum(ok for _, ok, _ in t.results)}/{len(t.results)} checks passed")
