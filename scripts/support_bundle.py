"""Collect a non-sensitive support bundle for a Sovereign Shield stack (plan.md section 13.1).

Includes: stack status and recent failure events, release version, launch
parameters (email addresses masked), alarm states, the readiness check result,
and recent failed workflow executions by error name.

Excludes by design: log messages, error causes, findings, evidence, report
content, user identities, and credentials. Review the file before sharing.

Usage:
    python scripts/support_bundle.py --stack SovereignShield --region eu-west-1 [--profile default]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_EMAIL = re.compile(r"[^@\s,]+@([^@\s,]+)")


def mask(value: str) -> str:
    """Mask email local parts; keep the domain so routing problems remain diagnosable."""

    return _EMAIL.sub(lambda match: f"***@{match.group(1)}", value)


def collect(session: Any, stack_name: str) -> dict[str, Any]:
    cloudformation = session.client("cloudformation")
    stack = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {output["OutputKey"]: output["OutputValue"] for output in stack.get("Outputs", [])}
    bundle: dict[str, Any] = {
        "collectedAt": datetime.now(timezone.utc).isoformat(),
        "stack": {
            "name": stack["StackName"],
            "status": stack["StackStatus"],
            "statusReason": stack.get("StackStatusReason", ""),
            "lastUpdated": str(stack.get("LastUpdatedTime") or stack.get("CreationTime")),
            "region": session.region_name,
        },
        "releaseVersion": outputs.get("ReleaseVersion", "unknown"),
        "parameters": {
            parameter["ParameterKey"]: mask(parameter.get("ParameterValue", ""))
            for parameter in stack.get("Parameters", [])
        },
        "outputsPresent": sorted(outputs),
    }

    events = cloudformation.describe_stack_events(StackName=stack_name)["StackEvents"][:200]
    bundle["recentFailures"] = [
        {
            "time": str(event["Timestamp"]),
            "resource": event["LogicalResourceId"],
            "type": event["ResourceType"],
            "status": event["ResourceStatus"],
            "reason": mask(event.get("ResourceStatusReason", ""))[:300],
        }
        for event in events
        if "FAILED" in event["ResourceStatus"]
    ][:25]

    bundle["alarms"] = _section(lambda: [
        {"name": alarm["AlarmName"], "state": alarm["StateValue"], "since": str(alarm["StateUpdatedTimestamp"])}
        for alarm in session.client("cloudwatch").describe_alarms(AlarmNamePrefix=stack_name)["MetricAlarms"]
    ])
    bundle["readiness"] = _section(lambda: _readiness(session, outputs))
    bundle["failedExecutions"] = _section(lambda: _failed_executions(session, outputs))
    return bundle


def _readiness(session: Any, outputs: dict[str, str]) -> Any:
    function_name = outputs.get("ReadinessFunctionName")
    if not function_name:
        return "ReadinessFunctionName output not present (release earlier than 1.0.0)."
    response = session.client("lambda").invoke(FunctionName=function_name, Payload=b"{}")
    return json.loads(response["Payload"].read())


def _failed_executions(session: Any, outputs: dict[str, str]) -> Any:
    state_machine = outputs.get("ScanStateMachineArn")
    if not state_machine:
        return []
    stepfunctions = session.client("stepfunctions")
    since = datetime.now(timezone.utc) - timedelta(days=7)
    failed = []
    for status in ("FAILED", "TIMED_OUT", "ABORTED"):
        for execution in stepfunctions.list_executions(
            stateMachineArn=state_machine, statusFilter=status, maxResults=20
        )["executions"]:
            if execution["startDate"] < since:
                continue
            detail = stepfunctions.describe_execution(executionArn=execution["executionArn"])
            # Error names only; causes can contain AWS response text.
            failed.append({
                "execution": execution["name"],
                "status": status,
                "started": str(execution["startDate"]),
                "error": detail.get("error", ""),
            })
    return failed


def _section(collector) -> Any:
    try:
        return collector()
    except Exception as exc:  # noqa: BLE001 - a missing permission must not abort the bundle
        response = getattr(exc, "response", {})
        code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
        return {"unavailable": code or type(exc).__name__}


def main() -> int:
    import boto3

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stack", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    bundle = collect(session, args.stack)
    out_dir = PROJECT_ROOT / "dist"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"support-bundle-{args.stack}-{stamp}.json"
    path.write_text(json.dumps(bundle, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"Support bundle written to {path}")
    print(f"  stack {bundle['stack']['status']}, release {bundle['releaseVersion']}, "
          f"{len(bundle['recentFailures'])} recent failure event(s)")
    print("Review the file before sharing it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
