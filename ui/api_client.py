"""API client for Sovereign Shield — routes requests to Lambda via API Gateway or local imports."""

from __future__ import annotations

import io
import json
import os
import sys

import requests

# Fix Windows cp1252 encoding crash when Strands streams Unicode/emoji to stdout
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

API_GATEWAY_URL = os.environ.get("API_GATEWAY_URL", "")
LAMBDA_FUNCTION_NAME = os.environ.get("LAMBDA_FUNCTION_NAME", "")
MODE = os.environ.get("SOVEREIGN_SHIELD_MODE", "local")


def _is_api_mode() -> bool:
    return MODE == "api" and (API_GATEWAY_URL or LAMBDA_FUNCTION_NAME)


def run_scan(regions: str, regulations: str, accounts: str = "") -> dict:
    payload = {"action": "scan", "regions": regions, "regulations": regulations, "accounts": accounts}

    if _is_api_mode() and API_GATEWAY_URL:
        return _call_api_gateway(payload)

    if _is_api_mode() and LAMBDA_FUNCTION_NAME:
        return _invoke_lambda(payload)

    return _call_local_scan(regions, regulations, accounts)


def chat(prompt: str) -> dict:
    payload = {"action": "chat", "prompt": prompt}

    if _is_api_mode() and API_GATEWAY_URL:
        return _call_api_gateway(payload)
    if _is_api_mode() and LAMBDA_FUNCTION_NAME:
        return _invoke_lambda(payload)

    from sovereign_shield.agents.orchestrator import create_orchestrator
    orchestrator = create_orchestrator()
    result = orchestrator(prompt)
    return {"action": "chat", "result": str(result)}


def check_violations(scan_results: dict | str, regulations: str = "") -> dict:
    if isinstance(scan_results, dict):
        scan_results_json = json.dumps(scan_results)
    else:
        scan_results_json = scan_results

    payload = {"action": "check_violations", "scan_results": scan_results_json, "regulations": regulations}

    if _is_api_mode() and API_GATEWAY_URL:
        return _call_api_gateway(payload)
    if _is_api_mode() and LAMBDA_FUNCTION_NAME:
        return _invoke_lambda(payload)

    from sovereign_shield.tools.invocation import invoke_tool
    from sovereign_shield.tools.violation_detector import check_violations as _check

    result_str = invoke_tool(_check, scan_results_json=scan_results_json, applicable_regulations=regulations)
    return json.loads(result_str)


def generate_scp(prohibited_regions: str, allowed_services: str, policy_name: str) -> dict:
    payload = {
        "action": "generate_scp",
        "prohibited_regions": prohibited_regions,
        "allowed_services": allowed_services,
        "policy_name": policy_name,
    }

    if _is_api_mode() and API_GATEWAY_URL:
        return _call_api_gateway(payload)
    if _is_api_mode() and LAMBDA_FUNCTION_NAME:
        return _invoke_lambda(payload)

    from sovereign_shield.tools.invocation import invoke_tool
    from sovereign_shield.tools.remediation import generate_scp_policy

    result_str = invoke_tool(
        generate_scp_policy,
        prohibited_regions=prohibited_regions,
        allowed_services=allowed_services,
        policy_name=policy_name,
    )
    return json.loads(result_str)


def generate_remediation(violations: dict | str) -> dict:
    if isinstance(violations, dict):
        violations_json = json.dumps(violations)
    else:
        violations_json = violations

    payload = {"action": "generate_remediation", "violations": violations_json}

    if _is_api_mode() and API_GATEWAY_URL:
        return _call_api_gateway(payload)
    if _is_api_mode() and LAMBDA_FUNCTION_NAME:
        return _invoke_lambda(payload)

    from sovereign_shield.tools.invocation import invoke_tool
    from sovereign_shield.tools.remediation import generate_remediation_plan

    result_str = invoke_tool(generate_remediation_plan, violations_json=violations_json)
    return json.loads(result_str)


def _call_api_gateway(payload: dict) -> dict:
    url = API_GATEWAY_URL.rstrip("/") + "/scan"
    resp = requests.post(url, json=payload, timeout=600)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data.get("body"), str):
        return json.loads(data["body"])
    return data


def _invoke_lambda(payload: dict) -> dict:
    import boto3
    client = boto3.client("lambda", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    resp = client.invoke(
        FunctionName=LAMBDA_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload),
    )
    result = json.loads(resp["Payload"].read())
    if isinstance(result.get("body"), str):
        return json.loads(result["body"])
    return result


def _call_local_scan(regions: str, regulations: str, accounts: str) -> dict:
    from sovereign_shield.agents.orchestrator import create_orchestrator
    orchestrator = create_orchestrator()
    prompt = (
        f"Run a complete sovereignty compliance scan.\n"
        f"Regions: {regions}\nAccounts: {accounts or 'current account'}\n"
        f"Regulations: {regulations or 'all'}\n"
        f"Execute the full pipeline: jurisdiction profiling, data flow scanning, "
        f"violation detection, remediation planning, and report generation."
    )
    result = orchestrator(prompt)
    return {"action": "scan", "result": str(result)}
