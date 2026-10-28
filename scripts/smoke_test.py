"""Authenticated end-to-end smoke test for a deployed Sovereign Shield stack.

Creates two temporary Cognito users (administrator and auditor) with email
delivery suppressed, exercises the v1 API, and deletes the users afterwards.
It starts one bounded read-only scan and creates, pauses, and deletes one
schedule. It never modifies scanned resources.

Usage:
    python scripts/smoke_test.py --outputs dist/stack-outputs.json \
        --profile default --region eu-central-1 [--scan-regions eu-central-1] \
        [--services s3,dynamodb,kms]
"""

from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import boto3

ADMINISTRATORS = "SovereignShieldAdministrators"
AUDITORS = "SovereignShieldAuditors"
TERMINAL = {"complete", "partial", "failed", "cancelled"}


class SmokeTest:
    def __init__(self, outputs: dict[str, str], session: boto3.Session, *, scan_timeout: int = 300) -> None:
        self.api_url = outputs["ApiUrl"].rstrip("/")
        self.outputs = outputs
        self.pool_id = outputs["UserPoolId"]
        self.client_id = outputs["UserPoolClientId"]
        self.cognito = session.client("cognito-idp")
        self.scan_timeout = scan_timeout
        self.results: list[tuple[str, bool, str]] = []
        self._users: list[str] = []

    # ── checks ──────────────────────────────────────────────────

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.results.append((name, passed, detail))
        print(f"[{'PASS' if passed else 'FAIL'}] {name}{f' - {detail}' if detail else ''}")
        return passed

    def run(self, scan_regions: list[str], services: list[str]) -> bool:
        try:
            admin = self._token_for(ADMINISTRATORS)
            auditor = self._token_for(AUDITORS)

            status, _ = self._call("GET", f"/v1/scans/{uuid.uuid4()}")
            self.check("Unauthenticated request is rejected by API Gateway", status == 401, f"status={status}")
            status, _ = self._call("GET", f"/v1/scans/{uuid.uuid4()}", token="not-a-jwt")
            self.check("Malformed token is rejected", status == 401, f"status={status}")

            request = {
                "idempotencyKey": f"smoke-{uuid.uuid4()}",
                "scanRegions": scan_regions,
                "services": services,
                "regulations": ["gdpr"],
                "dataCategories": ["personal_data"],
                "reportGenerationMode": "deterministic_only",
            }
            status, _ = self._call("POST", "/v1/scans", request, token=auditor)
            self.check("Auditor cannot start a scan", status == 403, f"status={status}")

            started = time.monotonic()
            status, body = self._call("POST", "/v1/scans", request, token=admin)
            accepted_in = time.monotonic() - started
            if not self.check(
                "Administrator scan is accepted asynchronously",
                status == 202 and body.get("status") == "queued" and body.get("created") is True,
                f"status={status} body={body} in {accepted_in:.1f}s",
            ):
                return False
            scan_run_id = body["scanRunId"]

            status, replay = self._call("POST", "/v1/scans", request, token=admin)
            self.check(
                "Idempotent replay returns the same run",
                status == 202 and replay.get("scanRunId") == scan_run_id and replay.get("created") is False,
                f"status={status}",
            )
            status, _ = self._call("POST", "/v1/scans", {**request, "regulations": ["dpdp"]}, token=admin)
            self.check("Idempotency key reuse with a changed payload is rejected", status == 400, f"status={status}")

            run = self._wait_for_terminal(scan_run_id, admin, self.scan_timeout)
            self.check(
                "Scan reaches a successful terminal state",
                run.get("status") in {"complete", "partial"},
                f"status={run.get('status')} progress={run.get('progress')} error={run.get('errorSummary')}",
            )

            status, page = self._call("GET", f"/v1/scans/{scan_run_id}/findings?limit=5", token=auditor)
            findings = page.get("findings", []) if isinstance(page, dict) else []
            self.check(
                "Auditor can page findings",
                status == 200 and isinstance(findings, list),
                f"status={status} returned={len(findings)} nextCursor={'yes' if page.get('nextCursor') else 'no'}",
            )
            status, report = self._call("GET", f"/v1/scans/{scan_run_id}/report", token=auditor)
            report_key = (report.get("report") or {}).get("object_key", "") if isinstance(report, dict) else ""
            download_url = ((report.get("download") or {}).get("url", "")) if isinstance(report, dict) else ""
            self.check(
                "Report metadata has no bucket URL; any download link is signed and expiring",
                status == 200
                and report_key.startswith(f"reports/{scan_run_id}/")
                and "https://" not in json.dumps(report.get("report"))
                and (not download_url or ("X-Amz-Signature=" in download_url and "X-Amz-Expires=" in download_url)),
                f"status={status} key={report_key}",
            )

            self._schedule_lifecycle(admin, auditor, request)
            self._console_api(admin, auditor, scan_run_id)
            if "ConsoleUrl" in self.outputs:
                self._console_hosting()
            return all(passed for _, passed, _ in self.results)
        finally:
            self._delete_users()

    def _schedule_lifecycle(self, admin: str, auditor: str, request: dict[str, Any]) -> None:
        schedule_request = {key: value for key, value in request.items() if key != "idempotencyKey"}
        payload = {
            "name": f"smoke-{uuid.uuid4().hex[:8]}",
            "scheduleExpression": "cron(0 3 1 1 ? 2099)",
            "scanRequest": schedule_request,
            "enabled": False,
        }
        status, _ = self._call("POST", "/v1/schedules", payload, token=auditor)
        self.check("Auditor cannot create a schedule", status == 403, f"status={status}")
        _, configuration = self._call("GET", "/v1/configuration", token=admin)
        if not (configuration.get("scanChoices") or {}).get("scheduledScansEnabled", True):
            # Release default: EnableScheduledScans=false. Creation must be refused outright.
            status, _ = self._call("POST", "/v1/schedules", payload, token=admin)
            self.check("Schedule creation is refused while scheduled scans are disabled", status == 409,
                       f"status={status}")
            return
        too_frequent = {**payload, "scheduleExpression": "rate(5 minutes)"}
        status, _ = self._call("POST", "/v1/schedules", too_frequent, token=admin)
        self.check("Schedules more frequent than hourly are rejected", status == 400, f"status={status}")

        status, created = self._call("POST", "/v1/schedules", payload, token=admin)
        created_ok = self.check(
            "Administrator can create a disabled schedule", status == 201, f"status={status} body={created}"
        )
        if not created_ok:
            return
        schedule_id = created["scheduleId"]
        status, updated = self._call("PATCH", f"/v1/schedules/{schedule_id}", {"enabled": False}, token=admin)
        self.check("Administrator can pause a schedule", status == 200 and updated.get("enabled") is False,
                   f"status={status}")
        status, _ = self._call("DELETE", f"/v1/schedules/{schedule_id}", token=admin)
        self.check("Administrator can delete a schedule", status == 204, f"status={status}")

    def _console_api(self, admin: str, auditor: str, scan_run_id: str) -> None:
        status, admin_config = self._call("GET", "/v1/configuration", token=admin)
        _, auditor_config = self._call("GET", "/v1/configuration", token=auditor)
        admin_actions = set((admin_config.get("caller") or {}).get("allowedActions", []))
        auditor_actions = set((auditor_config.get("caller") or {}).get("allowedActions", []))
        self.check(
            "Configuration reports role-specific actions and admin-only settings",
            status == 200
            and {"start_scan", "view_audit_log"} <= admin_actions
            and not {"start_scan", "cancel_scan", "manage_schedule", "view_audit_log"} & auditor_actions
            and "settings" in admin_config
            and "settings" not in auditor_config,
            f"admin={sorted(admin_actions)} auditor={sorted(auditor_actions)}",
        )

        status, listed = self._call("GET", "/v1/scans?limit=20", token=auditor)
        listed_ids = [scan.get("scanRunId") for scan in listed.get("scans", [])] if isinstance(listed, dict) else []
        self.check("Auditor can list scans, newest first", status == 200 and scan_run_id in listed_ids,
                   f"status={status} count={len(listed_ids)}")
        status, schedules = self._call("GET", "/v1/schedules", token=auditor)
        self.check("Auditor can list schedules", status == 200 and isinstance(schedules.get("schedules"), list),
                   f"status={status}")

        status, page = self._call("GET", f"/v1/scans/{scan_run_id}/findings?limit=100", token=auditor)
        findings = page.get("findings", []) if isinstance(page, dict) else []
        severities = {finding.get("severity") for finding in findings}
        guided = all((finding.get("guidance") or {}).get("steps") for finding in findings)
        self.check("Findings carry read-only remediation guidance", status == 200 and guided,
                   f"findings={len(findings)}")
        if severities:
            severity = sorted(severities)[0]
            status, filtered = self._call(
                "GET", f"/v1/scans/{scan_run_id}/findings?limit=100&severity={severity}", token=auditor
            )
            matched = {finding.get("severity") for finding in filtered.get("findings", [])}
            self.check("Findings filter server-side by severity", status == 200 and matched == {severity},
                       f"severity={severity} matched={matched}")
        status, _ = self._call("GET", f"/v1/scans/{scan_run_id}/findings?pk=RUN%23other", token=auditor)
        self.check("Unsupported findings parameters are rejected", status == 400, f"status={status}")

        status, report = self._call("GET", f"/v1/scans/{scan_run_id}/report", token=auditor)
        download = (report.get("download") or {}) if isinstance(report, dict) else {}
        body_ok = False
        if download.get("url"):
            with urllib.request.urlopen(download["url"], timeout=30) as response:
                disposition = response.headers.get("Content-Disposition", "")
                body_ok = response.status == 200 and "attachment" in disposition and response.read(1) == b"#"
        self.check("Report download link is short-lived and serves the report as an attachment",
                   status == 200 and body_ok, f"status={status} expiresAt={download.get('expiresAt')}")

        status, _ = self._call("GET", "/v1/audit-events", token=auditor)
        self.check("Auditor cannot read the audit log", status == 403, f"status={status}")
        status, audit = self._call("GET", "/v1/audit-events?limit=100", token=admin)
        events = audit.get("events", []) if isinstance(audit, dict) else []
        recorded = {(event.get("action"), event.get("outcome")) for event in events}
        started = any(
            event.get("action") == "scan.start" and event.get("targetId") == scan_run_id
            and event.get("outcome") == "succeeded"
            for event in events
        )
        self.check(
            "Audit log records the scan start, report link, and denied attempts",
            status == 200 and started and ("report.view", "succeeded") in recorded
            and ("scan.start", "denied") in recorded and ("audit.list", "denied") in recorded,
            f"status={status} events={len(events)}",
        )

    def _console_hosting(self) -> None:
        console_url = self.outputs["ConsoleUrl"].rstrip("/")
        with urllib.request.urlopen(f"{console_url}/", timeout=30) as response:
            headers = response.headers
            html = response.read().decode("utf-8", errors="replace")
        csp = headers.get("Content-Security-Policy", "")
        self.check(
            "Console is served over HTTPS with strict security headers",
            "frame-ancestors 'none'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp
            and headers.get("X-Frame-Options") == "DENY" and "max-age" in headers.get("Strict-Transport-Security", "")
            and '<div id="root">' in html,
            f"csp={'yes' if csp else 'missing'}",
        )
        with urllib.request.urlopen(f"{console_url}/scans/{uuid.uuid4()}", timeout=30) as response:
            spa_ok = response.status == 200 and '<div id="root">' in response.read().decode("utf-8", errors="replace")
        self.check("Client-side routes resolve to the console shell", spa_ok)
        with urllib.request.urlopen(f"{console_url}/config.json", timeout=30) as response:
            runtime = json.loads(response.read())
        self.check(
            "Runtime config points at this stack's API and console client",
            runtime.get("apiUrl") == self.api_url and runtime.get("clientId") == self.outputs.get("ConsoleClientId"),
            f"keys={sorted(runtime)}",
        )

        domain = runtime.get("cognitoDomain", "")
        common = {"response_type": "code", "client_id": runtime.get("clientId", ""), "scope": "openid",
                  "code_challenge": "x" * 43, "code_challenge_method": "S256", "state": "smoke"}
        allowed = _final_url(f"{domain}/oauth2/authorize?" + urllib.parse.urlencode(
            {**common, "redirect_uri": f"{console_url}/callback"}))
        foreign = _final_url(f"{domain}/oauth2/authorize?" + urllib.parse.urlencode(
            {**common, "redirect_uri": "https://attacker.example/callback"}))
        self.check(
            "Hosted sign-in accepts the console callback and rejects other redirect URLs",
            "/login" in allowed and "error" in foreign and "attacker.example" not in foreign.split("?")[0],
            f"allowed={allowed.split('?')[0]} foreign={foreign[:80]}",
        )

    def _wait_for_terminal(self, scan_run_id: str, token: str, timeout_seconds: int) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last_status = None
        while time.monotonic() < deadline:
            status, body = self._call("GET", f"/v1/scans/{scan_run_id}", token=token)
            if status == 200:
                if body.get("status") != last_status:
                    last_status = body.get("status")
                    print(f"       run {scan_run_id}: {last_status} {body.get('progress')}")
                if last_status in TERMINAL:
                    return body
            time.sleep(5)
        return {"status": "timeout"}

    # ── HTTP and identity ───────────────────────────────────────

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None, *, token: str | None = None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=35) as response:
                return response.status, _json(response.read())
        except urllib.error.HTTPError as error:
            return error.code, _json(error.read())

    def _token_for(self, group: str) -> str:
        username = f"smoke-{group.removeprefix('SovereignShield').lower()}-{uuid.uuid4().hex[:8]}@example.invalid"
        password = _password()
        self.cognito.admin_create_user(
            UserPoolId=self.pool_id,
            Username=username,
            MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "email", "Value": username}, {"Name": "email_verified", "Value": "true"}],
        )
        self._users.append(username)
        self.cognito.admin_set_user_password(
            UserPoolId=self.pool_id, Username=username, Password=password, Permanent=True
        )
        self.cognito.admin_add_user_to_group(UserPoolId=self.pool_id, Username=username, GroupName=group)
        response = self.cognito.admin_initiate_auth(
            UserPoolId=self.pool_id,
            ClientId=self.client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        return response["AuthenticationResult"]["AccessToken"]

    def _delete_users(self) -> None:
        for username in self._users:
            try:
                self.cognito.admin_delete_user(UserPoolId=self.pool_id, Username=username)
            except Exception as exc:  # noqa: BLE001 - report but continue cleanup
                print(f"WARNING: could not delete temporary user {username}: {type(exc).__name__}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001 - stdlib signature
        return None


def _final_url(url: str) -> str:
    """Follow redirects only within the hosted sign-in domain; report where they end."""

    opener = urllib.request.build_opener(_NoRedirect)
    current = url
    for _ in range(5):
        try:
            with opener.open(current, timeout=30) as response:
                return response.geturl()
        except urllib.error.HTTPError as error:
            location = error.headers.get("Location")
            if error.code in {301, 302, 303, 307, 308} and location:
                current = urllib.parse.urljoin(current, location)
                if urllib.parse.urlparse(current).netloc != urllib.parse.urlparse(url).netloc:
                    return current
                continue
            return f"{current}?error=http-{error.code}"
    return current


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"raw": raw[:200].decode(errors="replace")}


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(24))
    return f"{core}aA1!"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outputs", default="dist/stack-outputs.json")
    parser.add_argument("--stack", default="SovereignShieldStack")
    parser.add_argument("--profile")
    parser.add_argument("--region")
    parser.add_argument("--scan-regions", default="eu-central-1")
    parser.add_argument("--services", default="s3,dynamodb,kms")
    parser.add_argument("--scan-timeout", type=int, default=300, help="Seconds to wait for a terminal run.")
    args = parser.parse_args()

    outputs = json.loads(Path(args.outputs).read_text(encoding="utf-8"))[args.stack]
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    test = SmokeTest(outputs, session, scan_timeout=args.scan_timeout)
    passed = test.run(args.scan_regions.split(","), args.services.split(","))
    failures = [name for name, ok, _ in test.results if not ok]
    print(f"\n{len(test.results) - len(failures)}/{len(test.results)} checks passed")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
