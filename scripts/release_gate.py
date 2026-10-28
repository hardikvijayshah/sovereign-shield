"""Local release gate: every plan.md section 9.3 check, in one blocking command.

Runs, in order:
  1. ruff lint (src, tests, cdk, scripts)
  2. Python tests (unit, contract, synthesis assertions)
  3. Console type-check, tests, and CSP-safe production build
  4. Dependency vulnerability audit (pip-audit on the Lambda closure; npm audit, production deps)
  5. Secret scan
  6. Release templates synthesized bootstrapless and linted with cfn-lint
  7. IAM Access Analyzer validation of the installer and member-role policies (skip with --offline)

Exits non-zero if any check fails. Intended to run unchanged in CI once the
project is in a repository.

Usage:
    python scripts/release_gate.py [--offline] [--profile default]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONSOLE = PROJECT_ROOT / "console"
PLACEHOLDERS = {
    "${AccountId}": "111111111111",
    "${StackName}": "SovereignShieldGate",
    "${StackNameLowercase}": "sovereignshieldgate",
    "${DeploymentPrefix}": "ss-gate",
    "${ArtifactBucketPrefix}": "sovereign-shield-releases-111111111111",
}


def run(command: list[str], *, cwd: Path = PROJECT_ROOT, env: dict[str, str] | None = None) -> tuple[bool, str]:
    result = subprocess.run(
        command, cwd=cwd, env={**os.environ, **(env or {})}, capture_output=True, text=True, encoding="utf-8",
        errors="replace",
    )
    output = (result.stdout + result.stderr).strip().splitlines()
    return result.returncode == 0, "\n".join(output[-15:])


def tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise RuntimeError(f"{name} is not on PATH")
    return found


def check_lint() -> tuple[bool, str]:
    return run([sys.executable, "-m", "ruff", "check", "src", "tests", "cdk", "scripts"])


def check_python_tests() -> tuple[bool, str]:
    return run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], env={"PYTHONPATH": "src"})


def check_console() -> tuple[bool, str]:
    npm = tool("npm")
    for step in (["run", "typecheck"], ["test"], ["run", "build"]):
        ok, output = run([npm, *step], cwd=CONSOLE)
        if not ok:
            return False, output
    index = (CONSOLE / "dist" / "index.html").read_text(encoding="utf-8")
    if "<script>" in index or "<style" in index:
        return False, "console/dist/index.html contains inline script or style (breaks the CSP)."
    return True, "typecheck, tests, and build passed; no inline script or style"


def check_dependencies() -> tuple[bool, str]:
    ok, python_output = run([
        sys.executable, "-m", "pip_audit", "--requirement", "scripts/lambda-requirements.txt", "--no-deps",
        "--progress-spinner", "off",
    ])
    if not ok:
        return False, python_output
    ok, npm_output = run([tool("npm"), "audit", "--omit=dev", "--audit-level=high"], cwd=CONSOLE)
    return ok, f"pip-audit: no known vulnerabilities\nnpm audit (production): {npm_output.splitlines()[-1]}"


def check_secrets() -> tuple[bool, str]:
    return run([sys.executable, str(PROJECT_ROOT / "scripts" / "secret_scan.py"), str(PROJECT_ROOT)])


def check_templates() -> tuple[bool, str]:
    build_release = _load("build_release", PROJECT_ROOT / "scripts" / "build_release.py")
    from stacks.sovereign_shield_stack import ReleaseArtifacts

    artifacts = ReleaseArtifacts(version="0.0.0-gate", bucket_prefix="sovereign-shield-releases-111111111111")
    staging = Path(tempfile.mkdtemp(prefix="sovereign-shield-gate-"))
    try:
        templates = []
        for name, removal in build_release.TEMPLATES.items():
            build_release._synthesize(artifacts, removal, staging / name)
            templates.append(staging / name)
        build_release._write_member_role_template(staging / build_release.MEMBER_ROLE_TEMPLATE)
        templates.append(staging / build_release.MEMBER_ROLE_TEMPLATE)
        build_release._lint(templates)
        return True, f"{len(templates)} templates synthesized without bootstrap references; cfn-lint clean"
    except SystemExit as exc:
        return False, str(exc)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# API Gateway enforces these when CloudFormation tags an HTTP API stage (observed in the
# 2026-10-27 installer-policy acceptance run), but Access Analyzer's catalog does not list them yet.
UNCATALOGUED_ACTIONS = {"apigateway:TagResource", "apigateway:UntagResource"}


def _known_uncatalogued(finding: dict) -> bool:
    return finding["issueCode"] == "INVALID_ACTION" and any(
        f"action {action} does not exist" in finding["findingDetails"] for action in UNCATALOGUED_ACTIONS
    )


def check_policies(profile: str | None) -> tuple[bool, str]:
    import boto3

    sys.path.insert(0, str(PROJECT_ROOT / "cdk"))
    from stacks.member_role import member_role_template

    analyzer = boto3.Session(profile_name=profile, region_name="us-east-1").client("accessanalyzer")
    installer = (PROJECT_ROOT / "infrastructure" / "policies" / "installer-policy.json").read_text(encoding="utf-8")
    for placeholder, value in PLACEHOLDERS.items():
        installer = installer.replace(placeholder, value)
    role = member_role_template()["Resources"]["SovereignShieldScanRole"]["Properties"]
    trust = json.loads(
        json.dumps(role["AssumeRolePolicyDocument"])
        .replace('{"Ref": "CentralPrincipalArns"}', '["arn:aws:iam::111111111111:role/central-worker"]')
        .replace('{"Ref": "ExternalId"}', '"00000000-0000-0000-0000-000000000000"')
        .replace('{"Ref": "OrganizationId"}', '"o-abcdef1234"')
    )
    documents = {
        "installer policy": (installer, "IDENTITY_POLICY", {}),
        "member role permissions": (json.dumps(role["Policies"][0]["PolicyDocument"]), "IDENTITY_POLICY", {}),
        "member role trust": (json.dumps(trust), "RESOURCE_POLICY",
                              {"validatePolicyResourceType": "AWS::IAM::AssumeRolePolicyDocument"}),
    }
    problems = []
    for label, (document, policy_type, extra) in documents.items():
        findings = analyzer.validate_policy(policyDocument=document, policyType=policy_type, **extra)["findings"]
        blocking = [
            f for f in findings
            if f["findingType"] in {"ERROR", "SECURITY_WARNING"} and not _known_uncatalogued(f)
        ]
        problems += [f"{label}: {f['findingType']} {f['issueCode']}" for f in blocking]
    return not problems, "\n".join(problems) or "Access Analyzer: 0 errors or security warnings in 3 policies"


def _load(name: str, path: Path):
    sys.path.insert(0, str(PROJECT_ROOT / "cdk"))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--offline", action="store_true", help="Skip the IAM Access Analyzer check.")
    parser.add_argument("--profile")
    args = parser.parse_args()

    checks: list[tuple[str, Callable[[], tuple[bool, str]]]] = [
        ("Lint", check_lint),
        ("Python tests", check_python_tests),
        ("Console", check_console),
        ("Dependency audit", check_dependencies),
        ("Secret scan", check_secrets),
        ("Release templates", check_templates),
    ]
    if not args.offline:
        checks.append(("IAM policy validation", lambda: check_policies(args.profile)))

    results = []
    for name, check in checks:
        started = time.monotonic()
        try:
            ok, detail = check()
        except Exception as exc:  # noqa: BLE001 - a crashed check is a failed check
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append((name, ok, time.monotonic() - started, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {name} ({results[-1][2]:.0f}s)")
        if not ok:
            print("    " + detail.replace("\n", "\n    "))

    failed = [name for name, ok, _, _ in results if not ok]
    print(f"\nRelease gate: {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("BLOCKED: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
