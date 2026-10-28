"""Build a Sovereign Shield customer release (plan.md section 9.1).

Produces ``release/<version>/`` containing:

- ``lambda_package.zip``       deterministic runtime package (scripts/build_lambda.py)
- ``console.zip``              prebuilt web console bundle (reproducible zip)
- ``sovereign-shield.yaml``    production template: customer data is retained on delete
- ``sovereign-shield-nonprod.yaml``  non-production template: data deleted with the stack
- ``installer-policy.json``    least-privilege deployment policy (placeholders documented)
- ``manifest.json``            version, source digest, regions, artifact keys and SHA-256
- ``checksums.txt``            ``sha256  file`` lines for every artifact
- ``SBOM.spdx.json``           SPDX 2.3 inventory of runtime and console dependencies
- ``RELEASE_NOTES.md``         prerequisites, cost drivers, Quick Create links

Usage:
    python scripts/build_release.py --version 1.0.0 --bucket-prefix sovereign-shield-releases-<account>

Templates are linted with cfn-lint; the build fails on any lint error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "cdk"))

from stacks.member_role import member_role_template  # noqa: E402
from stacks.sovereign_shield_stack import (  # noqa: E402
    DATA_DELETION_ACKNOWLEDGEMENT,
    SUPPORTED_REGIONS,
    ReleaseArtifacts,
)

ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
TEMPLATES = {
    "sovereign-shield.yaml": "RETAIN",
    "sovereign-shield-nonprod.yaml": "DESTROY",
}
MEMBER_ROLE_TEMPLATE = "sovereign-shield-member-role.yaml"
SOURCE_DIRECTORIES = ("src", "cdk/stacks", "console/src", "scripts", "infrastructure")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--bucket-prefix", required=True, help="Per-region artifact buckets are <prefix>-<region>.")
    parser.add_argument("--skip-console-tests", action="store_true")
    args = parser.parse_args()

    artifacts = ReleaseArtifacts(version=args.version, bucket_prefix=args.bucket_prefix)
    out = PROJECT_ROOT / "release" / artifacts.version
    out.mkdir(parents=True, exist_ok=True)
    # Empty rather than delete the folder: sync clients (for example, OneDrive)
    # lock directories they are syncing.
    for stale in out.iterdir():
        if stale.is_file():
            stale.unlink()

    print(f"=== Sovereign Shield release {artifacts.version} ===")
    print("1. Lambda package")
    _run([sys.executable, str(PROJECT_ROOT / "scripts" / "build_lambda.py")])
    shutil.copy2(PROJECT_ROOT / "dist" / "lambda_package.zip", out / "lambda_package.zip")
    lambda_manifest = json.loads((PROJECT_ROOT / "dist" / "lambda_package.manifest.json").read_text())

    print("2. Console bundle")
    npm = _tool("npm")
    console = PROJECT_ROOT / "console"
    _run([npm, "ci", "--no-audit", "--no-fund"], cwd=console)
    if not args.skip_console_tests:
        _run([npm, "test"], cwd=console)
    _run([npm, "run", "build"], cwd=console)
    _zip_directory(console / "dist", out / "console.zip")

    print("3. Templates")
    for name, removal in TEMPLATES.items():
        _synthesize(artifacts, removal, out / name)
    _write_member_role_template(out / MEMBER_ROLE_TEMPLATE)
    _lint([out / name for name in TEMPLATES] + [out / MEMBER_ROLE_TEMPLATE])

    print("4. Installer policy, SBOM, manifest, checksums, notes")
    shutil.copy2(PROJECT_ROOT / "infrastructure" / "policies" / "installer-policy.json", out / "installer-policy.json")
    (out / "SBOM.spdx.json").write_text(
        json.dumps(_sbom(artifacts.version, lambda_manifest), indent=2) + "\n", encoding="utf-8"
    )
    files = sorted(path for path in out.iterdir() if path.is_file())
    digests = {path.name: _sha256(path) for path in files}
    manifest = {
        "product": "Sovereign Shield",
        "version": artifacts.version,
        "builtAt": datetime.now(timezone.utc).isoformat(),
        "sourceDigest": _source_digest(),
        "supportedRegions": list(SUPPORTED_REGIONS),
        "artifactBucketPattern": f"{artifacts.bucket_prefix}-<region>",
        "bedrockModels": [],
        "templates": {
            **{
                name: {
                    "dataRemoval": removal,
                    "url": {region: _object_url(artifacts, region, name) for region in SUPPORTED_REGIONS},
                }
                for name, removal in TEMPLATES.items()
            },
            MEMBER_ROLE_TEMPLATE: {
                "purpose": "Read-only member scan role (deployed automatically by the StackSet in "
                "AWS_ORGANIZATIONS mode; provided for self-managed rollouts).",
                "url": {region: _object_url(artifacts, region, MEMBER_ROLE_TEMPLATE) for region in SUPPORTED_REGIONS},
            },
        },
        "artifacts": [
            {"file": name, "key": artifacts.key(name), "sha256": digest} for name, digest in digests.items()
        ],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "checksums.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in digests.items()), encoding="utf-8"
    )
    (out / "RELEASE_NOTES.md").write_text(_release_notes(artifacts), encoding="utf-8")

    print(f"\nRelease written to {out}")
    for path in sorted(out.iterdir()):
        print(f"  {path.name:34} {path.stat().st_size:>12,} bytes")
    return 0


def _synthesize(artifacts: ReleaseArtifacts, removal: str, destination: Path) -> None:
    import yaml

    staging = tempfile.mkdtemp(prefix="sovereign-shield-synth-")
    assembly = Path(staging) / "assembly"
    _run(
        [
            _tool("cdk"), "synth", "--quiet", "--version-reporting", "false", "--path-metadata", "false",
            "--output", str(assembly),
            "-c", f"artifactBucketPrefix={artifacts.bucket_prefix}",
            "-c", f"releaseVersion={artifacts.version}",
            "-c", f"dataRemovalPolicy={removal}",
        ],
        cwd=PROJECT_ROOT / "cdk",
    )
    template = json.loads((assembly / "SovereignShieldStack.template.json").read_text(encoding="utf-8"))
    text = json.dumps(template)
    for forbidden in ("cdk-hnb659fds", "BootstrapVersion", "Custom::CDK"):
        if forbidden in text:
            raise SystemExit(f"Release template references {forbidden}; it would need CDK bootstrap.")
    destination.write_text(yaml.safe_dump(template, sort_keys=False, width=120), encoding="utf-8")
    shutil.rmtree(staging, ignore_errors=True)


def _write_member_role_template(destination: Path) -> None:
    """The same template the central StackSet deploys, for self-managed or manual onboarding."""

    import yaml

    destination.write_text(yaml.safe_dump(member_role_template(), sort_keys=False, width=120), encoding="utf-8")


def _lint(templates: list[Path]) -> None:
    try:
        import cfnlint  # noqa: F401
    except ImportError as exc:
        raise SystemExit("cfn-lint is required: pip install cfn-lint") from exc
    # cfn-lint's console entry point (cfnlint.runner:main); the package has no __main__.
    _run([
        sys.executable, "-c", "import sys; from cfnlint.runner import main; sys.exit(main())",
        "--regions", *SUPPORTED_REGIONS,
        # W1030: cfn-lint substitutes the empty ExistingKmsKeyArn default into both
        # branches of Fn::If; that branch is unreachable because the
        # ExistingKeyRequiresArn rule rejects an empty ARN in EXISTING_KEY_ARN mode.
        # W1033: likewise for the empty TargetOrganizationalUnitIds default inside the
        # StackSet, which exists only in AWS_ORGANIZATIONS mode, where the
        # OrganizationModeRequirements rule rejects empty OUs.
        # W3005: CDK adds explicit function->role DependsOn alongside GetAtt.
        "--ignore-checks", "W1030", "W1033", "W3005",
        "--", *map(str, templates),
    ])


def _zip_directory(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in source.rglob("*") if item.is_file()):
            info = zipfile.ZipInfo(path.relative_to(source).as_posix(), date_time=ZIP_TIMESTAMP)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def _sbom(version: str, lambda_manifest: dict) -> dict:
    lock = json.loads((PROJECT_ROOT / "console" / "package-lock.json").read_text(encoding="utf-8"))
    console_packages = sorted(
        (path.removeprefix("node_modules/").split("/node_modules/")[-1], entry["version"])
        for path, entry in lock.get("packages", {}).items()
        if path.startswith("node_modules/") and not entry.get("dev")
    )
    packages = [
        {
            "SPDXID": f"SPDXRef-pypi-{_spdx_id(dependency['name'])}",
            "name": dependency["name"],
            "versionInfo": dependency["version"],
            "downloadLocation": f"https://pypi.org/project/{dependency['name']}/{dependency['version']}/",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:pypi/{dependency['name'].lower()}@{dependency['version']}",
            }],
            "filesAnalyzed": False,
        }
        for dependency in lambda_manifest["dependencies"]
    ] + [
        {
            "SPDXID": f"SPDXRef-npm-{_spdx_id(name)}",
            "name": name,
            "versionInfo": package_version,
            "downloadLocation": f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{package_version}.tgz",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:npm/{urllib.parse.quote(name, safe='/')}@{package_version}",
            }],
            "filesAnalyzed": False,
        }
        for name, package_version in console_packages
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sovereign-shield-{version}",
        "documentNamespace": f"https://sovereign-shield.invalid/spdx/{version}",
        "creationInfo": {"created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "creators": ["Tool: scripts/build_release.py"]},
        "packages": packages,
    }


def _release_notes(artifacts: ReleaseArtifacts) -> str:
    def quick_create(region: str, template: str, stack_name: str) -> str:
        query = urllib.parse.urlencode(
            {"templateURL": _object_url(artifacts, region, template), "stackName": stack_name}
        )
        return f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/quickcreate?{query}"

    rows = "\n".join(
        f"| {region} | [Launch]({quick_create(region, 'sovereign-shield.yaml', 'SovereignShield')}) "
        f"| [Launch]({quick_create(region, 'sovereign-shield-nonprod.yaml', 'SovereignShieldTest')}) |"
        for region in SUPPORTED_REGIONS
    )
    return f"""# Sovereign Shield {artifacts.version}

## Launch

| Region | Production (retains data) | Non-production (deletes data) |
|---|---|---|
{rows}

The template creates IAM roles, so CloudFormation asks you to acknowledge
`CAPABILITY_IAM`. The roles are scoped to this stack's own resources plus
read-only discovery of the services Sovereign Shield assesses.

The non-production template requires `AcknowledgeDataDeletion` =
`{DATA_DELETION_ACKNOWLEDGEMENT}` and deletes all findings, reports, audit
records, users, and the encryption key with the stack.

## Prerequisites

- A supported region: {", ".join(SUPPORTED_REGIONS)}.
- Permissions in `installer-policy.json` (replace `${{AccountId}}`, `${{StackName}}`,
  `${{StackNameLowercase}}`, `${{DeploymentPrefix}}`, and `${{ArtifactBucketPrefix}}`).
- No Amazon Bedrock model access: scans and reports are deterministic.
- No CDK, Docker, source code, or uploaded files.

## AWS Organizations

Set `OrganizationMode` = `AWS_ORGANIZATIONS`, `OrganizationId`, and
`TargetOrganizationalUnitIds`, and confirm `AcknowledgeOrganizationPermissions`.
Deploy in the management account (`StackSetCallAs` = `SELF`) or a StackSets
delegated administrator (`DELEGATED_ADMIN`). StackSets trusted access must be
enabled for the organization. The stack deploys `sovereign-shield-member-role.yaml`
to every account under the OUs (minus `AccountDenylist`) and keeps it deployed
as accounts join. Per-account status appears on the console Accounts page.

## After deployment

1. Run the `PostDeployValidationCommand` stack output (read-only).
2. Open `ConsoleUrl` and sign in with the invitation sent to `AdministratorEmail`.
3. Scheduled scans are off unless `EnableScheduledScans` is `true`; no scan
   starts automatically.

## Cost drivers

Fixed: one KMS key (if created), CloudFront distribution, and CloudWatch
alarms and dashboard. Usage-based: Lambda, Step Functions, DynamoDB on-demand,
S3, API Gateway, and Cognito monthly active users. Scan cost grows with
regions x services per scan.

## Verification

`checksums.txt` lists SHA-256 digests of every artifact; `manifest.json`
records them with their release keys. `SBOM.spdx.json` lists runtime and
console dependencies.
"""


def _object_url(artifacts: ReleaseArtifacts, region: str, name: str) -> str:
    return f"https://{artifacts.bucket_prefix}-{region}.s3.{region}.amazonaws.com/{artifacts.key(name)}"


def _source_digest() -> str:
    digest = hashlib.sha256()
    for directory in SOURCE_DIRECTORIES:
        for path in sorted((PROJECT_ROOT / directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                digest.update(path.relative_to(PROJECT_ROOT).as_posix().encode())
                digest.update(path.read_bytes())
    return digest.hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _spdx_id(name: str) -> str:
    return "".join(character if character.isalnum() or character in ".-" else "-" for character in name)


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise SystemExit(f"{name} is required on PATH to build a release.")
    return found


def _run(command: list[str], *, cwd: Path | None = None) -> None:
    result = subprocess.run(command, cwd=cwd)
    if result.returncode != 0:
        raise SystemExit(f"Command failed ({result.returncode}): {' '.join(command[:3])} ...")


if __name__ == "__main__":
    sys.exit(main())
