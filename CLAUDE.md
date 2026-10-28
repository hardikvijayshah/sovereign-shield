# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sovereign Shield is a multi-agent AI system built with [Strands Agents SDK](https://strandsagents.com) that continuously scans AWS environments and evaluates them against data sovereignty regulations (GDPR, EU Data Act, India DPDP, China PIPL, Brazil LGPD, DORA, NIS2). Deployed to AWS via CDK (Lambda + Step Functions + EventBridge).

## Build and Run

```bash
# Install
pip install -e ".[dev]"

# Run locally (scans current AWS credentials' environment)
sovereign-shield --regions us-east-1,eu-west-1,eu-central-1 --regulations gdpr,dpdp
sovereign-shield --interactive   # chat mode after scan

# Tests
pytest                           # all tests
pytest tests/test_regulations.py # single file
pytest -k "test_gdpr"           # by name pattern

# Lint
ruff check src/ tests/
ruff format src/ tests/

# CDK deploy
cd cdk && pip install -e "../[cdk]" && cdk deploy
```

## Architecture

**Multi-agent system using Strands "agent-as-tool" pattern.** An orchestrator agent delegates to five specialist agents, each with its own tools and system prompt:

```
Orchestrator (src/sovereign_shield/agents/orchestrator.py)
  ├── jurisdiction_profiler  → regulation knowledge base (no AWS tools)
  ├── data_flow_scanner      → 8 AWS scanning tools (S3, RDS, DynamoDB, CloudFront, KMS, SNS/SQS, TGW, Lambda@Edge)
  ├── violation_detector     → check_violations tool (cross-refs scans against regulation constraints)
  ├── remediation_generator  → generate_remediation_plan + generate_scp_policy tools
  └── report_generator       → no tools (pure LLM synthesis)
```

- **Specialist agents** are defined in `src/sovereign_shield/agents/specialists.py` as `@tool`-decorated functions — each creates an inner `Agent()` with `callback_handler=None` (suppresses intermediate output)
- **AWS scanning tools** (`src/sovereign_shield/tools/aws_scanner.py`) use boto3 directly, with cross-account support via STS AssumeRole to `SovereignShieldScanRole`
- **Regulation knowledge base** (`src/sovereign_shield/regulations.py`) is a static `RegulationRegistry` mapping regulation IDs to `DataResidencyConstraint` objects with allowed/prohibited AWS regions per data category
- **Models** (`src/sovereign_shield/models/`) are Pydantic v2 — regulations, scan results, violations, and reports

## Web console (deployed)

React + Vite + TypeScript app in `console/`, served by CloudFront from a private bucket. Signs in with Cognito hosted login (authorization code + PKCE, implemented in `console/src/auth.ts`, no auth SDK) and calls only the `/v1/*` API. Runtime values come from `/config.json`, which the stack writes at deploy time.

```bash
cd console && npm ci
npm test            # vitest
npm run build       # tsc + vite build -> console/dist (deployed by the stack)
npm run dev         # needs public/config.json (see config.example.json) and -c consoleDevOrigins=http://localhost:5173
```

The build must stay CSP-clean: no inline scripts or styles (`assetsInlineLimit: 0`). Navigation hides actions the caller lacks (`console/src/nav.ts`), but the API enforces every action.

## Streamlit UI (local development only)

Not deployed. Web UI in `ui/` with 8 pages (Dashboard, Run Scan, Results, Remediation, SCP Policies, Schedule, Settings, Help). All backend calls route through `ui/api_client.py` which supports three modes:
- **API mode** (`SOVEREIGN_SHIELD_MODE=api`): calls Lambda via API Gateway or direct boto3 invoke
- **Local mode** (default): imports sovereign_shield tools directly

```bash
# Run locally
pip install -e ".[ui]"
streamlit run ui/app.py

# Build container
docker build -t sovereign-shield-ui .
docker run -p 8501:8501 sovereign-shield-ui
```

## AWS Deployment (CDK)

Stack in `cdk/stacks/sovereign_shield_stack.py` is the Phase 2 asynchronous, deterministic backend (no Bedrock in the deployed path):
- KMS key, `ScanRunsTableV1` + `FindingsTableV1` (`pk`/`sk`, PITR), private reports bucket — all RETAIN by default
- HTTP API with Cognito JWT authorizer on all eight `/v1/*` routes → `ApiFunction` (`lambda_handler.handler`)
- Step Functions Standard → `WorkflowFunction` (`workflow_handler.handler`): `admit_scheduled_run` → `prepare` → Map of `execute_work_item` (catch → `record_work_item_failure`) → `finalize`; `mark_failed` on any step error. Per-unit results go to S3 `work/` (DynamoDB's 400 KB item limit); workers update progress only via atomic `increment_progress`
- EventBridge Scheduler group (schedules are created only via `POST /v1/schedules`), SNS alerts, alarms, dashboard
- Customer choices are CloudFormation parameters (`_Parameters`: `DeploymentPrefix`, `AdministratorEmail`, `KmsKeyMode`, retention, `ScanConcurrency`, `EnableScheduledScans`, …). Dev-only context: `dataRemovalPolicy`, `allowedOrigins`, `consoleDevOrigins`, `releaseVersion`. Dev deploys pass `--parameters` every time (omitting `AdministratorEmail` removes the bootstrap user)
- Release mode (`-c artifactBucketPrefix=… -c releaseVersion=…`, `BootstraplessSynthesizer`) reads code from `<prefix>-<region>/releases/<version>/`; `scripts/build_release.py` → `release/<version>/`, `scripts/publish_release.py` publishes immutably. CloudFront names must stay derived from `AWS::StackId` (they are account-global)
- `deployment_handler.py` (custom resources: console publication, bucket emptier) and `readiness_handler.py` (PostDeployValidationCommand) ship in the same Lambda package
- AWS Organizations mode (Phase 5): `OrganizationMode=AWS_ORGANIZATIONS` adds a service-managed StackSet deploying `cdk/stacks/member_role.py` (single source for the member template; `SCANNER_READ_ACTIONS` lives there) and a 6-hourly `onboarding_handler.py` sync. `services/accounts.py` holds the registry, eligibility precedence (denylist > tag > allowlist > administrator), and the scan-target resolver. Member roles trust exact central role ARNs plus the external ID (stack UUID); central `sts:AssumeRole` is conditioned on `aws:ResourceOrgID`/`aws:ResourceOrgPaths`. Scans are capped at `MaxAccountsPerScan` and 1,000 work units. Router routes and HTTP API routes must match (`test_every_router_route_is_registered_on_the_http_api`)
- Requires `python scripts/build_lambda.py` (→ `dist/lambda_package.zip`, ~17 MB, reproducible) before deploy. The package excludes `agents/`, `cli.py`, and Strands; pins live in `scripts/lambda-requirements.txt`. `tools/invocation.py` provides a no-op `@tool` when Strands is absent, and `tests/test_deployed_runtime.py` enforces that the deployed handlers never import it
- `tests/test_cdk_stack.py` asserts security properties (JWT on every route, no wildcard CORS, encryption, no `sts:AssumeRole`)

- Phase 6 tooling: `python scripts/release_gate.py` must pass (ruff, pytest, console, pip-audit/npm audit, `scripts/secret_scan.py`, cfn-lint of release templates, Access Analyzer on installer + member policies) before publishing. `scripts/live_acceptance.py` runs upgrade/rollback/fresh-install with a temporary role holding ONLY `infrastructure/policies/installer-policy.json` — Access Analyzer passing does not prove the policy is sufficient. `scripts/support_bundle.py` collects masked diagnostics. Operator docs: `docs/OPERATIONS.md`, `docs/DATA_RESIDENCY.md`, `docs/REGULATION_COVERAGE.md`, `docs/PILOT_KIT.md`
- Coverage-gap messages are redacted (`redact_error_text`/`redact_exception` in `services/scan_engine.py`); never store raw AWS error text

`lambda_handler.py` still contains the legacy agent actions (`scan`, `chat`, …) for direct invocation, but the deployed API routes only `/v1/*`. The App Runner Streamlit service and REST `/scan` endpoint are no longer deployed (plan.md §2.3).

## Key Conventions

- Default Bedrock model: `us.anthropic.claude-sonnet-4-20250514-v1:0` — configurable via `BEDROCK_MODEL_ID` env var
- All scanning tools return JSON strings (Strands tools must return `str`)
- Violation severity levels: critical > high > medium > low > info
- Regulation IDs used throughout: `gdpr`, `eu-data-act`, `dpdp`, `pipl`, `lgpd`, `dora`, `nis2`
