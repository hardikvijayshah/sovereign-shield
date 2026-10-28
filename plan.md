# Sovereign Shield: Customer-Deployable Product Plan

## 1. Objective

Turn Sovereign Shield from a developer-run CDK demo into a secure, repeatable customer deployment that installs into the customer's AWS account with a CloudFormation launch flow. Terraform follows only after the CloudFormation interface and lifecycle are stable.

The deployed product must:

- scan the customer's AWS estate without user-supplied AWS credentials;
- support a single account first, then AWS Organizations multi-account scanning;
- provide authenticated access to scans, results, reports, schedules, and remediation guidance;
- keep findings, reports, configuration, and audit data in the customer's account;
- deploy from immutable vendor release artifacts, with no customer-side source checkout, Docker build, CDK installation, or CDK bootstrap;
- provide safe upgrades, rollback guidance, retention controls, monitoring, and a documented uninstall path.

## 2. Delivery decisions

### 2.1 Distribution

CloudFormation is the canonical customer-installation format.

- CDK may remain an internal authoring tool, but publish the synthesized and versioned CloudFormation template as the customer artifact.
- Do not ask a customer to run `cdk bootstrap`, `cdk deploy`, `pip install`, or `docker build`.
- Publish a stable release manifest and a CloudFormation Quick Create link.
- Add Terraform only after the CloudFormation parameters, outputs, IAM permissions, and lifecycle behavior are accepted.

### 2.2 Initial support boundary

The first released version supports commercial AWS partitions and a documented set of AWS regions where the selected Bedrock model and all required services are available.

- Do not claim AWS GovCloud or AWS China support until artifact distribution, ARN partitions, IAM principals, and Bedrock availability have been independently tested.
- Fail early with a clear message for unsupported region/model combinations.
- Include a region-and-model support matrix in every release.

### 2.3 Target architecture

Use deterministic code for discovery and policy evaluation. Use Bedrock only for optional natural-language report and remediation enrichment.

```text
Authenticated browser
    |
    +-- Cognito / customer OIDC or SAML identity provider
    |
CloudFront + static web UI
    |
API Gateway HTTP API with JWT authorizer
    |
    +-- Start Scan API --> coordinator --> Step Functions Standard
    |                                     |
    |                                     +-- account x region workers
    |                                     +-- normalized findings
    |                                     +-- rule evaluation
    |                                     +-- optional Bedrock report
    |
    +-- Scan status, findings, reports, schedules, and configuration APIs

Customer-owned DynamoDB + S3 + KMS + CloudWatch + EventBridge Scheduler
```

Replace the customer-facing Streamlit/App Runner deployment with a static authenticated web UI. This removes the current public App Runner endpoint, avoids customer-side image builds, reduces idle cost, and makes Cognito authentication straightforward.

If Streamlit must be retained temporarily, run it behind an ALB with Cognito authentication on ECS/Fargate. Do not expose the current App Runner endpoint as the production console.

## 3. Current-state gaps to remediate

These are implementation requirements, not optional hardening.

1. Current CDK deployment builds local Lambda and Docker assets. Release deployment must reference immutable published artifacts.
2. The public API currently allows all origins and has no authorizer. Every state-changing or data-returning route must require an authenticated user.
3. The API runs a full agent scan synchronously. Replace this with a scan-run API and asynchronous workflow; API Gateway is not a long-running job interface.
4. DynamoDB tables and the report bucket are provisioned but are not used to persist scan state, findings, reports, or schedules.
5. The EventBridge schedule is static, while the UI schedule page stores configuration only in Streamlit session memory. Persist schedules and manage them through an API.
6. Cross-account role setup is manual. A target role requires an external ID, but the scanner does not pass one. Fix this before cross-account scanning is offered.
7. Resource names, model ID, layer ARN, default regions, and schedule are hard-coded. Make them validated deployment configuration.
8. The external Lambda layer ARN is not a portable product dependency. Build, publish, and version a product-owned runtime package.
9. The agent-led flow produces unstructured text. The scanner, policy engine, API, and persistence layer need stable typed data contracts.
10. Deployment guidance asks customers for broad permissions and recommends AdministratorAccess. Publish a least-privilege installer policy and a separate optional organization-administration policy.

## 4. Public deployment contract

### 4.1 CloudFormation parameters

Expose a small, grouped parameter set through `AWS::CloudFormation::Interface` metadata. Do not expose internal table names, artifact locations, or implementation details.

| Group | Parameter | Requirement |
|---|---|---|
| Identity | `DeploymentPrefix` | 3-24 lowercase letters, numbers, and hyphens; used in physical names and tags. |
| Runtime | `HomeRegion` | Stack region; validate against the release support matrix. |
| Runtime | `BedrockModelId` | Allowed values for the selected release and region. |
| Scan scope | `OrganizationMode` | `SINGLE_ACCOUNT` by default; `AWS_ORGANIZATIONS` is explicit opt-in. |
| Scan scope | `OrganizationId` | Required only in organization mode and pattern-validated. |
| Scan scope | `DefaultScanRegions` | Comma-separated, validated commercial-region set. |
| Scheduling | `EnableScheduledScans` | Default `false`; installation must never silently begin scans. |
| Scheduling | `DefaultScheduleExpression` | Required only when scheduling is enabled; validate supported cron/rate format. |
| Data protection | `KmsKeyMode` | `AWS_MANAGED`, `CREATE_CUSTOMER_MANAGED`, or `EXISTING_KEY_ARN`. |
| Data protection | `ExistingKmsKeyArn` | Required only for `EXISTING_KEY_ARN`. |
| Data protection | `FindingsRetentionDays` | Bounded number, with a documented default. |
| Data protection | `ReportRetentionDays` | Bounded number, with a documented default. |
| Access | `IdentityProviderMode` | `COGNITO_LOCAL` initially; retain an extension path for enterprise OIDC/SAML. |
| Access | `AdministratorEmail` | Optional bootstrap administrator; validate email format. |
| Lifecycle | `DataRemovalPolicy` | `RETAIN` by default; non-production deletion requires explicit acknowledgement. |
| Notifications | `NotificationEmail` | Optional recipient for scan failures and critical-finding alerts. |
| Tags | `CostCenter`, `Environment`, `Owner` | Optional tags propagated to all taggable resources. |

Use Conditions for optional features. Validate malformed values before a scan is accepted, rather than passing arbitrary strings to an LLM.

### 4.2 Outputs

Return only durable, operator-useful values:

- `ConsoleUrl`
- `ApiUrl`
- `ScanRunTableName`
- `FindingsTableName`
- `ReportsBucketName`
- `KmsKeyArn`
- `ScannerRoleArn`
- `OrganizationOnboardingStatus`
- `OperationsDashboardUrl`
- `PostDeployValidationCommand`
- `ReleaseVersion`

### 4.3 Customer launch experience

The release page must show:

1. product version, supported regions, and release notes;
2. cost drivers and estimated baseline cost;
3. prerequisites, including Bedrock model access and organization permissions;
4. a Quick Create button using a versioned template;
5. a concise least-privilege deployment policy;
6. the `CAPABILITY_NAMED_IAM` acknowledgement and why it is required;
7. post-deploy validation, account onboarding, upgrade, and removal steps.

## 5. Runtime implementation plan

### 5.1 Establish typed, deterministic contracts

Create a versioned domain contract before changing infrastructure.

- Define `ScanRequest`, `ScanRun`, `ScanTarget`, `ScanStatus`, `Finding`, `Evidence`, `Report`, `Schedule`, and `RemediationRecommendation`.
- Include `schemaVersion`, `scanRunId`, account ID, region, service, resource ARN, rule ID, evidence timestamp, severity, and rule version in all persisted findings.
- Call every selected scanner directly. Do not depend on an agent deciding whether to call a scanner.
- Make regulation evaluation deterministic and rule-versioned. Record unknown data classification or legal basis as uncertainty, not as a confirmed violation.
- Treat AWS resource names, tags, descriptions, and account-provided input as untrusted data when composing Bedrock prompts. Label them as data, never execute embedded instructions, and do not give the report model infrastructure-changing tools.
- Keep Bedrock reporting optional. A scan must still create structured findings and usable remediation guidance if Bedrock is unavailable.

Acceptance criteria:

- A scan with Bedrock disabled completes and persists normalized findings.
- Unit tests cover each supported scanner and each regulation rule.
- A rule's evidence can be reproduced from the saved scan record.

### 5.2 Build the asynchronous workflow

Replace the synchronous scan action with these APIs:

| Route | Behavior |
|---|---|
| `POST /v1/scans` | Validates targets, creates a `ScanRun`, starts an asynchronous workflow, and returns `202` with `scanRunId`. |
| `GET /v1/scans/{scanRunId}` | Returns status, progress, timestamps, error summary, and links to findings/report. |
| `GET /v1/scans/{scanRunId}/findings` | Returns paginated structured findings; filtering occurs server-side. |
| `GET /v1/scans/{scanRunId}/report` | Returns report metadata and a short-lived report download URL when authorized. |
| `POST /v1/schedules` | Creates a persisted, validated scheduled scan. |
| `PATCH /v1/schedules/{scheduleId}` | Updates or pauses a schedule. |
| `DELETE /v1/schedules/{scheduleId}` | Deletes a schedule after an explicit authenticated request. |
| `GET /v1/configuration` | Returns safe customer configuration and supported scan choices. |

Use Step Functions Standard for the workflow:

1. validate the accepted request and resolve the account allowlist;
2. create idempotent account/region tasks;
3. use bounded concurrency and retry only transient AWS errors;
4. execute global-service scans once per account;
5. persist raw scanner outcomes and service/region errors;
6. aggregate evidence and run deterministic policy evaluation;
7. optionally invoke the Bedrock reporting worker;
8. persist report metadata and report object;
9. mark the run complete, partial, failed, or cancelled;
10. emit metrics and send requested notifications.

Each worker Lambda must process a bounded account/region/service unit and be idempotent by `scanRunId + accountId + region + service`. EventBridge schedules must start the state machine, never invoke a full scan Lambda directly.

### 5.3 Persist customer-owned product data

- Store `ScanRun` status, request details, progress, and schedule definitions in DynamoDB.
- Store findings in a queryable table keyed by scan run and indexed by severity, rule, account, region, and remediation state as required by the UI.
- Store large evidence payloads and reports in S3 under versioned prefixes such as `reports/<scanRunId>/...`.
- Enable DynamoDB point-in-time recovery, TTL for transient scan work, and S3 lifecycle expiration according to template parameters.
- Create explicit CloudWatch Log Groups with configurable retention and KMS encryption where supported.
- Add data classification/redaction before writing logs, reports, or Bedrock prompts.
- Record scan requests, schedule changes, report downloads, and configuration changes for audit.

Migration rule: do not mutate the current unused table schema in place. Introduce versioned tables or a documented migration path so existing deployments can upgrade safely.

### 5.4 Scheduling and notifications

- Persist schedules in DynamoDB and create them through EventBridge Scheduler in a dedicated schedule group.
- Store the exact versioned scan request with each schedule.
- Permit only approved regions/accounts and bounded schedule frequency.
- Use SNS or a customer EventBridge destination for scan failures and critical-finding summaries; keep detailed findings in the authenticated console.
- Record each scheduled execution as a normal `ScanRun`.

## 6. Identity, API, and network security

### 6.1 User authentication and authorization

Implement Cognito authorization-code flow with PKCE for the initial release.

- Create a user pool, app client, callback/logout URLs, administrator group, and auditor group.
- Protect every API route with an API Gateway JWT authorizer.
- Enforce authorization in the service layer: administrators manage schedules/settings; auditors view scans, findings, and reports.
- Do not accept AWS access keys, profiles, or secrets through the deployed UI.
- Add enterprise federation later as a supported configuration mode, not an undocumented customization.

### 6.2 API and UI exposure

- Serve a static web application through CloudFront and S3.
- Allow API CORS only from deployed UI origins, with explicit methods and headers. Do not use `*`.
- Apply API throttling, request-size limits, structured error responses, and redacted access logging.
- Attach AWS WAF to public CloudFront/API endpoints where supported by the product tier.
- Keep the reports bucket private; provide short-lived, authorized pre-signed URLs only.

### 6.3 Runtime IAM

Create separate roles for API coordination, scan workers, report generation, Step Functions, EventBridge Scheduler, notifications, cross-account scanning, and optional Organizations onboarding.

Grant only necessary actions. Document every wildcard that cannot be avoided for AWS `Describe`/`List` APIs and scope it by service, region, account, tag, or role ARN whenever AWS supports it. Use permissions boundaries where customers require them.

## 7. Account onboarding

### 7.1 Single-account mode

The central scanner role scans the account containing the stack. No STS assume-role call is needed.

- Deploy with `OrganizationMode=SINGLE_ACCOUNT`.
- Keep recurring scans disabled by default.
- Provide a post-deploy readiness check for Bedrock access, KMS permissions, and selected scan regions.

### 7.2 AWS Organizations mode

Deploy the central stack in the management account or approved delegated administrator account.

- Require organization ID and explicit acknowledgement of organization-level permissions.
- Use CloudFormation StackSets with service-managed permissions to deploy a member `SovereignShieldScanRole` into selected OUs/accounts.
- Trust the exact central scanner role ARN, not the scanner account root.
- Limit role deployment to selected OUs/accounts and report per-account onboarding status.
- Add account allowlist/denylist and exclusion tags for accounts that must never be scanned.
- If an external ID is retained, generate/store it per installation and pass it in every `AssumeRole` call. Otherwise remove that condition from the member trust policy; never leave the current mismatch.
- Restrict central `sts:AssumeRole` to approved member-role ARNs or organization paths, not `arn:aws:iam::*:role/SovereignShieldScanRole`.

Document CloudFormation StackSet trusted access and delegated-administrator registration as prerequisites where they cannot be safely enabled automatically.

## 8. CloudFormation implementation plan

### 8.1 Internal layout

Create these deliverables:

```text
infrastructure/
  cloudformation/
    sovereign-shield.yaml              # central customer stack
    sovereign-shield-member-role.yaml  # StackSet member template
    parameters/
      development.json
      production.json
  policies/
    installer-policy.json
    runtime-boundary.json
release/
  manifest.json
  checksums.txt
  SBOM.spdx.json
```

The customer receives only versioned CloudFormation templates and published artifact references. CDK source and asset staging remain internal build concerns.

### 8.2 Central stack resources

Create, conditionally where appropriate:

- customer-owned KMS key/alias or customer-supplied key reference;
- private report/evidence S3 bucket with versioning, lifecycle, encryption, block-public-access, and explicit deletion policy;
- DynamoDB tables for run state, findings, schedules, and audit records, with point-in-time recovery and encryption;
- Lambda functions/layers from versioned release artifacts;
- Step Functions Standard state machine, execution log group, and IAM role;
- API Gateway HTTP API, JWT authorizer, routes, access logs, throttles, and permissions;
- Cognito resources and user groups;
- UI asset bucket and CloudFront distribution with secure headers and origin access control;
- EventBridge Scheduler group and role;
- SNS topic/subscriptions when notifications are enabled;
- CloudWatch dashboard, alarms, and optional budget alarm;
- Organizations StackSet resources only when organization mode is selected.

Tag every supported resource with `Application=SovereignShield`, `DeploymentPrefix`, `ReleaseVersion`, `Environment`, `Owner`, and `CostCenter`.

### 8.3 Naming and lifecycle rules

- Generate physical names from `DeploymentPrefix`, account, region, and controlled suffixes; do not use fixed global names.
- Preserve logical IDs across compatible upgrades.
- Default customer data to `DeletionPolicy: Retain` and explain cleanup in stack outputs and documentation.
- Permit automated deletion only in an expressly acknowledged non-production configuration.
- Use change sets for upgrades and document breaking-change migration steps.

### 8.4 Validation

Provide non-mutating preflight and post-deployment readiness checks for:

- deployment region and Bedrock model availability;
- quotas and naming constraints;
- KMS key policy compatibility;
- optional organization/StackSet prerequisites;
- UI/API authentication configuration;
- dry-run scanner permission checks;
- alarm and log delivery configuration.

Do not make a real customer scan a hidden deployment-time side effect.

## 9. Release artifacts and supply chain

### 9.1 Build artifacts

Every release produces:

- a fully bundled Lambda package or container image with pinned runtime dependencies;
- a static web UI bundle;
- versioned CloudFormation templates;
- member-role StackSet template;
- release manifest with version, commit, SHA-256 checksums, supported regions, Bedrock-model matrix, and asset URIs;
- SBOM and dependency/license report.

Replace unpinned dependency ranges for production construction with a locked, hash-verified dependency set. Build for the Lambda architecture and Python runtime used in the template.

### 9.2 Artifact publishing

- Publish immutable assets under release-versioned keys and never overwrite released keys.
- Replicate Lambda artifacts into every supported stack region or use a supported service-native distribution channel.
- If an image-backed transitional UI remains, use a pinned digest, never a mutable image tag.
- Make CloudFormation artifact access explicit for the selected distribution model: private vendor distribution, AWS Marketplace, Serverless Application Repository where applicable, or approved customer release bucket.
- Sign code and retain provenance where the distribution path supports it; verify checksums during release validation.

### 9.3 CI/CD

For every pull request:

1. format, lint, type-check, and run unit tests;
2. build deterministic Lambda and UI artifacts;
3. synthesize CloudFormation and run `cfn-lint`;
4. run IaC/security policy checks and secret scanning;
5. run Terraform formatting/validation once Terraform exists;
6. generate an SBOM and verify dependency licenses;
7. run contract tests against API and typed models.

For a release:

1. require a tagged commit and changelog entry;
2. build in a clean isolated environment;
3. publish immutable artifacts and manifest;
4. deploy into a fresh test account;
5. run authenticated end-to-end smoke tests;
6. test an in-place upgrade from the previous supported version;
7. publish release notes, checksums, and Quick Create link only after acceptance tests pass.

## 10. Web console requirements

The authenticated console must include:

- sign-in/sign-out and clear access-denied behavior;
- guided first-run selection of scan regions, regulations, optional accounts/OUs, and schedules after prerequisite validation;
- scan-run launch, progress, and cancellation view;
- server-side paginated findings filters;
- evidence and rule-version visibility for every finding;
- authorized report viewing/download;
- remediation guidance clearly marked as guidance, with no automatic destructive remediation;
- schedule management backed by the scheduling API;
- administrator-only configuration, retention, and notification settings;
- operations/status view showing CloudWatch links and onboarding state.

The console must not collect AWS access keys, store configuration only in browser/session memory, call a public unauthenticated scan endpoint, promise legal compliance, or automatically attach SCPs/remediations.

## 11. Terraform parity plan

> **Descoped (2026-10-27):** the product deploys only through CloudFormation. This section is retained for reference only.

Terraform begins after the CloudFormation contract is accepted.

```text
terraform/
  modules/sovereign-shield/
  examples/single-account/
  examples/organizations/
```

Requirements:

- mirror accepted CloudFormation inputs, defaults, output meanings, encryption choices, tags, and deletion behavior;
- use immutable release artifact versions;
- provide formatting, validation, policy checks, examples, and deployed acceptance tests;
- maintain a parity matrix comparing resources, IAM actions, outputs, and lifecycle behavior with CloudFormation for each release.

Terraform must not become a separate product with different runtime behavior.

## 12. Testing strategy

### 12.1 Unit and contract tests

- Scanner tests for each service, including pagination, partial failures, access denial, unsupported regions, and cross-account role use.
- Rule-engine tests for every regulation, allowed/prohibited region, adequacy exception, unknown classification, encryption condition, and evidence output.
- API tests for validation, authorization, pagination, idempotency, status transitions, and error redaction.
- Tests proving that configured external IDs are passed in `AssumeRole`.
- Tests proving Bedrock outage does not discard deterministic findings.
- Tests proving untrusted resource names/tags cannot alter workflow instructions or invoke remediation actions.

### 12.2 Infrastructure and end-to-end tests

- CDK/synthesis assertions while CDK remains the authoring source.
- CloudFormation lint and policy checks.
- IAM policy tests rejecting wildcard principals, public report buckets, unauthenticated routes, and unrestricted CORS.
- Fresh-account deployment tests in every advertised region.
- Organization integration tests with StackSets, excluded accounts, failed member deployment, and role revocation.
- Upgrade, rollback, and retain/delete lifecycle tests.

In a disposable AWS environment:

1. launch the published template;
2. authenticate as administrator and auditor;
3. run a bounded scan and verify asynchronous progress;
4. create a known test finding and verify evidence, report, and notification;
5. create, pause, and delete a schedule;
6. verify unauthorized users cannot start scans or download reports;
7. verify report storage is not publicly readable;
8. upgrade via change set and validate retained data;
9. remove a test stack and verify selected retention behavior.

## 13. Operations, cost, and documentation

### 13.1 Observability

Create dashboard and alarms for failed/timed-out Step Functions executions, Lambda errors/throttles/duration, API 4xx/5xx, authorization failures, schedule delivery failures, Bedrock errors/throttling, report failures, DynamoDB throttling, and storage growth.

Provide a support bundle command that gathers non-sensitive stack status, release version, configuration validation, and recent error IDs.

### 13.2 Cost controls

- Show fixed and variable cost drivers before deployment.
- Keep schedules disabled by default.
- Bound account count, region count, concurrency, report size, and retry limits.
- Offer budget alarms and cost allocation tags.
- Let customers choose whether LLM reporting is enabled per scan/schedule.

### 13.3 Documentation

Publish deployment, least-privilege installer, architecture/data-flow, Bedrock data-use, regulation coverage/limitations, single-account and Organizations onboarding, upgrade/rollback/decommissioning, operations, supported-region, and release-notes guides.

## 14. Delivery sequence and completion gates

### Implementation tracker

| Phase | Status | Completion evidence |
|---|---|---|
| Phase 0: Product contract | Complete | Product architecture and v1 customer contract were accepted to proceed. The empirically tested release support matrix is a Phase 4 release gate. |
| Phase 1: Deterministic scan core | Complete | Typed contracts, direct scanner orchestration, fault-tolerant scanner normalization, pure category-aware rules, stable evidence-linked findings, and persistence ports/adapters are implemented. The executable acceptance matrix covers every supported scanner and regulatory constraint with Bedrock disabled. |
| Phase 2: Asynchronous backend | Complete | Coordinator, durable lifecycle, role-enforced v1 scan/schedule APIs, deterministic reports, EventBridge Scheduler, notifications/metrics, and the CDK workflow infrastructure (KMS-encrypted tables and bucket, Cognito JWT on every route, alarms, dashboard, separate least-privilege roles). Scans fan out through a Step Functions Map state: prepare -> one bounded worker per account/region/service with per-unit S3 results and atomic progress -> finalize; crashed units become coverage gaps. Exit gate met in the sandbox (eu-central-1) on 2026-10-26: `scripts/smoke_test.py` 14/14, `scripts/failure_checks.py` 10/10, and a 16-unit, 5-region scan completed through the Map in 12.3 s. The crashed-unit path is covered by unit tests and synthesized-template assertions but was not forced live. |
| Phase 3: Secure customer console | Complete | React + Vite + TypeScript console (`console/`) on CloudFront from a private bucket with strict CSP/HSTS/frame denial; Cognito hosted sign-in with authorization code + PKCE and only the console callback registered; CORS limited to the console origin. New APIs: scan/schedule listing (sparse `by-entity-created` index), configuration with role-specific allowed actions, server-side findings filters, 5-minute signed report downloads, deterministic read-only remediation guidance per finding category, and an append-only, administrator-only audit log (starts, cancellations, schedule changes, report links, denied attempts). Deployed to the sandbox on 2026-10-26: `scripts/smoke_test.py` 27/27 (administrator/auditor authorization end to end, console headers, SPA routing, callback restriction) and `scripts/failure_checks.py` 10/10. Exit gate met: administrator browser sign-in confirmed by the user; administrator/auditor authorization verified end to end by the smoke test. Index-backfill responses (found live: listing failed for ~100 s after the upgrade added the index) now return 503 with `Retry-After`, deployed and re-verified 27/27. The Streamlit UI is local-development only and is not deployed. |
| Phase 4: CloudFormation release package | Complete | One parameterized CDK source produces bootstrapless release templates: `sovereign-shield.yaml` (retains data) and `sovereign-shield-nonprod.yaml` (deletes data, explicit acknowledgement parameter), because CloudFormation cannot take `DeletionPolicy` from a parameter. Launch parameters per section 4.1 with Interface grouping, a supported-region Rule (eu-central-1, eu-west-1, us-east-1, us-west-2), and `KmsKeyMode` CREATE/EXISTING (AWS_MANAGED deferred: alarm notifications need a customer-managed key). No `BedrockModelId` (deployed path never calls Bedrock). Product-owned deployment and readiness functions replace CDK helper custom resources. `scripts/build_release.py` (cfn-lint clean, manifest, checksums, SPDX SBOM, Quick Create notes) and `scripts/publish_release.py` (per-region vendor buckets, Block Public Access, account allowlist, immutable keys, S3-verified SHA-256). Installer policy validated by IAM Access Analyzer (0 findings). Exit gate met on 2026-10-26: release 1.0.1 created with plain `create-stack` in eu-west-1 (no CDK bootstrap, no prior stack); readiness 15/15, smoke test 24/24 with defaults and 27/27 after a change set enabling schedules, failure checks 10/10. Release testing found account-global CloudFront names (fixed in 1.0.1; 1.0.0 remains published but is superseded). Follow-ups: deploy under a role holding only the installer policy; version-to-version upgrade test with the next release; CI/CD pipeline (section 9.3); code signing; cross-account reader test. |
| Phase 5: Organizations onboarding | Built; live verification pending | Built and tested on 2026-10-26 without a live organization (none available). Implemented: `OrganizationMode=AWS_ORGANIZATIONS` with organization ID, target OUs, acknowledgement, and `StackSetCallAs` (management or delegated administrator), enforced by a template Rule; a service-managed StackSet with auto-deployment deploys a read-only member role (single-source `cdk/stacks/member_role.py`, also published as `sovereign-shield-member-role.yaml`) trusting only the exact central role ARNs, with the installation's external ID and `aws:PrincipalOrgID`; central `sts:AssumeRole` is limited to the member role name, `aws:ResourceOrgID`, and `aws:ResourceOrgPaths` under the selected OUs; account allowlist, denylist (StackSet DIFFERENCE filter), exclusion tag, and administrator exclusions with fixed precedence; a 6-hourly and on-demand onboarding sync recording per-account status (onboarded, pending, failed, role unreachable, excluded, suspended, out of scope); multi-account scans with frozen target accounts, per-account finding attribution, re-checked eligibility per unit, and `MaxAccountsPerScan` plus 1,000-unit bounds; `/v1/accounts` list/sync/exclude APIs (audited); console Accounts page, account scope selection with work-unit estimates, and account columns and filters; organization readiness checks; installer and member-role policies validated by IAM Access Analyzer (0 findings). The external-ID mismatch is fixed and the manual `scripts/cross_account_role.yaml` (trusting the whole account) was removed. Evidence: 227 Python and 22 console tests. Remaining exit gate: deploy into an organization, onboard a selected OU, verify an excluded account, a failed member deployment, and role revocation, and scan the OU without manual per-account installation. |
| Phase 6: Production readiness | Built and accepted; customer pilot pending | Started 2026-10-26. Release gate (local, in place of hosted CI/CD): `scripts/release_gate.py` runs ruff, pytest, console type-check/tests/build, pip-audit and npm audit, `scripts/secret_scan.py`, cfn-lint of the release templates, and IAM Access Analyzer on the installer and member-role policies; it passes 7/7. The dependency audit found 12 urllib3 1.26.20 advisories, fixed by pinning 2.8.0. P0 data residency: `docs/DATA_RESIDENCY.md` inventories what the product stores and what leaves the home region. Hardening: coverage-gap messages no longer store raw AWS error text; STS uses regional endpoints; metric-filter alarms for audit-write failures, authorization denials, and onboarding errors (12 alarms in total); optional `MonthlyBudgetUsd` budget; `scripts/support_bundle.py` collects masked diagnostics. Docs: `docs/OPERATIONS.md` (alarm runbook, backup/restore, upgrade, rollback, decommissioning), `docs/REGULATION_COVERAGE.md`, `docs/PILOT_KIT.md`. Live acceptance with a role holding only the installer policy (`scripts/live_acceptance.py`, eu-west-1, 2026-10-27): the published 1.1.0 policy passed Access Analyzer but failed a real upgrade (missing tag, read, scheduler, Cognito-group, and API Gateway tag permissions; the stack rolled back cleanly). After fixes: the upgrade from 1.0.1 to 1.1.0 changed 78 resources with no data resource replaced; a forced-failure update rolled back to `UPDATE_ROLLBACK_COMPLETE` with the intended trigger; a fresh non-production install was created and deleted. All three passed, with no orphaned resources. The rollback check now fails if any other error triggers the rollback, because an earlier run orphaned a schedule group that way. Release 1.1.1, published 2026-10-27 to all four regions after the gate passed 7/7 again, carries the corrected installer policy (sha256 `1ddcbc1d…`). Its runtime and console packages are byte-identical to 1.1.0. Removal and retention (`live_acceptance.py --steps removal`, 1.1.1, eu-west-1, 2026-10-27): each template was installed with the installer-only role, populated by the smoke test (24/24 passed; 23-24 table items and 4 report objects), and deleted with the same role. The non-production stack left nothing behind. The production stack kept exactly the documented 13 resources: 3 tables, the reports bucket, the KMS key, the user pool, and 7 log groups; the console bucket was deleted. Following the decommissioning steps in `docs/OPERATIONS.md` then removed all of them (the key enters a 7-day pending-deletion window), with no orphaned log groups or schedule groups. Not done: a representative customer pilot (kit prepared), and the Phase 5 live organization test. |
| Phase 7: Terraform parity | Descoped | Descoped by the product owner on 2026-10-27. The product deploys only through the published CloudFormation templates (single-account or Organizations mode), so a separate Terraform path is not needed. Section 11 is kept for reference in case a customer later requires Terraform; the release gate's Terraform step (section 9.3, item 5) does not apply. |

### Phase 0: Product contract

Deliver architecture decision, region/model matrix, CloudFormation contract, customer data classification, and single-account/Organizations onboarding decision.

Exit gate: product, security, and platform owners approve the contract.

### Phase 1: Deterministic scan core

Implement typed contracts, direct scanner execution, deterministic rules, structured evidence, persistence, and tests.

Exit gate: a complete structured scan runs without Bedrock.

### Phase 2: Asynchronous backend

Implement coordinator, Step Functions workflow, status/findings/report APIs, durable schedules, notifications, observability, and IAM boundaries.

Exit gate: a single-account scan works without a long-lived HTTP request and survives worker retry/failure conditions.

### Phase 3: Secure customer console

Implement Cognito-backed authorization and durable console, then remove production reliance on unauthenticated Streamlit/App Runner.

Exit gate: administrator/auditor end-to-end authorization tests pass.

### Phase 4: CloudFormation release package

Build parameterized templates, immutable runtime/UI artifacts, release manifest, Quick Create page, installer policy, and post-deploy validation.

Exit gate: a clean commercial AWS account deploys without CDK, Docker, source code, or manually uploaded assets.

### Phase 5: Organizations onboarding

Implement StackSet member roles, account selection/exclusion, cross-account trust, onboarding status, and organization integration tests.

Exit gate: a selected OU is onboarded and scanned without manual per-account installation.

### Phase 6: Production readiness

Complete fresh-install, upgrade, rollback, removal, security, cost, and operational acceptance tests. Run a representative customer pilot.

Exit gate: no unresolved P0/P1 deployment, security, or data-residency concerns remain.

### Phase 7: Terraform parity

Implement and test Terraform against the accepted CloudFormation contract.

Exit gate: the parity matrix is complete and both paths pass the same core acceptance suite.

## 15. Non-goals for the first production release

- automatic deletion, migration, or modification of customer resources;
- automatic SCP attachment or remediation execution;
- legal certification or guaranteed regulatory compliance;
- support for every AWS partition/region before testing;
- collecting customer AWS access keys;
- requiring customers to build or host product artifacts;
- enabling recurring scans by default.

## 16. Definition of done

Sovereign Shield is a single-click customer deployment only when a customer can open a versioned CloudFormation launch link, choose validated parameters, deploy into a clean supported AWS account, sign in through a protected console, start and track a durable scan, review customer-owned findings and reports, configure approved schedules, upgrade via change set, and remove the stack with documented retention behavior—without development tools, access keys, or direct engineering assistance.
