# Sovereign Shield v1 Product Contract

## 1. Purpose

This contract defines what a customer receives when they deploy Sovereign Shield
v1 into their AWS account. It is the implementation baseline for Phase 0 and
the source of truth for CloudFormation inputs, UI behavior, APIs, permissions,
data handling, and acceptance testing.

This is a product contract, not legal advice. Sovereign Shield provides
evidence-based data-sovereignty assessments. A customer remains responsible for
validating legal applicability, data classification, transfer mechanisms, and
remediation decisions.

## 2. Customer promise

After deploying a versioned CloudFormation stack into a supported commercial AWS
region, a customer can:

1. sign in to a protected Sovereign Shield console;
2. start a read-only assessment of selected services and regions in the
   deployment account;
3. follow asynchronous scan progress instead of holding a browser connection;
4. review evidence-backed findings, scan coverage gaps, rule versions, reports,
   and remediation guidance;
5. explicitly create or pause scheduled scans;
6. retain, export, and remove data according to documented lifecycle controls;
7. upgrade using a CloudFormation change set.

The installation does not require the customer to clone this repository, build
Docker images, install CDK, upload a Lambda package, or provide AWS access keys
in the UI.

## 3. Release 1 scope

### Included

- Commercial AWS partition only.
- One deployment account per installation.
- Read-only discovery of S3, RDS, DynamoDB, CloudFront, KMS, SNS/SQS, Transit
  Gateway, and Lambda@Edge configurations.
- On-demand scans with a selected set of regions, regulations, and supported
  services.
- Deterministic findings based on versioned policy rules.
- Optional Bedrock-enhanced executive narrative; deterministic reports remain
  available if this is disabled or unavailable.
- Cognito-backed administrator and auditor access.
- Customer-owned encrypted findings, evidence, reports, schedules, audit
  events, and logs.
- Explicitly enabled scheduled scans.

### Deferred

- AWS Organizations account onboarding and StackSet deployment.
- Enterprise OIDC/SAML federation.
- Private-VPC-only deployment.
- GovCloud and China partitions.
- Automatic SCP attachment, automated remediation, or changes to customer
  infrastructure.
- Legal certification, jurisdiction-specific legal determinations, or
  enforcement claims.

## 4. Deployment model

### 4.1 Source of truth and release identity

Each published release has:

- a semantic version, for example `1.0.0`;
- a source commit identifier;
- a signed/checked release manifest;
- immutable CloudFormation template, Lambda package, and UI bundle locations;
- SHA-256 checksums;
- an SBOM and dependency-license report;
- a tested AWS region and Bedrock support matrix;
- release notes and upgrade compatibility statement.

The CloudFormation template must expose `ReleaseVersion` in its outputs and
apply it as a resource tag. Artifact keys and image references must be
version-addressed; published artifacts are never overwritten.

### 4.2 Support matrix

The exact Release 1 region/model matrix is not yet approved. It is a release
gate, not a deployment-time assumption.

Before publishing a release, the pipeline must test every claimed combination
for:

- CloudFormation resource availability;
- API Gateway, Cognito, Step Functions, EventBridge Scheduler, DynamoDB, S3,
  KMS, CloudWatch, and required Lambda runtime availability;
- selected Bedrock model or inference profile availability when AI reporting is
  enabled;
- Lambda artifact access from the target stack region;
- authenticated end-to-end scan completion.

Only combinations that pass are added to the release manifest and template
mapping. The console must surface the exact tested home region and report mode.

### 4.3 Installation lifecycle

```text
Choose release -> CloudFormation Quick Create -> select validated parameters
-> create authenticated console + scan backend -> run readiness check
-> sign in -> explicitly start first scan or create schedule
```

Installing the stack does not scan the account, send notifications, create an
Organization StackSet, or invoke Bedrock.

## 5. CloudFormation interface

The template uses parameter groups and labels. Defaults prioritize non-invasive
operation and customer data retention.

| Parameter | Required | Default | Contract |
|---|---:|---|---|
| `DeploymentPrefix` | Yes | — | 3-24 lowercase letters, numbers, and hyphens. It makes every physical resource name unique within an account/region. |
| `HomeRegion` | Implicit | Stack region | Must be in the release support matrix. No cross-region data store is created by default. |
| `ReportGenerationMode` | No | `DETERMINISTIC_ONLY` | `DETERMINISTIC_ONLY` or `BEDROCK_ENHANCED`. Bedrock is never invoked in the default mode. |
| `BedrockProfileId` | Conditional | Release-approved default | Required only for `BEDROCK_ENHANCED`; must be permitted for the home region by the release mapping. |
| `DefaultScanRegions` | Yes | — | Comma-separated commercial AWS region codes, pattern-validated and bounded by a maximum count. |
| `DefaultServices` | No | All supported services | Comma-separated allowlisted service identifiers. |
| `DefaultRegulations` | No | All released rules | Comma-separated allowlisted regulation/rule-pack identifiers. |
| `EnableScheduledScans` | No | `false` | Enables creation of a default schedule only with a valid expression. |
| `DefaultScheduleExpression` | Conditional | — | Validated EventBridge schedule expression; only evaluated when scheduling is enabled. |
| `KmsKeyMode` | No | `CREATE_CUSTOMER_MANAGED` | `CREATE_CUSTOMER_MANAGED` or `EXISTING_KEY_ARN`. |
| `ExistingKmsKeyArn` | Conditional | — | Required only for `EXISTING_KEY_ARN`; policy compatibility is validated. |
| `FindingsRetentionDays` | No | Product-approved safe default | Bounded retention for finding records and transient evidence. |
| `ReportRetentionDays` | No | Product-approved safe default | Bounded S3 lifecycle retention for generated reports. |
| `LogRetentionDays` | No | Product-approved safe default | Bounded CloudWatch Logs retention. |
| `BootstrapAdminEmail` | Yes | — | Email address for the initial Cognito administrator. It is not used for marketing or scan alerts. |
| `NotificationEmail` | No | — | Optional recipient for scan failure/critical-finding notification. Customer confirms the SNS subscription. |
| `DataRemovalPolicy` | No | `RETAIN` | `RETAIN` for production-safe deletion behavior; non-production delete behavior requires explicit acknowledgement. |
| `Environment` | No | `production` | Customer tag and lifecycle label: `development`, `test`, `staging`, or `production`. |
| `CostCenter` | No | — | Customer billing tag. |
| `Owner` | No | — | Customer operations tag. |

Release 1 does not expose `OrganizationMode`, VPC configuration, or external
identity-provider parameters. Those features are deliberately deferred until
their deployment and support contracts are implemented.

### 5.1 Template outputs

| Output | Meaning |
|---|---|
| `ConsoleUrl` | Customer console URL served through CloudFront. |
| `ApiUrl` | Authenticated API base URL; not a public unauthenticated service contract. |
| `ScannerRoleArn` | Read-only runtime role used for same-account discovery. |
| `RunsTableName` | Customer-owned scan run and schedule store. |
| `FindingsTableName` | Customer-owned findings and audit store. |
| `ReportsBucketName` | Private customer-owned report/evidence bucket. |
| `KmsKeyArn` | Customer key protecting product data. |
| `OperationsDashboardUrl` | CloudWatch dashboard for the deployment. |
| `ReadinessStatus` | Output of the non-mutating dependency/permission check. |
| `ReleaseVersion` | Exact installed product release. |
| `DataRemovalGuide` | Documentation location describing retained-data cleanup. |

## 6. Customer roles and authorization

| Role | Allowed actions | Disallowed actions |
|---|---|---|
| Administrator | Start/cancel scans, view/export reports, manage schedules, configure notifications, view operational status, and manage user group membership through approved identity administration. | Modify customer infrastructure, attach SCPs, alter scanner IAM policies, or access other deployments. |
| Auditor | View scan status, findings, evidence metadata, reports, rule versions, and remediation guidance. | Start/cancel scans, manage schedules/settings, change users, or access other deployments. |

The browser authenticates through Cognito with authorization-code flow and PKCE.
API Gateway validates JWTs. The application verifies authorization again before
every operation. A valid user token does not authorize access outside its
deployment/account scope.

No deployed user interface collects or stores AWS access keys, AWS profiles,
secret keys, or a customer's Bedrock credentials.

## 7. Scan contract

### 7.1 Request

An administrator starts a scan through `POST /v1/scans` using this logical
payload:

```json
{
  "idempotencyKey": "client-generated-uuid",
  "scanRegions": ["eu-west-1", "eu-central-1"],
  "services": ["s3", "rds", "dynamodb"],
  "regulations": ["gdpr"],
  "reportGenerationMode": "DETERMINISTIC_ONLY"
}
```

The API rejects:

- unrecognized regions, services, regulations, or report modes;
- a region outside the published release support boundary;
- duplicate requests with a different payload under the same idempotency key;
- request sizes or target counts above product limits;
- administrator-only requests from auditor identities;
- arbitrary account IDs in Release 1.

### 7.2 Response and lifecycle

The API returns `202 Accepted` with `scanRunId`, `status=QUEUED`, and a
correlation ID. It does not wait for discovery or report generation.

The valid statuses are:

`QUEUED`, `VALIDATING`, `RUNNING`, `EVALUATING`, `REPORTING`, `COMPLETE`,
`PARTIAL`, `FAILED`, `CANCEL_REQUESTED`, and `CANCELLED`.

`PARTIAL` is a valid useful result only when the result prominently identifies
unscanned scope and coverage gaps, including access-denied, unsupported region,
and unavailable-service failures.

### 7.3 Results

Every finding includes:

- finding ID and scan-run ID;
- account ID, region, service, resource ARN/name;
- rule ID and rule-pack version;
- evidence reference/digest and collection timestamp;
- severity;
- data-category/legal-basis assumptions and uncertainty;
- explanation, remediation guidance, and remediation status.

A scan cannot be presented as “clean” when selected resources/regions could not
be scanned. The console shows coverage before it shows a compliance summary.

## 8. Data handling contract

### 8.1 Customer data location

The following data remains in the customer's account and home region unless the
customer explicitly enables a documented exception:

- scan configuration and run status;
- resource metadata and evidence;
- findings, remediation state, and audit events;
- reports and exports;
- application logs and metrics;
- encryption keys and IAM identities.

The product does not copy reports or findings to vendor infrastructure.

### 8.2 Bedrock data use

`DETERMINISTIC_ONLY` is the default. In this mode, no finding or evidence is
sent to Bedrock.

When an administrator selects `BEDROCK_ENHANCED`, only the report worker can
invoke the approved model/profile. The worker sends a constrained, documented
set of structured finding fields and evidence summaries. It must:

- minimize resource identifiers and redact configured sensitive tag values;
- treat all source values as untrusted quoted data;
- use a versioned prompt template with no infrastructure tools;
- record model/profile, model region, prompt-template version, and generation
  timestamp in the report metadata;
- fall back to a deterministic report if the invocation fails.

The release guide identifies which AWS-managed service boundary is used for the
selected Bedrock model/profile. The customer must be able to determine whether
that model mode is acceptable under its data-residency policy before enabling it.

### 8.3 Encryption, retention, and deletion

- Findings, schedules, runs, reports, evidence, and application logs use the
  selected customer KMS key where supported.
- DynamoDB point-in-time recovery is enabled for persistent product tables.
- Report/evidence S3 has block-public-access, bucket-owner-enforced ownership,
  versioning, encryption, and lifecycle expiration.
- Retention is configurable only within documented safe bounds.
- Stack deletion defaults to retaining customer data. The outputs and
  decommissioning guide identify all retained resources and approved cleanup
  steps.

## 9. IAM and read-only guarantee

Release 1 scanner roles use only the service discovery permissions required by
the supported scanners. They do not include write, delete, policy attachment,
SCP management, key deletion, data-plane object reads, or arbitrary role
assumption permissions.

Some discovery APIs require `Resource: "*"` because AWS does not provide
resource-level authorization for them. Every such permission is documented in
the installer policy with its purpose and affected service.

The installer policy is separate from runtime roles:

- **Installer policy:** only the CloudFormation and resource-creation
  permissions necessary for this stack.
- **Runtime roles:** least-privilege permissions needed during normal use.
- **No normal installation path:** `AdministratorAccess`.

## 10. Scheduling and notifications

- Scheduled scans are disabled by default.
- An administrator creates, changes, enables, pauses, or deletes schedules
  through authenticated APIs and console controls.
- Each schedule stores an immutable validated scan request.
- EventBridge Scheduler starts the named Step Functions workflow; it never
  invokes raw worker Lambda functions.
- Failure or critical-finding notifications are opt-in and concise. Full
  findings are available only in the authenticated console/report.
- Every scheduled run has the same audit and retention behavior as an on-demand
  run.

## 11. Availability and failure behavior

The product reports operational truth over optimistic status.

- Transient AWS errors use bounded exponential backoff.
- Access denied, malformed input, unsupported region, and rule defects are
  reported as coverage gaps or failures; they are not blindly retried.
- Each worker uses an idempotency key derived from scan run, account, region,
  and service. Retries cannot duplicate findings or notifications.
- Worker failures do not erase findings from successful scope elements.
- Bedrock failure cannot erase deterministic findings or mark a run failed when
  deterministic reporting is sufficient.
- API responses include correlation IDs and redact sensitive internal details.
- CloudWatch alarms cover workflow timeout/failure, Lambda errors/throttles,
  API errors, scheduler delivery failure, report-generation failure, and data
  store throttling.

## 12. Customer experience requirements

The console provides:

1. a first-run readiness view showing release version, supported mode, model
   mode, scan limits, and prerequisites;
2. a scan form containing only supported regions, regulations, and services;
3. live asynchronous scan status and explicit coverage gaps;
4. server-side filtered/paginated findings;
5. evidence metadata, rule version, assumptions, and remediation guidance;
6. protected report view/download;
7. administrator-only schedule, notification, and retention views;
8. operational status and CloudWatch dashboard links.

The console must not:

- contain a raw free-form orchestration prompt in Release 1;
- expose direct Lambda invocation as an end-user operation;
- represent a rule result as legal advice;
- offer a “fix automatically” action;
- preserve configuration only in browser/Streamlit session memory.

## 13. Upgrade and decommissioning contract

### Upgrade

- Every release declares compatible prior versions and required migrations.
- Customers review a CloudFormation change set before update.
- Schema migrations are explicit, observable, retry-safe, and testable from the
  oldest supported release.
- A failed update must roll back runtime infrastructure without deleting
  retained evidence, reports, findings, or audit records.
- The post-update check validates authentication, API readiness, workflow
  startup, and persisted-data access.

### Decommissioning

- `DataRemovalPolicy=RETAIN` is the normal production default.
- The stack output provides an inventory of retained buckets, tables, key
  aliases, and logs.
- The decommissioning guide describes the customer-authorized sequence to
  export, expire, or delete retained data.
- Product automation must not silently delete evidence or reports during a
  production stack deletion.

## 14. Acceptance criteria for this contract

Phase 0 can close after:

1. product, platform, and security owners approve this contract and
   `PRODUCT_ARCHITECTURE.md`;
2. the Release 1 support matrix is defined from actual deployment tests;
3. the installer policy and all runtime IAM boundaries are reviewed;
4. the exact Bedrock field-level data-use statement is approved;
5. product limits for account scope, region count, concurrency, report size,
   and retention are specified;
6. the CloudFormation parameter/output contract is frozen for Release 1;
7. deterministic-only reporting is accepted as the default customer experience;
8. Release 1’s non-goals are accepted by product stakeholders.

## 15. Decision log

| Decision | Status | Owner/action before Phase 0 closes |
|---|---|---|
| CloudFormation is the first customer deployment method. | Proposed baseline | Product/platform approval. |
| Terraform follows CloudFormation contract stabilization. | Proposed baseline | Product/platform approval. |
| Static UI + CloudFront replaces production Streamlit/App Runner. | Proposed baseline | Platform/UI approval. |
| Cognito local users are the initial identity mode. | Proposed baseline | Security approval. |
| Single-account scanning is the initial release scope. | Proposed baseline | Product approval. |
| Bedrock is optional and deterministic-only is default. | Proposed baseline | Product/security data-use approval. |
| Customer-managed KMS key is the initial default. | Proposed baseline | Security/platform approval. |
| Scheduled scans are disabled by default. | Proposed baseline | Product approval. |
| Organizations, federation, and private-VPC mode are deferred. | Proposed baseline | Product roadmap approval. |
