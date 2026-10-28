# Deployment Guide

Sovereign Shield is installed from a versioned CloudFormation release. Customers
need no CDK, Docker, source code, or uploaded files. The developer sections
below cover deploying from source and publishing releases.

---

## Customer installation (published release)

### 1. Choose the template

Each release (`release/<version>/RELEASE_NOTES.md`) has Quick Create links for
every supported region: **eu-central-1, eu-west-1, us-east-1, us-west-2**.
Launching in another region fails immediately with a clear message.

| Template | Data on stack deletion | Use |
|---|---|---|
| `sovereign-shield.yaml` | **Retained**: tables, reports, key, user pool, and logs survive | Production |
| `sovereign-shield-nonprod.yaml` | **Deleted** with the stack; requires `AcknowledgeDataDeletion` = `DELETE_ALL_SOVEREIGN_SHIELD_DATA_WITH_THE_STACK` | Evaluation and test |

CloudFormation does not allow a parameter to choose `DeletionPolicy`, so data
removal is a choice of template rather than a parameter.

### 2. Launch parameters

| Group | Parameter | Default | Notes |
|---|---|---|---|
| Deployment | `DeploymentPrefix` | `sovereign-shield` | 3-24 lowercase letters, numbers, hyphens. Names the sign-in domain, key alias, schedule group, and dashboard; use a different prefix per installation in the same region. Must not contain `aws`, `amazon`, or `cognito`. |
| Organization | `OrganizationMode` | `SINGLE_ACCOUNT` | `AWS_ORGANIZATIONS` scans an organization's OUs; see [AWS Organizations scanning](#aws-organizations-scanning) for the related parameters. |
| Access | `IdentityProviderMode` | `COGNITO_LOCAL` | Only value in this release. |
| Access | `AdministratorEmail` | empty | Bootstrap administrator; receives an invitation with the console link. |
| Access | `NotificationEmail` | empty | Receives scan-failure, critical-finding, and alarm emails (confirm the SNS subscription). |
| Scanning | `DefaultScanRegions` | empty | Preselected in the console and used by the readiness check. Empty means the stack region. |
| Scanning | `ScanConcurrency` | `10` | 1-40 units in parallel per scan. |
| Scanning | `EnableScheduledScans` | `false` | When `false`, schedules cannot be created and existing schedules do not start scans. |
| Data protection | `KmsKeyMode` | `CREATE_CUSTOMER_MANAGED` | Or `EXISTING_KEY_ARN` with `ExistingKmsKeyArn`. |
| Data protection | `ExistingKmsKeyArn` | empty | Key in the stack region. Its key policy must allow `logs.<region>.amazonaws.com` (with the `kms:EncryptionContext:aws:logs:arn` condition) and `cloudwatch.amazonaws.com` (`kms:Decrypt`, `kms:GenerateDataKey*`). |
| Data protection | `FindingsRetentionDays` | `0` | Days to keep completed runs, evidence, and findings (DynamoDB TTL). `0` keeps them indefinitely. |
| Data protection | `ReportRetentionDays` | `365` | 30-3650. |
| Data protection | `LogRetentionDays` | `90` | 30, 90, 180, or 365. |
| Tags | `Environment`, `Owner`, `CostCenter` | `unspecified` | Applied to every taggable resource. |

The stack creates IAM roles, so acknowledge `CAPABILITY_IAM`. The deploying
principal needs the permissions in `installer-policy.json` (replace
`${AccountId}`, `${StackName}`, `${StackNameLowercase}`, `${DeploymentPrefix}`,
and `${ArtifactBucketPrefix}`).

### 3. From the CLI

```bash
aws cloudformation create-stack --region eu-west-1 --stack-name SovereignShield \
  --template-url https://<artifact-bucket-prefix>-eu-west-1.s3.eu-west-1.amazonaws.com/releases/<version>/sovereign-shield.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters ParameterKey=AdministratorEmail,ParameterValue=admin@example.com
```

### 4. After deployment

1. Run the `PostDeployValidationCommand` output. It is read-only: it describes
   the stack's resources and dry-runs the scanner's read permissions in each
   default scan region. `"ready": true` means every check passed; warnings mark
   regions that are not enabled for the account.
2. Open `ConsoleUrl` and sign in with the invitation email.
3. No scan starts on its own. Start one from **New scan**.

### Upgrading

Create a change set from the new version's template URL with the same
parameters, review it, then execute it. Do not use "Use existing template" with
a new release.

---

## Publishing a release (vendor)

```bash
pip install -e ".[dev,cdk]" cfn-lint
# Builds the Lambda package and console, synthesizes both templates (no CDK
# bootstrap references allowed), runs cfn-lint, and writes the manifest,
# checksums, SBOM, installer policy, and Quick Create release notes.
python scripts/build_release.py --version 1.0.1 --bucket-prefix sovereign-shield-releases-<account>

# Creates or updates <prefix>-<region> buckets (versioned, Block Public Access,
# TLS-only, read on releases/* for allowlisted accounts only) and uploads with
# S3-verified SHA-256. Released keys are immutable: republishing identical
# content is a no-op, and different content for a released key is refused.
python scripts/publish_release.py --version 1.0.1 \
  --bucket-prefix sovereign-shield-releases-<account> --reader-accounts <customer-account>,...
```

A fix to a published release is always a new version.

---

## Developer deployment (from source)

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.10+ | [python.org](https://www.python.org/downloads/) |
| Node.js | 20+ | [nodejs.org](https://nodejs.org/) (console build and CDK) |
| AWS CDK | 2.x | `npm install -g aws-cdk` |
| AWS CLI | 2.x | [AWS CLI install](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |

The deployed backend is deterministic: discovery, policy evaluation, and
reporting do not call Bedrock, so no model access is required. (Bedrock is
only used by the local agent experience, `sovereign-shield --interactive`.)

```bash
pip install -e ".[dev,cdk]"
python scripts/build_lambda.py                      # dist/lambda_package.zip (reproducible)
(cd console && npm ci && npm test && npm run build)  # console/dist
cd cdk && cdk bootstrap                              # first time per account/region

cdk deploy -c dataRemovalPolicy=DESTROY \
  --parameters AdministratorEmail=admin@example.com \
  --parameters NotificationEmail=ops@example.com
```

Launch values are the CloudFormation parameters above. Pass them on every
deploy: an omitted `AdministratorEmail` removes the bootstrap user.

### Development-only context

| Key | Default | Notes |
|---|---|---|
| `dataRemovalPolicy` | `RETAIN` | `DESTROY` matches the non-production template. |
| `allowedOrigins` | none | Extra CORS origins. `*` is rejected. |
| `consoleDevOrigins` | none | Extra sign-in callback origins, for example `http://localhost:5173`. |
| `releaseVersion` | `development` | Version label shown in the console. |

### What gets created

| Resource | Purpose |
|---|---|
| KMS key (rotation enabled) | Encrypts tables, reports, log groups, and the alert topic |
| DynamoDB `ScanRunsTableV1` | Runs, evidence, coverage gaps, schedules (`pk`/`sk`, PITR) |
| DynamoDB `FindingsTableV1` | Findings (`pk`/`sk`, PITR) |
| S3 reports bucket | Private, versioned, KMS-encrypted, TLS-only, lifecycle-expired |
| Lambda `ApiFunction` | v1 API: validate, record, start workflow, manage schedules |
| Lambda `WorkflowFunction` | Admits scheduled runs, executes scans, records failures |
| Step Functions (Standard) | `[AdmitScheduledRun] -> PrepareRun -> ScanWorkItems (Map, one Lambda per account/region/service) -> FinalizeRun`; a crashed unit becomes a coverage gap, any other step error goes to `MarkRunFailed` |
| Lambda `DeploymentFunction` / `ReadinessFunction` | Publishes the console bundle at deploy time; non-mutating post-deploy readiness check |
| HTTP API + Cognito JWT authorizer | All twelve `/v1/*` routes require a Cognito token; throttled at 20 rps / 40 burst; CORS allows only the console origin (plus `consoleDevOrigins` / `allowedOrigins`) |
| Web console | React app in a private S3 bucket behind CloudFront (origin access control), with strict CSP, HSTS, and `X-Frame-Options: DENY`. Output `ConsoleUrl` |
| Cognito hosted sign-in | Domain `<prefix>-<account>`; console client uses authorization code + PKCE with only the console callback registered |
| DynamoDB `AuditTableV1` | Append-only audit records (the API role has `PutItem`/`Query` only), PITR, KMS |
| Cognito user pool | `SovereignShieldAdministrators` and `SovereignShieldAuditors` groups; no self sign-up |
| EventBridge Scheduler group | Customer schedules created through `POST /v1/schedules`; no schedule exists by default |
| SNS topic, 9 alarms, dashboard | Workflow failures/timeouts, Lambda errors/throttles, API 5xx, scheduler delivery, DynamoDB throttles |

The prototype resources (REST `/scan` API, App Runner Streamlit service,
static daily EventBridge rule, `sovereign-shield-violations` and
`sovereign-shield-scan-results` tables, and fixed-name reports bucket) are no
longer part of the stack. On upgrade from the prototype, the retained tables
and bucket are orphaned rather than deleted; remove them manually once you
no longer need them.

---

## Post-Deployment Verification

### Automated checks

Both scripts take `--outputs`, `--stack`, `--region`, and `--profile`, so they run
against a development stack or a release installation.

```bash
# Authenticated end-to-end smoke test (14 checks). Creates and deletes
# temporary Cognito users; runs one bounded read-only scan; creates, pauses,
# and deletes one schedule.
python scripts/smoke_test.py --outputs dist/stack-outputs.json --profile <profile> --region <region>

# State-machine failure paths (8 checks): scheduled admission, rejected
# schedules, terminal-outcome preservation, report encryption.
python scripts/failure_checks.py
```

Pass `--outputs-file ../dist/stack-outputs.json` to `cdk deploy` to produce
the outputs file. The manual steps below show what the scripts automate.

### Sign in to the console

Open the `ConsoleUrl` output. The bootstrap administrator receives an
invitation email with a temporary password and the console link. Add more
users in the Cognito console (or with `aws cognito-idp admin-create-user`)
and put them in `SovereignShieldAdministrators` or `SovereignShieldAuditors`.
Users outside both groups can sign in but see no data.

### Sign in from the CLI and get a token

```bash
POOL_ID=<UserPoolId output>
CLIENT_ID=<UserPoolClientId output>
API_URL=<ApiUrl output>
ADMIN=admin@example.com

# Replace the emailed temporary password (requires IAM access to the pool).
aws cognito-idp admin-set-user-password --user-pool-id "$POOL_ID"   --username "$ADMIN" --password '<new-password>' --permanent

TOKEN=$(aws cognito-idp admin-initiate-auth --user-pool-id "$POOL_ID" --client-id "$CLIENT_ID"   --auth-flow ADMIN_USER_PASSWORD_AUTH   --auth-parameters "USERNAME=$ADMIN,PASSWORD=<new-password>"   --query AuthenticationResult.AccessToken --output text)
```

Add auditors with `aws cognito-idp admin-create-user` and
`admin-add-user-to-group --group-name SovereignShieldAuditors`.

### Start and follow a scan

```bash
curl -s -X POST "$API_URL/v1/scans"   -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json"   -d '{"idempotencyKey":"smoke-001","scanRegions":["eu-central-1"],"services":["s3"],
       "regulations":["gdpr"],"dataCategories":["personal_data"],
       "reportGenerationMode":"deterministic_only"}'
# -> 202 {"scanRunId": "...", "status": "queued", ...}

curl -s "$API_URL/v1/scans/<scanRunId>" -H "Authorization: Bearer $TOKEN"
curl -s "$API_URL/v1/scans/<scanRunId>/findings?limit=50" -H "Authorization: Bearer $TOKEN"
curl -s "$API_URL/v1/scans/<scanRunId>/report" -H "Authorization: Bearer $TOKEN"
```

Requests without a valid token get `401` from API Gateway. Authenticated
users outside the product groups get `403` from the function.

### Check the workflow

```bash
aws stepfunctions list-executions --state-machine-arn <ScanStateMachineArn output> --max-results 5
```

Failed executions also mark the scan run `failed` with a sanitized error
code, so `GET /v1/scans/{id}` never stays in `running` after a worker
timeout. Operations status is available from the `OperationsDashboardUrl`
output.

---

## AWS Organizations scanning

One installation can scan many accounts. The central stack deploys a read-only
member role (`sovereign-shield-member-role.yaml`) into every account under the
selected OUs through a service-managed StackSet, keeps it deployed as accounts
join, and records each account's onboarding status.

> **Verification status:** organization mode is unit- and synthesis-tested,
> including StackSet configuration, trust, eligibility, onboarding, and
> multi-account scans. It has not yet been deployed against a live
> organization; see `plan.md` (Phase 5).

### Prerequisites

1. Deploy in the **management account** (`StackSetCallAs` = `SELF`) or an
   account registered as a **CloudFormation StackSets delegated
   administrator** (`DELEGATED_ADMIN`).
2. **Trusted access for StackSets** is enabled for the organization
   (CloudFormation console > StackSets > Enable trusted access).
3. The management account itself is not covered by service-managed StackSets;
   it is scanned only if it is the deployment account.

### Parameters

| Parameter | Notes |
|---|---|
| `OrganizationMode` | `AWS_ORGANIZATIONS` |
| `OrganizationId` | For example `o-a1b2c3d4e5`. |
| `TargetOrganizationalUnitIds` | Comma-separated OU or root IDs; child OUs are included. |
| `AcknowledgeOrganizationPermissions` | `I_ACKNOWLEDGE_ORGANIZATION_WIDE_READ_ONLY_ACCESS` |
| `StackSetCallAs` | `SELF` or `DELEGATED_ADMIN`. |
| `AccountAllowlist` | Optional. If set, only these accounts are scanned (roles are still deployed to the OUs). |
| `AccountDenylist` | Optional. These accounts never receive the role and are never scanned. |
| `ExclusionTagKey` | Default `sovereign-shield:exclude`. An account tagged with this key and value `true` in Organizations is never scanned. |
| `MemberRoleName` | Default `SovereignShieldScanRole`. |
| `MaxAccountsPerScan` | 1-200, default 25. Scans are also limited to 1,000 account/region/service units. |

The stack rejects organization mode unless `OrganizationId`,
`TargetOrganizationalUnitIds`, and the acknowledgement are all provided.

### Trust model

- The member role trusts only the exact ARNs of the central scan-worker and
  onboarding roles. It does not trust the central account as a whole.
- Every `AssumeRole` call sends this installation's external ID, which is the
  `MemberRoleExternalId` stack output, derived from the stack's unique ID.
  The trust policy also requires `aws:PrincipalOrgID`.
- The central roles may assume only `role/<MemberRoleName>`, and only when
  `aws:ResourceOrgID` is the configured organization and `aws:ResourceOrgPaths`
  lies under a selected OU.
- The member role grants the same read-only List and Describe actions as the
  central scanner, and nothing else.

### Onboarding status

The onboarding sync runs every 6 hours, and on demand from **Accounts > Refresh
status** (administrators). It reads Organizations membership, the StackSet's
instance status, and account tags, then test-assumes each deployed role:

| Status | Meaning |
|---|---|
| Onboarded | Role deployed and assumable; the account can be scanned. |
| Pending | Role not yet deployed, or deployment in progress. |
| Role deployment failed | The StackSet instance failed; the detail shows the reason. |
| Role unreachable | Role deployed but `AssumeRole` failed (trust, SCP, or external ID mismatch). |
| Excluded | Denylist, exclusion tag, allowlist, or administrator exclusion (in that precedence). Administrators can only lift their own exclusions. |
| Suspended / Out of scope | Account suspended, or no longer under the selected OUs. |

Eligibility is checked again when each work unit starts. An account excluded
mid-scan is skipped and reported as a coverage gap.

### Self-managed onboarding

To roll out the role with your own tooling instead, deploy
`sovereign-shield-member-role.yaml` in each account with these parameters:
- `CentralPrincipalArns`: the central `ScannerRoleArn` and the onboarding role ARN;
- `ExternalId`: the `MemberRoleExternalId` stack output;
- `OrganizationId`;
- `RoleName`.

---

## Running Locally (no deployment needed)

You can run Sovereign Shield directly from your machine without deploying to AWS. It just needs AWS credentials with:
- Bedrock InvokeModel access
- Read-only access to the AWS services being scanned

```bash
# Install
pip install -e .

# Scan current account (CLI)
sovereign-shield --regions us-east-1,eu-west-1 --regulations gdpr

# Interactive mode
sovereign-shield --regions eu-central-1 --regulations gdpr --interactive

# Run offline demos (no AWS credentials needed)
python demos/demo_offline_detection.py
python demos/demo_scp_generation.py
```

### Streamlit UI (local)

```bash
# Install UI dependencies
pip install -e ".[ui]"

# Run the web UI
streamlit run ui/app.py

# Or via Docker
docker build -t sovereign-shield-ui .
docker run -p 8501:8501 \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -e AWS_DEFAULT_REGION=us-east-1 \
  sovereign-shield-ui
```

In local mode the UI calls sovereign_shield tools directly (no Lambda/API Gateway needed).

---

## Configuration

### Deployed function environment

CDK sets these from stack resources. Do not edit them in the console.

| Function | Variables |
|---|---|
| `ApiFunction` | `SCAN_RUNS_TABLE`, `FINDINGS_TABLE`, `SCAN_STATE_MACHINE_ARN`, `SCHEDULE_GROUP_NAME`, `SCHEDULER_ROLE_ARN`, `DEPLOYMENT_ACCOUNT_ID` |
| `WorkflowFunction` | `SCAN_RUNS_TABLE`, `FINDINGS_TABLE`, `REPORTS_BUCKET`, `REPORTS_KMS_KEY_ID`, `NOTIFICATION_TOPIC_ARN`, `DEPLOYMENT_ACCOUNT_ID` |

For local CLI and Streamlit use, `BEDROCK_MODEL_ID` (default
`us.anthropic.claude-sonnet-4-20250514-v1:0`) and `BEDROCK_REGION` still
configure the agent experience.

### Scheduled scans

No schedule exists after deployment. An administrator creates one through the
API. Expressions must be `rate(...)` no more frequent than hourly, or a
six-field `cron(...)`:

```bash
curl -s -X POST "$API_URL/v1/schedules"   -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json"   -d '{"name":"weekly-eu","scheduleExpression":"cron(0 6 ? * MON *)",
       "scanRequest":{"scanRegions":["eu-central-1","eu-west-1"],"services":["s3","rds"],
                  "regulations":["gdpr"],"dataCategories":["personal_data"]}}'
```

Pause it with `PATCH /v1/schedules/{scheduleId}` and `{"enabled": false}`, or
remove it with `DELETE`. Each firing creates a normal scan run.

---

## Updating

```bash
git pull
python scripts/build_lambda.py
cd cdk
cdk diff    # Preview changes; logical IDs of data resources must not change
cdk deploy
```

---

## Teardown

```bash
cd cdk
cdk destroy
```

With the default `dataRemovalPolicy=RETAIN`, the KMS key, both DynamoDB
tables, the reports bucket, the Cognito user pool, and the log groups survive
`cdk destroy`, so customer findings are never deleted as a side effect.
Delete them manually after export if they are no longer required. Delete
schedules through the API first; the schedule group is removed with the stack.

Stacks deployed with `-c dataRemovalPolicy=DESTROY` remove all data with the
stack. Use this only for disposable test accounts.

---

## Troubleshooting

### "Runtime.ImportModuleError" / "No module named pydantic"

The functions were deployed without `dist/lambda_package.zip` (synthesis
prints a warning). Run `python scripts/build_lambda.py` and redeploy.

### Scan run is `partial` with a `worker_incomplete` coverage gap

One account/region/service unit exceeded its 15-minute limit or crashed. The
rest of the scan completed. Check the workflow function logs for that unit.
Very large single units (thousands of resources of one type in one region)
are the likely cause.

### Coverage gaps with `AccessDenied`

The workflow role grants only the read actions used by
`src/sovereign_shield/tools/aws_scanner.py`. A new scanner call must be added
to `_SCANNER_READ_ACTIONS` in the stack.

### Accounts show "Role unreachable"

The member role exists but cannot be assumed. Check that:
- the role's trust policy lists the current `ScannerRoleArn`, which changes if the central role is replaced;
- `ExternalId` matches the `MemberRoleExternalId` output;
- no SCP denies `sts:AssumeRole` for that role.

Then select **Refresh status**.

### CDK bootstrap errors

```bash
# Re-bootstrap with the correct account/region
cdk bootstrap aws://ACCOUNT_ID/REGION --force
```
