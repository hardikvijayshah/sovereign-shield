# Sovereign Shield: Where the Product's Own Data Lives

Sovereign Shield assesses where *your* data lives. This document states,
for the deployed product itself, what data it creates or receives, where it is
stored or processed, and what leaves the deployment (home) region. It reflects
release 1.1.0 behavior, and each statement is tied to the code that enforces it.

## Summary

- All product data (scan runs, evidence, findings, reports, audit records,
  schedules, account registry, logs, and metrics) is stored in **the home
  region**, encrypted with the stack's KMS key. Exceptions are listed below.
- Scans make **read-only AWS API calls in each region you select**. The
  configuration metadata they return (resource names, ARNs, replication
  targets, encryption flags) is **copied into the home region**. Choose the
  home region with this in mind: scanning `us-east-1` from `eu-central-1`
  stores `us-east-1` resource metadata in `eu-central-1`.
- Sovereign Shield never reads object contents, table items, messages, or any
  other customer payload data. It reads configuration only (`SCANNER_READ_ACTIONS`).
- No Amazon Bedrock or other model is called in the deployed product.

## Data inventory

| Data | Contents | Stored in | Encryption | Retention |
|---|---|---|---|---|
| Scan runs, evidence, coverage gaps | Run request, resource names/ARNs/regions, encryption and replication settings | DynamoDB `ScanRunsTableV1`, home region | Stack KMS key | `FindingsRetentionDays` (0 = keep) |
| Findings | Rule, severity, resource ARN/name, evidence IDs | DynamoDB `FindingsTableV1`, home region | Stack KMS key | `FindingsRetentionDays` |
| Per-unit scan results | The same evidence, in transit between workflow steps | S3 `work/` prefix, home region | Stack KMS key | Deleted after 7 days |
| Reports | Markdown summary of findings and evidence | S3 `reports/`, home region | Stack KMS key | `ReportRetentionDays` |
| Audit records | Actor subject ID, action, target ID, outcome | DynamoDB `AuditTableV1`, home region | Stack KMS key | Kept; append-only |
| Account registry (Organizations mode) | Account ID, name, OU, onboarding status | DynamoDB runs table, home region | Stack KMS key | Until removed |
| Console users | Email address, group membership, password hash, MFA | Cognito user pool, home region | Cognito-managed | Until deleted |
| Logs | Run IDs, account IDs, regions, services, route names, error *codes* | CloudWatch Logs, home region | Stack KMS key | `LogRetentionDays` |
| Metrics and alarms | Counts by status (no resource names or ARNs) | CloudWatch, home region | AWS-managed | CloudWatch defaults |
| Traces | Function and state-machine timings | AWS X-Ray, home region | AWS-managed | 30 days (X-Ray default) |

Coverage-gap messages keep only the AWS error code and operation (for example,
`AccessDenied calling GetBucketReplication`). AWS error text, which can name
principals and resources, and validation input values are withheld
(`redact_error_text` and `redact_exception` in `services/scan_engine.py`).

## What leaves the home region

| Flow | Destination | What is sent | Why |
|---|---|---|---|
| Discovery API calls | Each selected scan region | Read-only `List`/`Describe`/`Get` requests | Assess resources where they are |
| CloudFront and Lambda@Edge discovery | `us-east-1` endpoints | Read-only list calls | These are global services served from `us-east-1` |
| Organizations reads (Organizations mode) | AWS Organizations (global service, `us-east-1`) | List accounts, OUs, and tags | Organizations has no regional endpoint |
| Console static files | Amazon CloudFront edge locations (global) | The console app bundle and `config.json` (API URL, Cognito domain, client ID) | No customer or scan data is served through CloudFront; API calls go directly to the regional API |
| Email notifications | Email recipients via Amazon SNS | Run ID, status, and counts of critical findings and coverage gaps | No resource names, ARNs, or findings are included (`ScanOutcomeNotifier`) |
| Budget alerts (optional) | Email via AWS Budgets | Spend versus budget | Only when `MonthlyBudgetUsd` is set |
| Cross-account credentials | AWS STS **regional** endpoint in the home region | AssumeRole requests | STS is pinned to the home region (`_regional_sts_endpoint`) |
| Report downloads | The user's browser | The report, via a 5-minute pre-signed URL to the home-region bucket | Download is authorized and audited (`report.view`) |

In Organizations mode, metadata from every scanned member account is copied
into the central account's home region. The member role cannot read data
contents. It holds the same read-only actions as the central scanner.

## Recommendations for regulated customers

1. Deploy in the jurisdiction where assessment metadata may lawfully reside
   (for example, `eu-central-1` or `eu-west-1` for EU organizations).
2. Scope `DefaultScanRegions`, `TargetOrganizationalUnitIds`, and the account
   allowlist to the estate you are entitled to assess.
3. Set `FindingsRetentionDays` and `ReportRetentionDays` to your record-keeping
   policy.
4. Use `KmsKeyMode=EXISTING_KEY_ARN` if your key management policy requires a
   centrally managed key.
5. Treat findings as potential issues. Sovereign Shield does not classify your
   data and is not legal advice.
