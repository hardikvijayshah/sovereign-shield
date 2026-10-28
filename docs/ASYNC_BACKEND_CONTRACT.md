# Asynchronous Scan Backend Contract

## Purpose

This document defines the Phase 2 boundary between the customer-facing API,
the durable run store, Step Functions, and bounded discovery workers. It
replaces the former long-running `action=scan` request path for all new
customer-facing use cases.

## Request submission

`POST /v1/scans` accepts the documented `ScanRequest` JSON fields:

```json
{
  "idempotencyKey": "customer-request-001",
  "scanRegions": ["eu-central-1", "eu-west-1"],
  "services": ["s3", "cloudfront"],
  "regulations": ["gdpr"],
  "dataCategories": ["personal_data"],
  "reportGenerationMode": "deterministic_only"
}
```

The API validates the request and returns `202 Accepted` immediately:

```json
{
  "scanRunId": "uuid",
  "status": "queued",
  "correlationId": "uuid",
  "created": true
}
```

The API never performs discovery, invokes Bedrock, or returns raw AWS API
responses in this request. Replaying the same idempotency key for the same
customer deployment and requester returns the existing run with
`created=false`. Reusing it for a changed payload is rejected.

## Lifecycle

```text
QUEUED -> VALIDATING -> RUNNING -> EVALUATING -> COMPLETE | PARTIAL
                    \-> CANCEL_REQUESTED -> CANCELLED
                    \-> FAILED
```

`REPORTING` is reserved for the Phase 2 report worker. It runs only after
deterministic evidence and findings have been persisted. `COMPLETE`,
`PARTIAL`, `FAILED`, and `CANCELLED` are terminal.

## Workflow input and work items

The coordinator starts Step Functions with the minimal input:

```json
{"scanRunId":"uuid","correlationId":"uuid"}
```

The workflow loads the accepted run from DynamoDB. It derives one
`ScanWorkItem` for every selected account/region/service, except global
services (CloudFront and Lambda@Edge), which run once per account. A work item
contains only:

```json
{
  "scanRunId": "uuid",
  "accountId": "customer-account-id",
  "region": "eu-central-1",
  "service": "s3"
}
```

Each worker may use only the selected service's read-only discovery calls.
Every returned evidence record and finding is idempotent within a run.

## Read endpoints

- `GET /v1/scans/{scanRunId}` returns status, bounded progress counters,
  timestamps, correlation ID, report metadata, and a redacted error summary.
- `GET /v1/scans/{scanRunId}/findings?limit=1..100&cursor=<opaque>` returns
  a server-side page of stored findings.
- `POST /v1/scans/{scanRunId}/cancel` records `CANCEL_REQUESTED`. A worker
  completes its current AWS call then safely terminates before the next unit.
- `GET /v1/scans/{scanRunId}/report` returns report metadata and a
  pre-signed download link valid for 5 minutes that forces download as an
  attachment. The link covers one `reports/` object; it is never a public or
  bucket URL. Each link issued is audited (`report.view`).
- `GET /v1/scans?limit&cursor` and `GET /v1/schedules?limit&cursor` list
  newest first through the runs table's sparse `by-entity-created` index.
- `GET /v1/scans/{scanRunId}/findings` accepts `severity`, `ruleId`,
  `region`, `service`, and `findingState` filters. Filters apply after each
  page is read, so a page may be short (even empty) with a `nextCursor`.
  Unknown parameters are rejected. Each finding carries deterministic,
  read-only `guidance` for its `category`.
- `GET /v1/configuration` returns supported scan choices, the deployment's
  release and rule-pack versions, and the caller's roles and allowed actions.
  Administrator settings are included only for administrators.
- `GET /v1/accounts` (administrators and auditors) lists every account and
  its onboarding status. In single-account mode it lists only the deployment
  account.
- `POST /v1/accounts/sync` (administrators) starts the onboarding sync in the
  background and returns `202`.
- `PATCH /v1/accounts/{accountId}` (administrators) with
  `{"excluded": bool, "note": "..."}` sets or lifts an administrator
  exclusion. Exclusions from the denylist, exclusion tag, or allowlist cannot
  be lifted here (`409`). Both mutations are audited.
- `POST /v1/scans` and schedules accept `accountIds`. When empty, the run
  scans the deployment account (single-account mode) or every onboarded,
  non-excluded account (organization mode). Requested accounts must be
  scannable, a run may target at most `MaxAccountsPerScan` accounts, and a run
  may need at most 1,000 account x region x service units; otherwise the
  request is rejected with `400`. The resolved accounts are frozen as
  `targetAccountIds`. Scheduled runs re-resolve their accounts at every firing,
  and eligibility is checked again when each unit starts.
- Findings accept an `accountId` filter.
- `GET /v1/audit-events?month=YYYY-MM&limit&cursor` (administrators only)
  returns audit records newest first: scan starts and cancellations, schedule
  changes, report links issued, and denied or rejected attempts. The API role
  can only append to and read the audit table. An audit write failure is
  logged (`AUDIT_WRITE_FAILED`) but never fails the user's request.

The deterministic report worker writes a reproducible Markdown report after
findings have been persisted. If an enhanced report was requested, this
initial implementation writes the deterministic fallback and sets
`enrichment_status=not_available_fallback`; no data is sent to Bedrock.

## Deployment configuration

`cdk/stacks/sovereign_shield_stack.py` provisions and wires every value below;
the functions fail closed if one is missing.

- API function: `SCAN_RUNS_TABLE`, `FINDINGS_TABLE`, `SCAN_STATE_MACHINE_ARN`,
  `SCHEDULE_GROUP_NAME`, `SCHEDULER_ROLE_ARN`, `DEPLOYMENT_ACCOUNT_ID`
- Workflow function: `SCAN_RUNS_TABLE`, `FINDINGS_TABLE`, `REPORTS_BUCKET`,
  `REPORTS_KMS_KEY_ID`, `NOTIFICATION_TOPIC_ARN`, `DEPLOYMENT_ACCOUNT_ID`

Every route is protected by a Cognito JWT authorizer at API Gateway, and the
function repeats the group checks below. The scanner uses the function's own
credentials for `DEPLOYMENT_ACCOUNT_ID` and assumes the member role only for
other accounts. The workflow role has no `sts:AssumeRole` permission until
Phase 5 onboarding.

## State machine

```text
IsScheduledExecution --(scheduleId present)--> AdmitScheduledRun --> PrepareRun
                     \--(otherwise)--------------------------------> PrepareRun
PrepareRun --> HasWorkItems --(cancelled)--> ScanFinished
                            \--> ScanWorkItems (Map) --> FinalizeRun --> CheckRunOutcome
ScanWorkItems iteration: ExecuteWorkItem --(any error)--> RecordWorkItemFailure
PrepareRun | ScanWorkItems | FinalizeRun --(any error)--> MarkRunFailed --> ScanFailed
```

- `AdmitScheduledRun` loads the schedule, rejects disabled or
  fingerprint-mismatched schedules, and records a `QUEUED` run whose ID is
  derived from the schedule ID and execution ARN. A retried admission returns
  the same run.
- `PrepareRun` moves the run to `RUNNING` and returns its `ScanWorkItem`s
  (at most 25 regions x 8 services). Re-preparing a running run returns the
  same items.
- `ScanWorkItems` is a Map state with bounded concurrency (`scanConcurrency`,
  default 10, range 1-40). Each `ExecuteWorkItem` scans exactly one
  account/region/service unit, writes its normalized result to
  `work/<scanRunId>/<accountId>/<region>/<service>.json` in the reports
  bucket (KMS-encrypted, expired after 7 days), and atomically increments
  the run's progress counters. Map iterations return only `{"outcome": ...}`;
  results never travel through the 256 KB state payload.
- A unit whose worker crashes or times out is caught inside its iteration.
  `RecordWorkItemFailure` stores a `worker_incomplete` coverage gap for it,
  unless the worker already stored a result. The scan continues and ends as
  `partial`.
- Units that start after a cancellation request return `skipped` without
  scanning. `FinalizeRun` then marks the run `CANCELLED`.
- `FinalizeRun` reads every planned unit's result, records a
  `work_item_result_missing` gap for any unit without one, recomputes the
  progress counters from durable results (retried workers may have counted
  twice), then aggregates, evaluates, reports, and ends the run.
- Only Lambda service, SDK-client, and throttling errors are retried. These
  occur before the handler runs, so no step is applied twice.
  `RecordWorkItemFailure` is idempotent, so it also retries handler errors.
- `MarkRunFailed` records `FAILED` with a sanitized error name. It never
  overwrites a terminal run and never stores the error cause.
- Execution data is excluded from state-machine logs. The execution timeout
  is 2 hours; each unit and the finalize step are bounded at 15 minutes.

`{"scanRunId": ...}` sent directly to the workflow function (not through the
state machine) still runs every step sequentially in one invocation, for
operator use.

## Scheduling boundary

`ScanSchedule` stores a schedule name, immutable `ScanRequest` snapshot and
fingerprint, creator subject, enabled state, and EventBridge Scheduler ARN.
It is stored under `pk=SCHEDULE#<scheduleId>, sk=SCHEDULE` in the runs table.
Each firing is admitted by the state machine as a normal `ScanRun` attributed
to the schedule creator.

The scheduler adapter permits only EventBridge `rate(...)` expressions no more
frequent than hourly or six-field `cron(...)` expressions. It invokes only the
approved scan state machine with `{"scheduleId":"uuid"}`. It cannot directly
invoke a scanner Lambda.

`POST /v1/schedules`, `PATCH /v1/schedules/{scheduleId}`, and
`DELETE /v1/schedules/{scheduleId}` are available only to the
`SovereignShieldAdministrators` group. Auditors can access scan status,
findings, and report metadata but cannot start/cancel scans or manage
schedules. API Gateway JWT validation is provisioned with the customer
CloudFormation stack in Phase 3/4; the Lambda repeats these group checks so
route configuration alone cannot grant mutation authority.

## Operations boundary

The workflow emits customer-safe completion metrics—run count, finding count,
coverage-gap count, and terminal status—to the `SovereignShield/Scans`
namespace. Resource names, ARNs, evidence payloads, and report content are
never metrics dimensions or notification text.

Notifications are opt-in. The default notifier sends only failed scan runs or
runs with critical findings, directing recipients to the authenticated console
for details. Notification or metrics delivery failure cannot alter a persisted
scan outcome.
