# Deterministic Scan Data Persistence Contract

## Purpose

This contract defines the DynamoDB item shape required by the Phase 1
deterministic scan core. Phase 2 API/workflow code and Phase 4 CloudFormation
must implement this contract without changing primary keys or entity names.

The reference implementation is `DynamoDBScanStore` in
`src/sovereign_shield/services/scan_store.py`.

## Tables

### Runs table

The runs table has:

- partition key: `pk` (String)
- sort key: `sk` (String)
- point-in-time recovery: enabled
- customer KMS encryption: enabled

It stores scan-run summaries, normalized resource evidence, normalized flow
evidence, coverage gaps, and later schedule records.

| Entity | `pk` | `sk` | Required fields |
|---|---|---|---|
| Scan run (control plane) | `RUN#<scanRunId>` | `RUN` | `ScanRun`: status, request, fingerprint, requester, correlation ID, execution ARN, progress, report metadata, timestamps. Written only by `DynamoDBScanRunStore` |
| Scan result summary | `RUN#<scanRunId>` | `SUMMARY` | direct-engine status (`complete`/`partial`), request, account, schema version, timestamps, count fields. Written by `DynamoDBScanStore` |
| Resource evidence | `RUN#<scanRunId>` | `EVIDENCE#RESOURCE#<evidenceId>` | account, region, service, ARN, name, type, encryption, details, collected time |
| Flow evidence | `RUN#<scanRunId>` | `EVIDENCE#FLOW#<evidenceId>` | account, source/destination regions, service, ARN, name, type, encryption, details, collected time |
| Coverage gap | `RUN#<scanRunId>` | `COVERAGE_GAP#<gapId>` | account, region, service, code, message, retryability, observed time |
| Scan schedule | `SCHEDULE#<scheduleId>` | `SCHEDULE` | immutable request, request fingerprint, creator, expression, enabled state, Scheduler ARN, timestamps |
| Member account | `ACCOUNT#<accountId>` | `ACCOUNT` | onboarding status, OU, exclusion reason, administrator exclusion and note, StackSet instance status, detail, last sync. Written by the onboarding sync and administrator exclusions; listed through `by-entity-created` (`entity_type=member_account`) |

### Findings table

The findings table has:

- partition key: `pk` (String)
- sort key: `sk` (String)
- point-in-time recovery: enabled
- customer KMS encryption: enabled
- future GSI: `scan_run_id` + `severity_created_at` for severity-ordered run
  views.

| Entity | `pk` | `sk` | Required fields |
|---|---|---|---|
| Finding | `RUN#<scanRunId>` | `FINDING#<findingId>` | rule ID/version, account/region/service, ARN/name, severity, evidence IDs, classification/uncertainty, timestamp |

### Reports bucket

| Object | Key | Lifetime |
|---|---|---|
| Per-unit scanner result (`DeterministicScanResult` JSON) | `work/<scanRunId>/<accountId>/<region>/<service>.json` | Transient; expired after 7 days |
| Report | `reports/<scanRunId>/<reportId>.md` | `reportRetentionDays` |

Per-unit results are stored in S3 because a single unit can exceed DynamoDB's
400 KB item limit. Both object types are KMS-encrypted with the stack key.

## Write behavior

- Evidence and findings are identified deterministically from their scan-run
  scope so a worker retry overwrites the same item instead of duplicating it.
- The control-plane run record also stores the request fingerprint, requester
  subject, correlation ID, workflow execution ARN, progress counters, and a
  redacted terminal error summary. It is created conditionally and subsequent
  lifecycle writes require the existing `RUN` item.
- A scan-run summary records the final Phase 1 direct-engine status:
  `complete` or `partial`.
- Workers update the `RUN` record only through atomic `UpdateItem`
  increments of `progress.completed_units` / `progress.failed_units`, so
  parallel units cannot overwrite a status change such as a cancellation.
- `ScanRun.target_account_ids` freezes the accounts resolved when a run is
  accepted; runs accepted before multi-account support scan only `account_id`.
  Findings carry the account of their own evidence, and the account is part
  of the finding ID.
- A request without `account_ids` fingerprints exactly as it did before the
  field existed, so stored schedules and idempotency keys remain valid.
- Coverage gaps are first-class records. A clean result cannot be inferred when
  gaps exist.
- Each scanner response is normalized record-by-record. Invalid collections or
  individual records are captured as coverage gaps; valid evidence from the
  same response remains available. Repeated evidence identifiers are
  deduplicated within a scan run.
- All model serialization uses Pydantic JSON mode so DynamoDB receives strings,
  lists, maps, and booleans rather than Python datetime or enum objects.

## Phase ownership

- **Phase 1:** typed contracts, item shape, in-memory adapter, and DynamoDB
  adapter.
- **Phase 2:** workflow state transitions, query APIs, idempotent conditional
  writes, cancellation, audit records, and schedule entities.
- **Phase 4:** provision tables, indexes, KMS encryption, retention, alarms,
  and runtime IAM in the customer CloudFormation stack.
