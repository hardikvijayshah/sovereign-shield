# Sovereign Shield Operations Runbook

For operators of an installed stack. Every alarm notifies the stack's SNS topic
(subscribe with `NotificationEmail`). The CloudWatch dashboard is in the
`OperationsDashboardUrl` output.

## First response for any problem

1. Run the `PostDeployValidationCommand` output. It is read-only and shows
   which component is not ready.
2. Collect a support bundle:
   `python scripts/support_bundle.py --stack <stack> --region <region>`.
   It contains no log messages, findings, or reports. Email addresses are
   masked. Review it before sharing.

## Alarms

| Alarm | Meaning | Action |
|---|---|---|
| `StateMachineFailedAlarm` / `FailedScanRunsAlarm` | A scan run ended `failed` | Open the run in the console (error summary), then the state-machine execution of the same name. Units that failed individually appear as coverage gaps rather than failing the run. A failed *run* means prepare or finalize failed. |
| `StateMachineTimedOutAlarm` | A run exceeded 2 hours | Reduce accounts, regions, or services per scan. |
| `WorkflowErrorsAlarm` / `WorkflowThrottlesAlarm` | Scan worker errors or Lambda throttling | Throttling: lower `ScanConcurrency` or raise the account's Lambda concurrency quota. Errors: check the workflow log group by run ID. |
| `ApiFunctionErrorsAlarm` / `Api5xxAlarm` | API failures | Check the API log group. `503` responses with `Retry-After` during an upgrade are expected while an index builds. |
| `AuthorizationDenialsAlarm` | 25 or more role-check denials in 5 minutes | Look up `denied` events in the console **Audit log**. Either a user lacks the right Cognito group, or someone is probing. |
| `AuditWriteFailuresAlarm` | An audit record could not be written | The audited action did succeed. Check `AUDIT_WRITE_FAILED` in the API log group, and audit table throttling or KMS access. |
| `SchedulerDeliveryAlarm` | EventBridge Scheduler could not start a scheduled scan | Check that the scheduler role still exists and that the schedule group matches. |
| `DynamoDBThrottlesAlarm` | Table throttling | Tables are on-demand, so sustained throttling means account-level limits; contact AWS Support. |
| `OnboardingErrorsAlarm` | The organization onboarding sync failed | Check the onboarding log group. Organizations access usually requires the management or delegated administrator account. |

## Backup and restore

- DynamoDB tables have point-in-time recovery (35 days). To recover data,
  restore to a *new* table with `aws dynamodb restore-table-to-point-in-time`,
  verify it, then copy the items back. Do not point the stack at a restored
  table by hand: CloudFormation owns the table names.
- The reports bucket is versioned. Noncurrent report versions are kept for 30
  days.
- The audit table is append-only through the product. Treat PITR exports as
  your long-term audit archive if your policy requires more than 35 days of
  recovery.

## Upgrade

1. Read the new release's `RELEASE_NOTES.md` and `manifest.json`, and verify
   checksums with `checksums.txt`.
2. Create a change set from the new template URL with the **same parameters**.
   Do not use "Use existing template".
3. Review the change set. Data resources (tables, reports bucket, KMS key, user
   pool) must show `Modify` with `Replacement: False`. Do not execute a change
   set that replaces them.
4. Execute it, then run `PostDeployValidationCommand`. If the release adds an
   index, listing pages return `503` for a few minutes while it builds.

## Rollback

- **Failed update:** CloudFormation rolls back automatically to the previous
  release (`UPDATE_ROLLBACK_COMPLETE`). Data is not affected. Rerun the
  readiness check.
- **Unwanted completed update:** create a change set from the *previous*
  release's template URL with the same parameters, review it, and execute it.
  Released artifacts are immutable, so the previous version's code is still
  available.

## Decommissioning

- **Production template:** deleting the stack *retains* the tables, reports
  bucket, KMS key, user pool, and log groups. Export what you need, then delete
  them yourself. KMS keys enter a 7-30 day pending-deletion window.
- **Non-production template:** deleting the stack deletes all data, including
  the key (scheduled for deletion) and the user pool.
- **Organizations mode:** deleting the stack deletes the StackSet, which removes
  the member role from every member account.
- Schedules are deleted with the stack's schedule group. Delete them from the
  console first to keep the audit trail complete.
