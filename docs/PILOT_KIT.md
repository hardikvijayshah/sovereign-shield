# Sovereign Shield Customer Pilot Kit

A representative pilot is the last Phase 6 item (plan.md section 14). It confirms that a
customer can install, operate, and act on Sovereign Shield without engineering
help. Plan for two to four weeks.

## Pilot candidate

Choose a customer that:
- has workloads in at least two regions, including one outside their
  regulated jurisdiction, so findings are likely;
- can deploy in a non-production account first, using the non-production
  template;
- has a compliance contact who can judge whether findings are correct.

Organizations mode is optional for the first pilot. It is the best way to
close the open Phase 5 live test if the customer can give access to a test OU.

## Plan

| Week | Activity | Owner |
|---|---|---|
| 0 | Share `RELEASE_NOTES.md`, `docs/DATA_RESIDENCY.md`, `docs/REGULATION_COVERAGE.md`, and `installer-policy.json`. Agree the success criteria below. | Vendor |
| 1 | Customer installs from the Quick Create link **without assistance**, runs `PostDeployValidationCommand`, signs in, and adds an auditor. | Customer |
| 1-2 | Customer runs scans for their regulations and data categories, and reviews findings with their compliance contact. | Customer |
| 2 | Optional: enable scheduled scans and receive a notification. | Customer |
| 3 | Upgrade to a newer release by change set (if one is available). | Customer |
| 3-4 | Feedback session; decommission or convert to production. | Both |

## Success criteria

| # | Criterion | Target |
|---|---|---|
| 1 | Install to first completed scan, unassisted | 60 minutes or less |
| 2 | Readiness check passes on first run | Yes |
| 3 | Findings judged correct by the customer's compliance contact | 90% or more of reviewed findings |
| 4 | Findings judged actionable (guidance was useful) | 75% or more |
| 5 | Coverage gaps explained to the customer's satisfaction | All |
| 6 | No P0/P1 security, deployment, or data-residency issue raised | None open |
| 7 | Customer confirms the data-residency statement matches their review | Yes |

## Feedback form

1. Installation: what was unclear? Which step took longest?
2. Permissions: did the installer policy work as written? What did your
   security team change?
3. Findings: which findings were wrong, missing, or noisy? Give run and
   finding IDs.
4. Guidance: was the remediation guidance enough to act on?
5. Console: what did you look for and not find?
6. Data residency: does `DATA_RESIDENCY.md` answer your reviewers' questions?
7. Operations: did alarms and notifications reach the right people?
8. Would you deploy this in production? What would block it?

## Support during the pilot

- Ask for a support bundle (`scripts/support_bundle.py`) before anything else.
  It contains no findings or log text.
- Triage with `docs/OPERATIONS.md`.
- Record each issue with a severity:
  - **P0:** security or data-residency exposure, or data loss;
  - **P1:** installation, upgrade, or scan correctness blocked;
  - **P2:** usability or documentation.

  P0 and P1 issues block Phase 6 completion.

## Exit

Record the outcome against each success criterion in `plan.md`. Phase 6 is
complete when the criteria are met and no P0 or P1 issue is open.
