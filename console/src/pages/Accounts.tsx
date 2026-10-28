import { useCallback, useEffect, useMemo, useState } from "react";

import { ErrorMessage, Loading, Panel, formatDate } from "../components";
import { isOrganizationMode } from "../scope";
import { useCan, useSession } from "../session";
import type { AccountStatus, MemberAccount } from "../types";

const STATUS_LABELS: Record<AccountStatus, string> = {
  deployment_account: "This account",
  onboarded: "Onboarded",
  pending: "Pending",
  failed: "Role deployment failed",
  role_unreachable: "Role unreachable",
  excluded: "Excluded",
  suspended: "Suspended",
  out_of_scope: "Out of scope",
};

const EXCLUSION_LABELS: Record<string, string> = {
  denylist: "AccountDenylist",
  exclusion_tag: "Exclusion tag",
  not_allowlisted: "Not in AccountAllowlist",
  administrator: "Administrator",
};

export function AccountStatusBadge({ status }: { status: AccountStatus }) {
  return <span className={`badge account-${status}`}>{STATUS_LABELS[status] ?? status}</span>;
}

/** Configuration-driven exclusions cannot be changed from the console. */
export function canToggleExclusion(account: MemberAccount): boolean {
  if (account.status === "deployment_account") return false;
  return !["denylist", "exclusion_tag", "not_allowlisted"].includes(account.exclusionReason ?? "");
}

export function Accounts() {
  const { api, configuration } = useSession();
  const canManage = useCan("manage_accounts");
  const organizationMode = isOrganizationMode(configuration);
  const [accounts, setAccounts] = useState<MemberAccount[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [ouFilter, setOuFilter] = useState("");

  const load = useCallback(async () => {
    try {
      setAccounts((await api.listAccounts()).accounts);
      setError(null);
    } catch (caught) {
      setError(caught);
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const counts = useMemo(() => {
    const result: Record<string, number> = {};
    for (const account of accounts ?? []) result[account.status] = (result[account.status] ?? 0) + 1;
    return result;
  }, [accounts]);
  const ous = useMemo(
    () => [...new Set((accounts ?? []).map((account) => account.organizationalUnitId).filter(Boolean))].sort(),
    [accounts],
  );
  const visible = (accounts ?? []).filter(
    (account) => (!statusFilter || account.status === statusFilter) && (!ouFilter || account.organizationalUnitId === ouFilter),
  );

  const sync = async () => {
    try {
      await api.syncAccounts();
      setNotice("Onboarding sync started. Status updates within a few minutes; this page refreshes shortly.");
      window.setTimeout(() => void load(), 20000);
    } catch (caught) {
      setError(caught);
    }
  };

  const toggle = async (account: MemberAccount) => {
    const excluding = !account.administratorExcluded;
    const note = excluding ? window.prompt(`Reason for excluding ${account.accountId} (recorded in the audit log):`) : "";
    if (excluding && note === null) return;
    try {
      await api.updateAccount(account.accountId, { excluded: excluding, note: note ?? "" });
      await load();
    } catch (caught) {
      setError(caught);
    }
  };

  return (
    <Panel
      title="Accounts"
      actions={
        canManage && organizationMode ? (
          <button type="button" className="button" onClick={() => void sync()}>
            Refresh status
          </button>
        ) : undefined
      }
    >
      {organizationMode ? (
        <p className="muted">
          Organization {configuration.organization.organizationId} · OUs{" "}
          {configuration.organization.targetOrganizationalUnitIds.join(", ")}. A read-only member role is deployed to
          these OUs by a StackSet; only onboarded accounts are scanned. Status refreshes every 6 hours.
        </p>
      ) : (
        <p className="muted">
          This deployment scans only its own account. To scan an AWS organization, update the stack with
          OrganizationMode = AWS_ORGANIZATIONS, OrganizationId, and TargetOrganizationalUnitIds from the management or
          a StackSets delegated administrator account.
        </p>
      )}
      {notice ? <p className="warning" role="status">{notice}</p> : null}
      <ErrorMessage error={error} />
      {accounts === null && !error ? <Loading /> : null}
      {accounts ? (
        <>
          <div className="chips">
            {Object.entries(counts).map(([status, count]) => (
              <button
                key={status}
                type="button"
                className={`chip ${statusFilter === status ? "active" : ""}`}
                onClick={() => setStatusFilter(statusFilter === status ? "" : status)}
              >
                {STATUS_LABELS[status as AccountStatus] ?? status}: {count}
              </button>
            ))}
          </div>
          {ous.length > 1 ? (
            <div className="filters">
              <label>
                Organizational unit
                <select value={ouFilter} onChange={(event) => setOuFilter(event.target.value)}>
                  <option value="">All</option>
                  {ous.map((entry) => (
                    <option key={entry}>{entry}</option>
                  ))}
                </select>
              </label>
            </div>
          ) : null}
          <table>
            <thead>
              <tr>
                <th>Account</th>
                <th>Name</th>
                <th>OU</th>
                <th>Status</th>
                <th>Detail</th>
                <th>Last checked</th>
                {canManage && organizationMode ? <th aria-label="Actions" /> : null}
              </tr>
            </thead>
            <tbody>
              {visible.map((account) => (
                <tr key={account.accountId}>
                  <td>
                    <code>{account.accountId}</code>
                  </td>
                  <td>{account.name || "—"}</td>
                  <td>{account.organizationalUnitId || "—"}</td>
                  <td>
                    <AccountStatusBadge status={account.status} />
                    {account.exclusionReason ? (
                      <div className="muted">{EXCLUSION_LABELS[account.exclusionReason]}</div>
                    ) : null}
                  </td>
                  <td>
                    {account.detail}
                    {account.administratorExclusionNote ? (
                      <div className="muted">Note: {account.administratorExclusionNote}</div>
                    ) : null}
                  </td>
                  <td>{formatDate(account.lastSyncedAt)}</td>
                  {canManage && organizationMode ? (
                    <td>
                      {canToggleExclusion(account) ? (
                        <button
                          type="button"
                          className={account.administratorExcluded ? "" : "danger"}
                          onClick={() => void toggle(account)}
                        >
                          {account.administratorExcluded ? "Include" : "Exclude"}
                        </button>
                      ) : null}
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
    </Panel>
  );
}
