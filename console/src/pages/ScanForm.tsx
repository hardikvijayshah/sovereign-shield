import { useEffect, useMemo, useState } from "react";

import { ErrorMessage } from "../components";
import { estimateWorkUnits, isOrganizationMode, scopeProblem as checkScope, targetAccountCount } from "../scope";
import { useSession } from "../session";
import type { Configuration, MemberAccount, ScanRequestSummary } from "../types";

/** Shared scan-scope selector for on-demand scans and schedules. */
export function ScanScopeFields({
  choices,
  value,
  onChange,
}: {
  choices: Configuration["scanChoices"];
  value: ScanRequestSummary;
  onChange: (next: ScanRequestSummary) => void;
}) {
  const { configuration } = useSession();
  const toggle = (field: "scanRegions" | "services" | "regulations" | "dataCategories", item: string) => {
    const current = value[field];
    onChange({
      ...value,
      [field]: current.includes(item) ? current.filter((entry) => entry !== item) : [...current, item],
    });
  };

  const selectedRegulations = choices.regulations.filter((regulation) => value.regulations.includes(regulation.id));
  const categories = selectedRegulations.length
    ? [...new Set(selectedRegulations.flatMap((regulation) => regulation.dataCategories))].sort()
    : choices.dataCategories;

  return (
    <>
      {isOrganizationMode(configuration) ? <AccountScopeField value={value} onChange={onChange} /> : null}
      <fieldset>
        <legend>
          Regions <span className="muted">({value.scanRegions.length}/{choices.maxRegions})</span>
        </legend>
        <div className="checkbox-grid">
          {choices.regions.map((region) => (
            <label key={region}>
              <input
                type="checkbox"
                checked={value.scanRegions.includes(region)}
                disabled={!value.scanRegions.includes(region) && value.scanRegions.length >= choices.maxRegions}
                onChange={() => toggle("scanRegions", region)}
              />
              {region}
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend>Services</legend>
        <div className="checkbox-grid">
          {choices.services.map((service) => (
            <label key={service.id}>
              <input
                type="checkbox"
                checked={value.services.includes(service.id)}
                onChange={() => toggle("services", service.id)}
              />
              {service.id}
              {service.global ? <span className="muted"> (global, scanned once per account)</span> : null}
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend>Regulations</legend>
        <div className="checkbox-grid wide">
          {choices.regulations.map((regulation) => (
            <label key={regulation.id}>
              <input
                type="checkbox"
                checked={value.regulations.includes(regulation.id)}
                onChange={() => toggle("regulations", regulation.id)}
              />
              {regulation.name} <span className="muted">({regulation.jurisdiction})</span>
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend>Data categories in scope</legend>
        <p className="muted">
          Select the categories your data actually contains. Unselected categories are not evaluated.
        </p>
        <div className="checkbox-grid">
          {categories.map((category) => (
            <label key={category}>
              <input
                type="checkbox"
                checked={value.dataCategories.includes(category)}
                onChange={() => toggle("dataCategories", category)}
              />
              {category.replace(/_/g, " ")}
            </label>
          ))}
        </div>
      </fieldset>
      <p className="muted" aria-live="polite">
        Estimated work: {estimateWorkUnits(value, configuration)} account/region/service units across{" "}
        {targetAccountCount(value, configuration)} account(s) (limit {configuration.organization?.maxWorkUnits ?? 1000}).
      </p>
    </>
  );
}

/** Organization mode only: all onboarded accounts, or an explicit selection. */
function AccountScopeField({
  value,
  onChange,
}: {
  value: ScanRequestSummary;
  onChange: (next: ScanRequestSummary) => void;
}) {
  const { api, configuration } = useSession();
  const [accounts, setAccounts] = useState<MemberAccount[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [search, setSearch] = useState("");
  const [ou, setOu] = useState("");
  const selecting = value.accountIds.length > 0;

  useEffect(() => {
    api
      .listAccounts()
      .then((response) => setAccounts(response.accounts.filter((account) => account.scannable)))
      .catch(setError);
  }, [api]);

  const ous = useMemo(
    () => [...new Set((accounts ?? []).map((account) => account.organizationalUnitId).filter(Boolean))].sort(),
    [accounts],
  );
  const visible = (accounts ?? []).filter(
    (account) =>
      (!ou || account.organizationalUnitId === ou) &&
      (!search || `${account.accountId} ${account.name}`.toLowerCase().includes(search.toLowerCase())),
  );
  const toggleAccount = (accountId: string) =>
    onChange({
      ...value,
      accountIds: value.accountIds.includes(accountId)
        ? value.accountIds.filter((entry) => entry !== accountId)
        : [...value.accountIds, accountId],
    });
  const limit = configuration.organization.maxAccountsPerScan;

  return (
    <fieldset>
      <legend>Accounts</legend>
      <ErrorMessage error={error} />
      <label className="field inline">
        <input
          type="radio"
          name="account-scope"
          checked={!selecting}
          onChange={() => onChange({ ...value, accountIds: [] })}
        />
        All onboarded accounts ({configuration.organization.scannableAccountIds.length})
      </label>
      <label className="field inline">
        <input
          type="radio"
          name="account-scope"
          checked={selecting}
          disabled={!accounts?.length}
          onChange={() => onChange({ ...value, accountIds: accounts?.[0] ? [accounts[0].accountId] : [] })}
        />
        Selected accounts ({value.accountIds.length}/{limit})
      </label>
      {selecting && accounts ? (
        <>
          <div className="filters">
            <label>
              Search
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="ID or name" />
            </label>
            <label>
              Organizational unit
              <select value={ou} onChange={(event) => setOu(event.target.value)}>
                <option value="">All</option>
                {ous.map((entry) => (
                  <option key={entry}>{entry}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="checkbox-grid wide">
            {visible.map((account) => (
              <label key={account.accountId}>
                <input
                  type="checkbox"
                  checked={value.accountIds.includes(account.accountId)}
                  disabled={!value.accountIds.includes(account.accountId) && value.accountIds.length >= limit}
                  onChange={() => toggleAccount(account.accountId)}
                />
                <code>{account.accountId}</code> {account.name}
                {account.status === "deployment_account" ? <span className="muted"> (this account)</span> : null}
              </label>
            ))}
          </div>
        </>
      ) : null}
      <p className="muted">
        Only onboarded accounts are listed. Excluded accounts and accounts whose member role is missing or unreachable
        are never scanned; see the Accounts page.
      </p>
    </fieldset>
  );
}

export function emptyScope(choices: Configuration["scanChoices"]): ScanRequestSummary {
  return {
    scanRegions: [...(choices.defaultRegions ?? [])],
    services: choices.services.map((service) => service.id),
    regulations: [],
    dataCategories: [],
    reportGenerationMode: choices.reportGenerationModes[0] ?? "deterministic_only",
    accountIds: [],
  };
}

/** Validation for a scope, including account and work-unit limits. */
export function scopeProblem(value: ScanRequestSummary, configuration: Configuration): string | null {
  return checkScope(value, configuration);
}
