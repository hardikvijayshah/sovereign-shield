import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { ErrorMessage, Loading, Panel, SeverityBadge, StatusBadge, formatDate } from "../components";
import { useCan, useSession } from "../session";
import { TERMINAL_STATUSES } from "../types";
import type { Finding, FindingFilters, ScanRun } from "../types";

const POLL_INTERVAL_MS = 3000;
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function ScanDetail() {
  const { scanRunId = "" } = useParams();
  const { api } = useSession();
  const canCancel = useCan("cancel_scan");
  const [scan, setScan] = useState<ScanRun | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [cancelling, setCancelling] = useState(false);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const next = await api.getScan(scanRunId);
        if (!active) return;
        setScan(next);
        setError(null);
        if (!TERMINAL_STATUSES.has(next.status)) {
          timer = window.setTimeout(() => void poll(), POLL_INTERVAL_MS);
        }
      } catch (caught) {
        if (active) setError(caught);
      }
    };
    void poll();
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [api, scanRunId]);

  const cancel = async () => {
    if (!window.confirm("Cancel this scan? Units already in progress finish their current AWS call.")) return;
    setCancelling(true);
    try {
      setScan(await api.cancelScan(scanRunId));
    } catch (caught) {
      setError(caught);
    } finally {
      setCancelling(false);
    }
  };

  if (!scan) {
    return <Panel title="Scan">{error ? <ErrorMessage error={error} /> : <Loading />}</Panel>;
  }

  const terminal = TERMINAL_STATUSES.has(scan.status);
  const { progress } = scan;
  const percent = progress.planned_units ? Math.round((progress.completed_units / progress.planned_units) * 100) : 0;

  return (
    <>
      <Panel
        title={`Scan ${scan.scanRunId}`}
        actions={
          canCancel && !terminal && scan.status !== "cancel_requested" ? (
            <button type="button" onClick={() => void cancel()} disabled={cancelling}>
              Cancel scan
            </button>
          ) : undefined
        }
      >
        <ErrorMessage error={error} />
        <dl className="facts">
          <dt>Status</dt>
          <dd>
            <StatusBadge status={scan.status} />
          </dd>
          <dt>Started</dt>
          <dd>{formatDate(scan.startedAt ?? scan.createdAt)}</dd>
          <dt>Completed</dt>
          <dd>{formatDate(scan.completedAt)}</dd>
          <dt>Accounts</dt>
          <dd>
            {(scan.targetAccountIds ?? []).map((accountId) => (
              <code key={accountId} className="evidence-id">
                {accountId}
              </code>
            ))}
          </dd>
          <dt>Regions</dt>
          <dd>{scan.request.scanRegions.join(", ")}</dd>
          <dt>Services</dt>
          <dd>{scan.request.services.join(", ")}</dd>
          <dt>Regulations</dt>
          <dd>{scan.request.regulations.join(", ") || "all"}</dd>
          <dt>Data categories</dt>
          <dd>{scan.request.dataCategories.join(", ") || "all"}</dd>
        </dl>
        <div className="progress" aria-live="polite">
          <progress max={100} value={percent} aria-label="Scan progress" />
          <span>
            {progress.completed_units} of {progress.planned_units} units
            {progress.failed_units ? `, ${progress.failed_units} incomplete` : ""}
          </span>
        </div>
        {terminal ? (
          <p>
            {progress.resource_count} resources, {progress.flow_count} data flows, {progress.finding_count} findings,{" "}
            {progress.coverage_gap_count} coverage gaps.
          </p>
        ) : null}
        {progress.coverage_gap_count > 0 ? (
          <p className="warning">
            Some services or regions could not be fully assessed. A clean result cannot be inferred for them.
          </p>
        ) : null}
        {scan.errorSummary ? <p className="error">{scan.errorSummary}</p> : null}
        {scan.report ? <ReportDownload scanRunId={scan.scanRunId} /> : null}
      </Panel>
      {terminal && scan.status !== "cancelled" ? <Findings
          scanRunId={scan.scanRunId}
          accounts={scan.targetAccountIds ?? []}
          regions={scan.request.scanRegions}
          services={scan.request.services}
        /> : null}
    </>
  );
}

function ReportDownload({ scanRunId }: { scanRunId: string }) {
  const { api } = useSession();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const download = async () => {
    setBusy(true);
    try {
      const report = await api.report(scanRunId);
      if (!report.download) throw new Error("A download link is not available for this report.");
      // A short-lived, single-object link; navigating to it starts the download.
      window.location.assign(report.download.url);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <button type="button" onClick={() => void download()} disabled={busy}>
        Download report
      </button>
      <ErrorMessage error={error} />
    </div>
  );
}

function Findings({
  scanRunId,
  accounts,
  regions,
  services,
}: {
  scanRunId: string;
  accounts: string[];
  regions: string[];
  services: string[];
}) {
  const { api } = useSession();
  const [filters, setFilters] = useState<FindingFilters>({});
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(
    async (from?: string | null) => {
      try {
        const page = await api.findings(scanRunId, filters, from);
        setFindings((current) => (from ? [...(current ?? []), ...page.items] : page.items));
        setCursor(page.nextCursor);
        setError(null);
      } catch (caught) {
        setError(caught);
      }
    },
    [api, scanRunId, filters],
  );

  useEffect(() => {
    setFindings(null);
    void load();
  }, [load]);

  const setFilter = (key: keyof FindingFilters, value: string) =>
    setFilters((current) => ({ ...current, [key]: value || undefined }));

  return (
    <Panel title="Findings">
      <p className="muted">
        Findings are evidence-backed potential issues. Data classification and legal basis require validation by
        your compliance team.
      </p>
      <div className="filters">
        {accounts.length > 1 ? (
          <label>
            Account
            <select value={filters.accountId ?? ""} onChange={(event) => setFilter("accountId", event.target.value)}>
              <option value="">All</option>
              {accounts.map((accountId) => (
                <option key={accountId}>{accountId}</option>
              ))}
            </select>
          </label>
        ) : null}
        <label>
          Severity
          <select value={filters.severity ?? ""} onChange={(event) => setFilter("severity", event.target.value)}>
            <option value="">All</option>
            {SEVERITIES.map((severity) => (
              <option key={severity}>{severity}</option>
            ))}
          </select>
        </label>
        <label>
          Region
          <select value={filters.region ?? ""} onChange={(event) => setFilter("region", event.target.value)}>
            <option value="">All</option>
            {regions.map((region) => (
              <option key={region}>{region}</option>
            ))}
          </select>
        </label>
        <label>
          Service
          <select value={filters.service ?? ""} onChange={(event) => setFilter("service", event.target.value)}>
            <option value="">All</option>
            {services.map((service) => (
              <option key={service}>{service}</option>
            ))}
          </select>
        </label>
      </div>
      <ErrorMessage error={error} />
      {findings === null && !error ? <Loading /> : null}
      {findings?.length === 0 && !cursor ? <p className="muted">No findings match.</p> : null}
      {findings && findings.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Account</th>
              <th>Resource</th>
              <th>Region</th>
              <th>Rule</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <FindingRow
                key={finding.finding_id}
                finding={finding}
                expanded={expanded === finding.finding_id}
                onToggle={() => setExpanded(expanded === finding.finding_id ? null : finding.finding_id)}
              />
            ))}
          </tbody>
        </table>
      ) : null}
      {cursor ? (
        <button type="button" onClick={() => void load(cursor)}>
          Load more
        </button>
      ) : null}
    </Panel>
  );
}

function FindingRow({ finding, expanded, onToggle }: { finding: Finding; expanded: boolean; onToggle: () => void }) {
  return (
    <>
      <tr>
        <td>
          <SeverityBadge severity={finding.severity} />
        </td>
        <td>
          <code>{finding.account_id}</code>
        </td>
        <td>
          <button type="button" className="link-button" aria-expanded={expanded} onClick={onToggle}>
            {finding.resource_name || finding.resource_arn}
          </button>
          <div className="muted">{finding.service}</div>
        </td>
        <td>{finding.region}</td>
        <td>
          <code>{finding.rule_id}</code>
        </td>
        <td>{finding.description}</td>
      </tr>
      {expanded ? (
        <tr className="detail-row">
          <td colSpan={6}>
            <dl className="facts">
              <dt>Resource ARN</dt>
              <dd>
                <code>{finding.resource_arn}</code>
              </dd>
              <dt>Rule pack version</dt>
              <dd>{finding.rule_pack_version}</dd>
              <dt>State</dt>
              <dd>{finding.finding_state}</dd>
              <dt>Data classification</dt>
              <dd>{finding.data_classification}</dd>
              <dt>Uncertainty</dt>
              <dd>{finding.uncertainty}</dd>
              <dt>Evidence</dt>
              <dd>
                {finding.evidence_ids.map((evidenceId) => (
                  <code key={evidenceId} className="evidence-id">
                    {evidenceId}
                  </code>
                ))}
              </dd>
            </dl>
            <div className="guidance">
              <h3>Remediation guidance</h3>
              <p className="muted">{finding.guidance.notice}</p>
              <ol>
                {finding.guidance.steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}
