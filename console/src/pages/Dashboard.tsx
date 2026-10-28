import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { ErrorMessage, Loading, Panel, StatusBadge, formatDate, shortId } from "../components";
import { useCan, useSession } from "../session";
import type { ScanRun } from "../types";

export function Dashboard() {
  const { api } = useSession();
  const canStart = useCan("start_scan");
  const [scans, setScans] = useState<ScanRun[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(
    async (from?: string | null) => {
      try {
        const page = await api.listScans(from);
        setScans((current) => (from ? [...(current ?? []), ...page.items] : page.items));
        setCursor(page.nextCursor);
        setError(null);
      } catch (caught) {
        setError(caught);
      }
    },
    [api],
  );

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <Panel
      title="Scans"
      actions={canStart ? <Link className="button" to="/scans/new">New scan</Link> : undefined}
    >
      <ErrorMessage error={error} />
      {scans === null && !error ? <Loading /> : null}
      {scans?.length === 0 ? <p className="muted">No scans yet.</p> : null}
      {scans && scans.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Scan</th>
              <th>Status</th>
              <th>Started</th>
              <th>Accounts</th>
              <th>Regions</th>
              <th>Regulations</th>
              <th className="numeric">Findings</th>
              <th className="numeric">Coverage gaps</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.scanRunId}>
                <td>
                  <Link to={`/scans/${scan.scanRunId}`}>{shortId(scan.scanRunId)}</Link>
                </td>
                <td>
                  <StatusBadge status={scan.status} />
                </td>
                <td>{formatDate(scan.createdAt)}</td>
                <td>{(scan.targetAccountIds ?? []).length || 1}</td>
                <td>{scan.request.scanRegions.join(", ")}</td>
                <td>{scan.request.regulations.join(", ") || "all"}</td>
                <td className="numeric">{scan.progress.finding_count}</td>
                <td className="numeric">{scan.progress.coverage_gap_count}</td>
              </tr>
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
