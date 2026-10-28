import { useCallback, useEffect, useState } from "react";

import { ErrorMessage, Loading, Panel, formatDate, shortId } from "../components";
import { useSession } from "../session";
import type { AuditEvent } from "../types";

function currentMonth(): string {
  return new Date().toISOString().slice(0, 7);
}

export function AuditLog() {
  const { api } = useSession();
  const [month, setMonth] = useState(currentMonth);
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(
    async (from?: string | null) => {
      try {
        const page = await api.auditEvents(month, from);
        setEvents((current) => (from ? [...(current ?? []), ...page.items] : page.items));
        setCursor(page.nextCursor);
        setError(null);
      } catch (caught) {
        setError(caught);
      }
    },
    [api, month],
  );

  useEffect(() => {
    setEvents(null);
    void load();
  }, [load]);

  return (
    <Panel
      title="Audit log"
      actions={
        <label>
          Month{" "}
          <input type="month" value={month} max={currentMonth()} onChange={(event) => setMonth(event.target.value)} />
        </label>
      }
    >
      <p className="muted">
        Scan starts and cancellations, schedule changes, report downloads, and denied requests. Records cannot be
        edited or deleted through Sovereign Shield.
      </p>
      <ErrorMessage error={error} />
      {events === null && !error ? <Loading /> : null}
      {events?.length === 0 ? <p className="muted">No events this month.</p> : null}
      {events && events.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Outcome</th>
              <th>Target</th>
              <th>Actor</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.eventId}>
                <td>{formatDate(event.occurredAt)}</td>
                <td>
                  <code>{event.action}</code>
                </td>
                <td className={`outcome-${event.outcome}`}>{event.outcome}</td>
                <td>{event.targetId ? shortId(event.targetId) : "—"}</td>
                <td title={event.actorSubject}>{shortId(event.actorSubject)}</td>
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
