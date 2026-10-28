import { useCallback, useEffect, useState } from "react";

import { ErrorMessage, Loading, Panel, formatDate } from "../components";
import { useCan, useSession } from "../session";
import type { Schedule } from "../types";
import { ScanScopeFields, emptyScope, scopeProblem } from "./ScanForm";

function accountScopeLabel(accountIds: string[] | undefined): string {
  if (!accountIds?.length) return "All onboarded";
  return accountIds.length === 1 ? accountIds[0]! : `${accountIds.length} accounts`;
}

export function Schedules() {
  const { api } = useSession();
  const { configuration } = useSession();
  const canManage = useCan("manage_schedule");
  const schedulingEnabled = configuration.scanChoices.scheduledScansEnabled !== false;
  const [schedules, setSchedules] = useState<Schedule[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    try {
      setSchedules((await api.listSchedules()).items);
      setError(null);
    } catch (caught) {
      setError(caught);
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (action: () => Promise<unknown>) => {
    try {
      await action();
      await load();
    } catch (caught) {
      setError(caught);
    }
  };

  return (
    <>
      <Panel
        title="Scheduled scans"
        actions={
          canManage && schedulingEnabled && !creating ? (
            <button type="button" className="button" onClick={() => setCreating(true)}>
              New schedule
            </button>
          ) : undefined
        }
      >
        <p className="muted">Each run of a schedule is recorded as a normal scan. Schedules never run more often than hourly.</p>
        {!schedulingEnabled ? (
          <p className="warning">
            Scheduled scans are disabled for this deployment (stack parameter EnableScheduledScans). Existing schedules
            do not start scans.
          </p>
        ) : null}
        <ErrorMessage error={error} />
        {schedules === null && !error ? <Loading /> : null}
        {schedules?.length === 0 ? <p className="muted">No schedules.</p> : null}
        {schedules && schedules.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Expression</th>
                <th>Regions</th>
                <th>Accounts</th>
                <th>State</th>
                <th>Updated</th>
                {canManage ? <th aria-label="Actions" /> : null}
              </tr>
            </thead>
            <tbody>
              {schedules.map((schedule) => (
                <tr key={schedule.scheduleId}>
                  <td>{schedule.name}</td>
                  <td>
                    <code>{schedule.scheduleExpression}</code>
                  </td>
                  <td>{schedule.request.scanRegions.join(", ")}</td>
                  <td>{accountScopeLabel(schedule.request.accountIds)}</td>
                  <td>{schedule.enabled ? "Enabled" : "Paused"}</td>
                  <td>{formatDate(schedule.updatedAt)}</td>
                  {canManage ? (
                    <td className="actions">
                      <button
                        type="button"
                        onClick={() =>
                          void run(() => api.updateSchedule(schedule.scheduleId, { enabled: !schedule.enabled }))
                        }
                      >
                        {schedule.enabled ? "Pause" : "Resume"}
                      </button>
                      <button
                        type="button"
                        className="danger"
                        onClick={() => {
                          if (window.confirm(`Delete schedule "${schedule.name}"? Past scan results are kept.`)) {
                            void run(() => api.deleteSchedule(schedule.scheduleId));
                          }
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </Panel>
      {creating ? (
        <NewSchedule
          onCancel={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            void load();
          }}
        />
      ) : null}
    </>
  );
}

function NewSchedule({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const { api, configuration } = useSession();
  const [name, setName] = useState("");
  const [expression, setExpression] = useState("cron(0 6 ? * MON *)");
  const [enabled, setEnabled] = useState(false);
  const [scope, setScope] = useState(() => emptyScope(configuration.scanChoices));
  const [error, setError] = useState<unknown>(null);
  const problem = !name.trim() ? "Enter a name." : scopeProblem(scope, configuration);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (problem) return;
    try {
      await api.createSchedule({ name: name.trim(), scheduleExpression: expression.trim(), enabled, scanRequest: scope });
      onCreated();
    } catch (caught) {
      setError(caught);
    }
  };

  return (
    <Panel title="New schedule">
      <form onSubmit={(event) => void submit(event)}>
        <label className="field">
          Name
          <input value={name} maxLength={64} onChange={(event) => setName(event.target.value)} />
        </label>
        <label className="field">
          Schedule expression
          <input value={expression} onChange={(event) => setExpression(event.target.value)} />
          <span className="muted">
            EventBridge <code>rate(...)</code> (at least hourly) or six-field <code>cron(...)</code>, in UTC.
          </span>
        </label>
        <label className="field inline">
          <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
          Enable immediately
        </label>
        <ScanScopeFields choices={configuration.scanChoices} value={scope} onChange={setScope} />
        <ErrorMessage error={error} />
        {problem ? <p className="muted">{problem}</p> : null}
        <div className="actions">
          <button type="submit" className="button" disabled={Boolean(problem)}>
            Create schedule
          </button>
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Panel>
  );
}
