import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { ErrorMessage, Panel } from "../components";
import { useSession } from "../session";
import { ScanScopeFields, emptyScope, scopeProblem } from "./ScanForm";

export function NewScan() {
  const { api, configuration } = useSession();
  const navigate = useNavigate();
  const [scope, setScope] = useState(() => emptyScope(configuration.scanChoices));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>(null);
  // One key per form instance: a double-submit or retry returns the same run.
  const idempotencyKey = useMemo(() => `console-${crypto.randomUUID()}`, []);
  const problem = scopeProblem(scope, configuration);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (problem) return;
    setSubmitting(true);
    try {
      const accepted = await api.startScan({ ...scope, idempotencyKey });
      navigate(`/scans/${accepted.scanRunId}`);
    } catch (caught) {
      setError(caught);
      setSubmitting(false);
    }
  };

  return (
    <Panel title="New scan">
      <p className="muted">
        Scans are read-only. Sovereign Shield lists resource configuration in this account; it never changes
        resources.
      </p>
      <form onSubmit={(event) => void submit(event)}>
        <ScanScopeFields choices={configuration.scanChoices} value={scope} onChange={setScope} />
        <ErrorMessage error={error} />
        {problem ? <p className="muted">{problem}</p> : null}
        <button type="submit" className="button" disabled={submitting || Boolean(problem)}>
          {submitting ? "Starting…" : "Start scan"}
        </button>
      </form>
    </Panel>
  );
}
