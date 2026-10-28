import type { ReactNode } from "react";

import { ApiError } from "./api";
import type { ScanStatus } from "./types";

const STATUS_LABELS: Record<ScanStatus, string> = {
  queued: "Queued",
  validating: "Validating",
  running: "Running",
  evaluating: "Evaluating",
  reporting: "Reporting",
  cancel_requested: "Cancelling",
  complete: "Complete",
  partial: "Partial",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return <span className={`badge badge-${status}`}>{STATUS_LABELS[status] ?? status}</span>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge severity-${severity}`}>{severity}</span>;
}

export function ErrorMessage({ error }: { error: unknown }) {
  if (!error) return null;
  const message =
    error instanceof ApiError && error.isAccessDenied
      ? "Your role does not allow this action."
      : error instanceof Error
        ? error.message
        : "Something went wrong.";
  return (
    <p className="error" role="alert">
      {message}
    </p>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p className="muted" aria-live="polite">
      {label}
    </p>
  );
}

export function Panel({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-header">
        <h2>{title}</h2>
        {actions}
      </header>
      {children}
    </section>
  );
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

export function shortId(value: string): string {
  return value.slice(0, 8);
}
