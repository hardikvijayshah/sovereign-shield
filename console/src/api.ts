import type { Auth } from "./auth";
import type { RuntimeConfig } from "./config";
import type {
  AuditEvent,
  Configuration,
  Finding,
  FindingFilters,
  MemberAccount,
  NewScanRequest,
  Page,
  ReportResponse,
  ScanRequestSummary,
  ScanRun,
  Schedule,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }

  get isAccessDenied(): boolean {
    return this.status === 403;
  }
}

type Method = "GET" | "POST" | "PATCH" | "DELETE";

export class Api {
  constructor(
    private readonly config: RuntimeConfig,
    private readonly auth: Pick<Auth, "accessToken" | "signIn">,
    private readonly fetchFn: typeof fetch = (...args) => fetch(...args),
    private readonly currentPath: () => string = () => window.location.pathname + window.location.search,
  ) {}

  configuration(): Promise<Configuration> {
    return this.request("GET", "/v1/configuration");
  }

  async listScans(cursor?: string | null): Promise<Page<ScanRun>> {
    const body = await this.request<{ scans: ScanRun[]; nextCursor: string | null }>(
      "GET",
      `/v1/scans${query({ limit: "20", cursor })}`,
    );
    return { items: body.scans, nextCursor: body.nextCursor };
  }

  getScan(scanRunId: string): Promise<ScanRun> {
    return this.request("GET", `/v1/scans/${segment(scanRunId)}`);
  }

  startScan(request: NewScanRequest): Promise<{ scanRunId: string; created: boolean }> {
    return this.request("POST", "/v1/scans", request);
  }

  cancelScan(scanRunId: string): Promise<ScanRun> {
    return this.request("POST", `/v1/scans/${segment(scanRunId)}/cancel`);
  }

  async findings(scanRunId: string, filters: FindingFilters, cursor?: string | null): Promise<Page<Finding>> {
    const body = await this.request<{ findings: Finding[]; nextCursor: string | null }>(
      "GET",
      `/v1/scans/${segment(scanRunId)}/findings${query({ limit: "50", cursor, ...filters })}`,
    );
    return { items: body.findings, nextCursor: body.nextCursor };
  }

  report(scanRunId: string): Promise<ReportResponse> {
    return this.request("GET", `/v1/scans/${segment(scanRunId)}/report`);
  }

  async listSchedules(): Promise<Page<Schedule>> {
    const body = await this.request<{ schedules: Schedule[]; nextCursor: string | null }>(
      "GET",
      `/v1/schedules${query({ limit: "100" })}`,
    );
    return { items: body.schedules, nextCursor: body.nextCursor };
  }

  createSchedule(schedule: {
    name: string;
    scheduleExpression: string;
    enabled: boolean;
    scanRequest: ScanRequestSummary;
  }): Promise<Schedule> {
    return this.request("POST", "/v1/schedules", schedule);
  }

  updateSchedule(scheduleId: string, changes: { enabled?: boolean; scheduleExpression?: string }): Promise<Schedule> {
    return this.request("PATCH", `/v1/schedules/${segment(scheduleId)}`, changes);
  }

  deleteSchedule(scheduleId: string): Promise<void> {
    return this.request("DELETE", `/v1/schedules/${segment(scheduleId)}`);
  }

  async listAccounts(): Promise<{ organizationMode: string; accounts: MemberAccount[] }> {
    return this.request("GET", "/v1/accounts");
  }

  syncAccounts(): Promise<{ syncRequested: boolean }> {
    return this.request("POST", "/v1/accounts/sync");
  }

  updateAccount(accountId: string, change: { excluded: boolean; note?: string }): Promise<MemberAccount> {
    return this.request("PATCH", `/v1/accounts/${segment(accountId)}`, change);
  }

  async auditEvents(month: string, cursor?: string | null): Promise<Page<AuditEvent>> {
    const body = await this.request<{ events: AuditEvent[]; nextCursor: string | null }>(
      "GET",
      `/v1/audit-events${query({ month, limit: "50", cursor })}`,
    );
    return { items: body.events, nextCursor: body.nextCursor };
  }

  private async request<T>(method: Method, path: string, body?: unknown): Promise<T> {
    const token = await this.auth.accessToken();
    if (!token) {
      return this.auth.signIn(this.currentPath());
    }
    const response = await this.fetchFn(`${this.config.apiUrl}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-Correlation-Id": crypto.randomUUID(),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 401) {
      return this.auth.signIn(this.currentPath());
    }
    if (response.status === 204) {
      return undefined as T;
    }
    const payload = (await response.json().catch(() => ({}))) as { error?: string };
    if (!response.ok) {
      throw new ApiError(response.status, payload.error ?? "The request could not be completed.");
    }
    return payload as T;
  }
}

function segment(value: string): string {
  return encodeURIComponent(value);
}

function query(parameters: Record<string, string | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(parameters)) {
    if (value) {
      search.set(key, value);
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}
