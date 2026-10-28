/** Response shapes of the Sovereign Shield v1 API used by the console. */

export type ScanStatus =
  | "queued"
  | "validating"
  | "running"
  | "evaluating"
  | "reporting"
  | "cancel_requested"
  | "complete"
  | "partial"
  | "failed"
  | "cancelled";

export const TERMINAL_STATUSES: ReadonlySet<ScanStatus> = new Set(["complete", "partial", "failed", "cancelled"]);

export interface Configuration {
  caller: { subject: string; roles: string[]; allowedActions: string[] };
  scanChoices: {
    regions: string[];
    maxRegions: number;
    services: { id: string; global: boolean }[];
    regulations: { id: string; name: string; jurisdiction: string; dataCategories: string[] }[];
    dataCategories: string[];
    reportGenerationModes: string[];
    minimumScheduleInterval: string;
    defaultRegions: string[];
    scheduledScansEnabled: boolean;
  };
  organization: OrganizationSummary;
  deployment: {
    accountId: string;
    region: string;
    releaseVersion: string;
    rulePackVersion: string;
    operationsDashboardUrl: string;
  };
  settings?: Record<string, string | number | boolean>;
}

export interface OrganizationSummary {
  mode: "SINGLE_ACCOUNT" | "AWS_ORGANIZATIONS";
  organizationId: string;
  targetOrganizationalUnitIds: string[];
  maxAccountsPerScan: number;
  maxWorkUnits: number;
  accountsByStatus: Record<string, number>;
  scannableAccountIds: string[];
}

export type AccountStatus =
  | "deployment_account"
  | "onboarded"
  | "pending"
  | "failed"
  | "role_unreachable"
  | "excluded"
  | "suspended"
  | "out_of_scope";

export interface MemberAccount {
  accountId: string;
  name: string;
  organizationalUnitId: string;
  status: AccountStatus;
  scannable: boolean;
  exclusionReason: "denylist" | "exclusion_tag" | "not_allowlisted" | "administrator" | null;
  administratorExcluded: boolean;
  administratorExclusionNote: string;
  stackInstanceStatus: string;
  detail: string;
  lastSyncedAt: string | null;
}

export interface ScanRequestSummary {
  scanRegions: string[];
  services: string[];
  regulations: string[];
  dataCategories: string[];
  reportGenerationMode: string;
  /** Empty: the deployment account (single-account mode) or every onboarded account (organization mode). */
  accountIds: string[];
}

export interface ScanProgress {
  planned_units: number;
  completed_units: number;
  failed_units: number;
  resource_count: number;
  flow_count: number;
  finding_count: number;
  coverage_gap_count: number;
}

export interface ScanRun {
  scanRunId: string;
  status: ScanStatus;
  correlationId: string;
  progress: ScanProgress;
  errorSummary: string | null;
  createdAt: string;
  updatedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  report: Record<string, string | number> | null;
  request: ScanRequestSummary;
  requesterSubject: string;
  targetAccountIds: string[];
}

export interface Finding {
  finding_id: string;
  account_id: string;
  region: string;
  service: string;
  resource_arn: string;
  resource_name: string;
  rule_id: string;
  rule_pack_version: string;
  severity: string;
  category: string;
  description: string;
  evidence_ids: string[];
  data_categories: string[];
  finding_state: string;
  data_classification: string;
  uncertainty: string;
  created_at: string;
  guidance: { notice: string; steps: string[] };
}

export interface FindingFilters {
  accountId?: string;
  severity?: string;
  region?: string;
  service?: string;
  ruleId?: string;
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

export interface Schedule {
  scheduleId: string;
  name: string;
  scheduleExpression: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  request: ScanRequestSummary;
  requesterSubject: string;
}

export interface ReportResponse {
  scanRunId: string;
  report: Record<string, string | number>;
  download: { url: string; expiresAt: string } | null;
}

export interface AuditEvent {
  eventId: string;
  occurredAt: string;
  actorSubject: string;
  action: string;
  targetType: string;
  targetId: string;
  outcome: "succeeded" | "denied" | "rejected";
  correlationId: string;
  details: Record<string, string>;
}

export interface NewScanRequest {
  idempotencyKey: string;
  scanRegions: string[];
  services: string[];
  regulations: string[];
  dataCategories: string[];
  reportGenerationMode: string;
  accountIds: string[];
}
