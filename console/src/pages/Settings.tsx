import { Panel } from "../components";
import { useSession } from "../session";

const SETTING_LABELS: Record<string, string> = {
  reportRetentionDays: "Report retention (days)",
  findingsRetentionDays: "Findings retention (days, 0 = indefinitely)",
  scheduledScansEnabled: "Scheduled scans",
  kmsKeyMode: "Encryption key",
  organizationId: "Organization ID",
  targetOrganizationalUnitIds: "Target OUs",
  accountAllowlist: "Account allowlist",
  accountDenylist: "Account denylist",
  exclusionTagKey: "Exclusion tag key",
  memberRoleName: "Member role name",
  maxAccountsPerScan: "Max accounts per scan",
  organizationMode: "Account scope",
  identityProviderMode: "Identity provider",
  dataDeletionAcknowledgement: "Data deletion acknowledgement",
  logRetentionDays: "Log retention (days)",
  scanConcurrency: "Parallel work units per scan",
  notificationsEnabled: "Email notifications",
  dataRemovalPolicy: "Data removal on stack deletion",
};

function displaySetting(value: string | number | boolean): string {
  if (value === true || value === "true") return "On";
  if (value === false || value === "false") return "Off";
  if (value === "") return "—";
  return String(value);
}

export function Settings() {
  const { configuration } = useSession();
  const { deployment, settings } = configuration;

  return (
    <>
      <Panel title="Deployment">
        <dl className="facts">
          <dt>Account</dt>
          <dd>{deployment.accountId}</dd>
          <dt>Region</dt>
          <dd>{deployment.region}</dd>
          <dt>Release</dt>
          <dd>{deployment.releaseVersion}</dd>
          <dt>Rule pack</dt>
          <dd>{deployment.rulePackVersion}</dd>
          <dt>Account scope</dt>
          <dd>
            {configuration.organization?.mode === "AWS_ORGANIZATIONS"
              ? `AWS Organizations (${configuration.organization.organizationId})`
              : "This account only"}
          </dd>
        </dl>
        {deployment.operationsDashboardUrl ? (
          <p>
            <a href={deployment.operationsDashboardUrl} target="_blank" rel="noreferrer noopener">
              Open the CloudWatch operations dashboard
            </a>{" "}
            <span className="muted">(requires AWS console access)</span>
          </p>
        ) : null}
      </Panel>
      {settings ? (
        <Panel title="Administrator settings">
          <p className="muted">
            These values are set by the CloudFormation stack. Change them with a stack update so the change is
            reviewed and recorded.
          </p>
          <dl className="facts">
            {Object.entries(settings).map(([key, value]) => (
              <div key={key} className="fact">
                <dt>{SETTING_LABELS[key] ?? key}</dt>
                <dd>{displaySetting(value)}</dd>
              </div>
            ))}
          </dl>
        </Panel>
      ) : null}
    </>
  );
}
