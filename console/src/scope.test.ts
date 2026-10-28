import { describe, expect, it } from "vitest";

import { canToggleExclusion } from "./pages/Accounts";
import { estimateWorkUnits, scopeProblem, targetAccountCount } from "./scope";
import type { Configuration, MemberAccount, ScanRequestSummary } from "./types";

function configuration(mode: "SINGLE_ACCOUNT" | "AWS_ORGANIZATIONS", scannable = 3, maxAccounts = 25): Configuration {
  return {
    caller: { subject: "u", roles: ["administrator"], allowedActions: [] },
    scanChoices: {
      regions: ["eu-west-1", "eu-central-1"],
      maxRegions: 25,
      services: [
        { id: "s3", global: false },
        { id: "kms", global: false },
        { id: "cloudfront", global: true },
      ],
      regulations: [],
      dataCategories: [],
      reportGenerationModes: ["deterministic_only"],
      minimumScheduleInterval: "rate(1 hour)",
      defaultRegions: [],
      scheduledScansEnabled: true,
    },
    organization: {
      mode,
      organizationId: "o-abcdef1234",
      targetOrganizationalUnitIds: ["ou-prod"],
      maxAccountsPerScan: maxAccounts,
      maxWorkUnits: 1000,
      accountsByStatus: {},
      scannableAccountIds: Array.from({ length: scannable }, (_, index) => String(index).padStart(12, "0")),
    },
    deployment: { accountId: "111111111111", region: "eu-west-1", releaseVersion: "dev", rulePackVersion: "x",
                  operationsDashboardUrl: "" },
  };
}

function scope(changes: Partial<ScanRequestSummary> = {}): ScanRequestSummary {
  return {
    scanRegions: ["eu-west-1", "eu-central-1"],
    services: ["s3", "kms", "cloudfront"],
    regulations: [],
    dataCategories: [],
    reportGenerationMode: "deterministic_only",
    accountIds: [],
    ...changes,
  };
}

describe("account scope", () => {
  it("estimates units like the backend: global services run once per account", () => {
    // per account: 2 regional services x 2 regions + 1 global = 5
    expect(estimateWorkUnits(scope(), configuration("SINGLE_ACCOUNT"))).toBe(5);
    expect(estimateWorkUnits(scope(), configuration("AWS_ORGANIZATIONS", 3))).toBe(15);
    expect(estimateWorkUnits(scope({ accountIds: ["222222222222"] }), configuration("AWS_ORGANIZATIONS"))).toBe(5);
  });

  it("targets every onboarded account by default in organization mode, and one account otherwise", () => {
    expect(targetAccountCount(scope(), configuration("AWS_ORGANIZATIONS", 7))).toBe(7);
    expect(targetAccountCount(scope(), configuration("SINGLE_ACCOUNT", 7))).toBe(1);
  });

  it("blocks scans over the account and work-unit limits before they reach the API", () => {
    expect(scopeProblem(scope(), configuration("AWS_ORGANIZATIONS", 30, 25))).toMatch(/at most 25 accounts/);
    expect(scopeProblem(scope(), configuration("AWS_ORGANIZATIONS", 201, 300))).toMatch(/limit is 1000/);
    expect(scopeProblem(scope(), configuration("AWS_ORGANIZATIONS", 0))).toMatch(/No onboarded accounts/);
    expect(scopeProblem(scope(), configuration("AWS_ORGANIZATIONS", 3))).toBeNull();
    expect(scopeProblem(scope({ scanRegions: [] }), configuration("SINGLE_ACCOUNT"))).toMatch(/region/);
  });
});

describe("account exclusions", () => {
  const base: MemberAccount = {
    accountId: "222222222222", name: "", organizationalUnitId: "", status: "onboarded", scannable: true,
    exclusionReason: null, administratorExcluded: false, administratorExclusionNote: "", stackInstanceStatus: "",
    detail: "", lastSyncedAt: null,
  };

  it("lets administrators toggle only their own exclusions", () => {
    expect(canToggleExclusion(base)).toBe(true);
    expect(canToggleExclusion({ ...base, status: "excluded", exclusionReason: "administrator" })).toBe(true);
    expect(canToggleExclusion({ ...base, status: "excluded", exclusionReason: "denylist" })).toBe(false);
    expect(canToggleExclusion({ ...base, status: "excluded", exclusionReason: "exclusion_tag" })).toBe(false);
    expect(canToggleExclusion({ ...base, status: "deployment_account" })).toBe(false);
  });
});
