import { describe, expect, it, vi } from "vitest";

import { Api, ApiError } from "./api";
import { SignInRequiredError } from "./auth";
import { parseConfig } from "./config";
import { navItems } from "./nav";

const CONFIG = parseConfig({
  apiUrl: "https://api.example.com/",
  region: "eu-central-1",
  cognitoDomain: "https://shield.auth.eu-central-1.amazoncognito.com",
  clientId: "client-123",
});

function setup(responses: Response[], token: string | null = "token-1") {
  const fetchImpl = vi.fn(async () => responses.shift() ?? new Response("{}", { status: 500 }));
  const signIn = vi.fn(async () => {
    throw new SignInRequiredError();
  });
  const auth = { accessToken: vi.fn(async () => token), signIn };
  const api = new Api(CONFIG, auth as never, fetchImpl as unknown as typeof fetch, () => "/scans/1");
  return { api, fetchImpl, signIn };
}

describe("Api", () => {
  it("sends the bearer token and encodes identifiers and filters", async () => {
    const { api, fetchImpl } = setup([new Response(JSON.stringify({ findings: [], nextCursor: null }))]);

    await api.findings("run/../x", { severity: "critical", region: undefined }, "c1");

    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.example.com/v1/scans/run%2F..%2Fx/findings?limit=50&cursor=c1&severity=critical");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-1");
  });

  it("starts sign-in, resuming the current page, when no token or a 401 is returned", async () => {
    const noToken = setup([], null);
    await expect(noToken.api.getScan("run-1")).rejects.toBeInstanceOf(SignInRequiredError);
    expect(noToken.signIn).toHaveBeenCalledWith("/scans/1");
    expect(noToken.fetchImpl).not.toHaveBeenCalled();

    const expired = setup([new Response("{}", { status: 401 })]);
    await expect(expired.api.getScan("run-1")).rejects.toBeInstanceOf(SignInRequiredError);
  });

  it("surfaces 403 as access denied without exposing server details", async () => {
    const { api } = setup([new Response(JSON.stringify({ error: "Not authorized." }), { status: 403 })]);

    const error = await api.startScan({} as never).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).isAccessDenied).toBe(true);
  });

  it("treats 204 as success with no body", async () => {
    const { api } = setup([new Response(null, { status: 204 })]);

    await expect(api.deleteSchedule("s-1")).resolves.toBeUndefined();
  });
});

describe("parseConfig", () => {
  it("requires https endpoints", () => {
    expect(() => parseConfig({ ...CONFIG, apiUrl: "http://api.example.com" })).toThrow(/https/);
    expect(() => parseConfig({ ...CONFIG, clientId: "" })).toThrow(/clientId/);
    expect(CONFIG.apiUrl).toBe("https://api.example.com");
  });
});

describe("navItems", () => {
  it("shows administrators every section", () => {
    const admin = [
      "view_scan", "start_scan", "view_accounts", "manage_accounts", "view_schedules", "manage_schedule",
      "view_audit_log", "view_configuration",
    ];
    expect(navItems(admin).map((item) => item.label)).toEqual([
      "Scans", "New scan", "Accounts", "Schedules", "Audit log", "Settings",
    ]);
  });

  it("hides scan starts and the audit log from auditors", () => {
    const auditor = ["view_scan", "view_findings", "view_report", "view_accounts", "view_schedules", "view_configuration"];
    expect(navItems(auditor).map((item) => item.label)).toEqual(["Scans", "Accounts", "Schedules", "Settings"]);
  });
});


describe("accounts API", () => {
  it("lists, syncs, and updates accounts on the documented routes", async () => {
    const { api, fetchImpl } = setup([
      new Response(JSON.stringify({ organizationMode: "AWS_ORGANIZATIONS", accounts: [] })),
      new Response(JSON.stringify({ syncRequested: true }), { status: 202 }),
      new Response(JSON.stringify({ accountId: "222222222222" })),
    ]);

    await api.listAccounts();
    await api.syncAccounts();
    await api.updateAccount("222222222222", { excluded: true, note: "Review" });

    const calls = fetchImpl.mock.calls as unknown as [string, RequestInit][];
    expect(calls.map(([url, init]) => `${init.method} ${url.replace("https://api.example.com", "")}`)).toEqual([
      "GET /v1/accounts",
      "POST /v1/accounts/sync",
      "PATCH /v1/accounts/222222222222",
    ]);
    expect(JSON.parse(String(calls[2]![1].body))).toEqual({ excluded: true, note: "Review" });
  });
});
