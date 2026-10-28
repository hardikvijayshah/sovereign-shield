import { createHash } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { Auth, SignInRequiredError, base64UrlEncode, pkceChallenge, randomString, safeReturnPath } from "./auth";
import type { RuntimeConfig } from "./config";

const CONFIG: RuntimeConfig = {
  apiUrl: "https://api.example.com",
  region: "eu-central-1",
  cognitoDomain: "https://shield.auth.eu-central-1.amazoncognito.com",
  clientId: "client-123",
};

class MemoryStorage implements Storage {
  private values = new Map<string, string>();
  get length() {
    return this.values.size;
  }
  clear() {
    this.values.clear();
  }
  getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  key(index: number) {
    return [...this.values.keys()][index] ?? null;
  }
  removeItem(key: string) {
    this.values.delete(key);
  }
  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
}

function tokenResponse(overrides: Record<string, unknown> = {}) {
  return new Response(
    JSON.stringify({ access_token: "access-1", id_token: "header.e30.sig", refresh_token: "refresh-1", expires_in: 3600, ...overrides }),
    { status: 200 },
  );
}

function setup(fetchImpl = vi.fn(async () => tokenResponse())) {
  const storage = new MemoryStorage();
  const assigned: string[] = [];
  let now = 1_000_000;
  const auth = new Auth(
    CONFIG,
    storage,
    { origin: "https://console.example.com", assign: (url) => assigned.push(url) },
    fetchImpl as unknown as typeof fetch,
    () => now,
  );
  return { auth, storage, assigned, fetchImpl, advance: (ms: number) => (now += ms) };
}

async function signInAndComplete(context: ReturnType<typeof setup>, returnTo = "/scans/abc") {
  await expect(context.auth.signIn(returnTo)).rejects.toBeInstanceOf(SignInRequiredError);
  const authorize = new URL(context.assigned[0] ?? "");
  const state = authorize.searchParams.get("state") ?? "";
  return { authorize, resumed: await context.auth.completeSignIn(`?code=code-1&state=${state}`) };
}

describe("PKCE helpers", () => {
  it("derives the S256 challenge exactly as an independent SHA-256 implementation does", async () => {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const verifier = randomString(48);
      const expected = createHash("sha256").update(verifier).digest("base64url");
      expect(await pkceChallenge(verifier)).toBe(expected);
    }
  });

  it("produces URL-safe, unpadded random strings of sufficient length", () => {
    const value = randomString(48);
    expect(value).toMatch(/^[A-Za-z0-9_-]{64}$/);
    expect(base64UrlEncode(new Uint8Array([251, 255]))).toBe("-_8");
  });

  it("only resumes same-origin paths", () => {
    expect(safeReturnPath("/scans/1?x=1")).toBe("/scans/1?x=1");
    expect(safeReturnPath("//evil.example")).toBe("/");
    expect(safeReturnPath("/\\evil.example")).toBe("/");
    expect(safeReturnPath("https://evil.example")).toBe("/");
    expect(safeReturnPath(null)).toBe("/");
  });
});

describe("Auth", () => {
  let context: ReturnType<typeof setup>;

  beforeEach(() => {
    context = setup();
  });

  it("redirects to hosted sign-in with an S256 code challenge", async () => {
    const { authorize } = await signInAndComplete(context);

    expect(authorize.origin + authorize.pathname).toBe(`${CONFIG.cognitoDomain}/oauth2/authorize`);
    expect(authorize.searchParams.get("response_type")).toBe("code");
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorize.searchParams.get("redirect_uri")).toBe("https://console.example.com/callback");
    expect(authorize.searchParams.get("client_id")).toBe("client-123");
  });

  it("exchanges the code with the stored verifier and resumes the original path", async () => {
    const { authorize, resumed } = await signInAndComplete(context);

    expect(resumed).toBe("/scans/abc");
    const [url, init] = context.fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${CONFIG.cognitoDomain}/oauth2/token`);
    const form = new URLSearchParams(String(init.body));
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toBe("code-1");
    expect(await pkceChallenge(form.get("code_verifier") ?? "")).toBe(authorize.searchParams.get("code_challenge"));
    expect(form.has("client_secret")).toBe(false);
    expect(await context.auth.accessToken()).toBe("access-1");
  });

  it("rejects a callback whose state does not match this browser session", async () => {
    await expect(context.auth.signIn("/")).rejects.toBeInstanceOf(SignInRequiredError);

    await expect(context.auth.completeSignIn("?code=code-1&state=forged")).rejects.toThrow(/did not match/);
    expect(context.fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects a replayed callback after the pending sign-in is consumed", async () => {
    const { authorize } = await signInAndComplete(context);
    const state = authorize.searchParams.get("state") ?? "";

    await expect(context.auth.completeSignIn(`?code=code-1&state=${state}`)).rejects.toThrow(/did not match/);
  });

  it("refreshes an expiring access token and keeps the refresh token", async () => {
    await signInAndComplete(context);
    context.fetchImpl.mockResolvedValueOnce(tokenResponse({ access_token: "access-2", refresh_token: undefined }));
    context.advance(3600 * 1000);

    expect(await context.auth.accessToken()).toBe("access-2");
    const form = new URLSearchParams(String((context.fetchImpl.mock.calls[1] as unknown as [string, RequestInit])[1].body));
    expect(form.get("grant_type")).toBe("refresh_token");
    context.advance(3600 * 1000);
    context.fetchImpl.mockResolvedValueOnce(tokenResponse({ access_token: "access-3" }));
    expect(await context.auth.accessToken()).toBe("access-3");
  });

  it("drops the session when refresh fails", async () => {
    await signInAndComplete(context);
    context.fetchImpl.mockResolvedValueOnce(new Response("{}", { status: 400 }));
    context.advance(3600 * 1000);

    expect(await context.auth.accessToken()).toBeNull();
    expect(await context.auth.accessToken()).toBeNull();
  });

  it("signs out by clearing the session, revoking the refresh token, and leaving via hosted logout", async () => {
    await signInAndComplete(context);
    await context.auth.signOut();

    const revoke = context.fetchImpl.mock.calls[1] as unknown as [string, RequestInit];
    expect(revoke[0]).toBe(`${CONFIG.cognitoDomain}/oauth2/revoke`);
    expect(context.assigned.at(-1)).toContain(`${CONFIG.cognitoDomain}/logout?`);
    expect(await context.auth.accessToken()).toBeNull();
  });
});
