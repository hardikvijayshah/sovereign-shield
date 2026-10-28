/**
 * Cognito hosted sign-in using the OAuth 2.0 authorization code grant with
 * PKCE (RFC 7636). The console is a public client: there is no client secret.
 *
 * Tokens are kept in sessionStorage, so they do not outlive the browser tab.
 * The CloudFront Content-Security-Policy allows only same-origin scripts,
 * which limits exposure of stored tokens to injected script.
 */
import type { RuntimeConfig } from "./config";

const SESSION_KEY = "sovereign-shield.session";
const PENDING_KEY = "sovereign-shield.pending-sign-in";
const REFRESH_MARGIN_MS = 60_000;

export interface Session {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresAt: number;
}

interface PendingSignIn {
  state: string;
  verifier: string;
  returnTo: string;
}

export interface IdentityClaims {
  email?: string;
  sub?: string;
}

export interface Navigator {
  origin: string;
  assign(url: string): void;
}

export class SignInRequiredError extends Error {
  constructor() {
    super("Sign-in is required.");
  }
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomString(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

/** Only same-origin paths are accepted, so a crafted state cannot redirect off-site. */
export function safeReturnPath(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) {
    return "/";
  }
  return value;
}

export class Auth {
  constructor(
    private readonly config: RuntimeConfig,
    private readonly storage: Storage = sessionStorage,
    private readonly navigator: Navigator = {
      origin: window.location.origin,
      assign: (url) => window.location.assign(url),
    },
    private readonly fetchFn: typeof fetch = (...args) => fetch(...args),
    private readonly now: () => number = Date.now,
  ) {}

  get redirectUri(): string {
    return `${this.navigator.origin}/callback`;
  }

  async signIn(returnTo = "/"): Promise<never> {
    const pending: PendingSignIn = {
      state: randomString(),
      verifier: randomString(48),
      returnTo: safeReturnPath(returnTo),
    };
    this.storage.setItem(PENDING_KEY, JSON.stringify(pending));
    const parameters = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.redirectUri,
      scope: "openid email profile",
      state: pending.state,
      code_challenge: await pkceChallenge(pending.verifier),
      code_challenge_method: "S256",
    });
    this.navigator.assign(`${this.config.cognitoDomain}/oauth2/authorize?${parameters}`);
    throw new SignInRequiredError();
  }

  /** Complete the redirect from the hosted sign-in page; returns the path to resume. */
  async completeSignIn(search: string): Promise<string> {
    const parameters = new URLSearchParams(search);
    const pendingRaw = this.storage.getItem(PENDING_KEY);
    this.storage.removeItem(PENDING_KEY);
    if (parameters.get("error")) {
      throw new Error("Sign-in was not completed.");
    }
    const pending = pendingRaw ? (JSON.parse(pendingRaw) as PendingSignIn) : null;
    const code = parameters.get("code");
    if (!pending || !code || parameters.get("state") !== pending.state) {
      throw new Error("The sign-in response did not match this browser session. Please sign in again.");
    }
    const session = await this.requestTokens({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: this.redirectUri,
      code_verifier: pending.verifier,
    });
    this.storage.setItem(SESSION_KEY, JSON.stringify(session));
    return safeReturnPath(pending.returnTo);
  }

  /** Return a valid access token, refreshing it if needed, or null if sign-in is required. */
  async accessToken(): Promise<string | null> {
    const session = this.session();
    if (!session) {
      return null;
    }
    if (session.expiresAt - REFRESH_MARGIN_MS > this.now()) {
      return session.accessToken;
    }
    if (!session.refreshToken) {
      this.storage.removeItem(SESSION_KEY);
      return null;
    }
    try {
      const refreshed = await this.requestTokens({
        grant_type: "refresh_token",
        client_id: this.config.clientId,
        refresh_token: session.refreshToken,
      });
      const next = { ...refreshed, refreshToken: refreshed.refreshToken ?? session.refreshToken };
      this.storage.setItem(SESSION_KEY, JSON.stringify(next));
      return next.accessToken;
    } catch {
      this.storage.removeItem(SESSION_KEY);
      return null;
    }
  }

  /** Identity claims for display only; the API verifies every token it receives. */
  claims(): IdentityClaims {
    const session = this.session();
    if (!session) {
      return {};
    }
    try {
      const payload = session.idToken.split(".")[1] ?? "";
      const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
      const claims = JSON.parse(json) as Record<string, unknown>;
      return {
        email: typeof claims.email === "string" ? claims.email : undefined,
        sub: typeof claims.sub === "string" ? claims.sub : undefined,
      };
    } catch {
      return {};
    }
  }

  async signOut(): Promise<void> {
    const session = this.session();
    this.storage.removeItem(SESSION_KEY);
    if (session?.refreshToken) {
      try {
        await this.fetchFn(`${this.config.cognitoDomain}/oauth2/revoke`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: session.refreshToken, client_id: this.config.clientId }),
        });
      } catch {
        // Revocation is best-effort; the local session is already cleared.
      }
    }
    const parameters = new URLSearchParams({
      client_id: this.config.clientId,
      logout_uri: `${this.navigator.origin}/`,
    });
    this.navigator.assign(`${this.config.cognitoDomain}/logout?${parameters}`);
  }

  private session(): Session | null {
    const raw = this.storage.getItem(SESSION_KEY);
    if (!raw) {
      return null;
    }
    try {
      return JSON.parse(raw) as Session;
    } catch {
      this.storage.removeItem(SESSION_KEY);
      return null;
    }
  }

  private async requestTokens(form: Record<string, string>): Promise<Session> {
    const response = await this.fetchFn(`${this.config.cognitoDomain}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form),
    });
    if (!response.ok) {
      throw new Error("Token request failed.");
    }
    const body = (await response.json()) as Record<string, unknown>;
    if (typeof body.access_token !== "string" || typeof body.id_token !== "string") {
      throw new Error("Token response was incomplete.");
    }
    return {
      accessToken: body.access_token,
      idToken: body.id_token,
      refreshToken: typeof body.refresh_token === "string" ? body.refresh_token : undefined,
      expiresAt: this.now() + Number(body.expires_in ?? 3600) * 1000,
    };
  }
}
