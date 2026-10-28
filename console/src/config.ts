/** Deployment-specific values, written to /config.json by the stack at deploy time. */
export interface RuntimeConfig {
  apiUrl: string;
  region: string;
  cognitoDomain: string;
  clientId: string;
}

export async function loadConfig(fetchFn: typeof fetch = fetch): Promise<RuntimeConfig> {
  const response = await fetchFn("/config.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("The console configuration could not be loaded.");
  }
  return parseConfig(await response.json());
}

export function parseConfig(raw: unknown): RuntimeConfig {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("The console configuration is invalid.");
  }
  const value = raw as Record<string, unknown>;
  const config = {
    apiUrl: requireHttpsUrl(value.apiUrl, "apiUrl"),
    region: requireString(value.region, "region"),
    cognitoDomain: requireHttpsUrl(value.cognitoDomain, "cognitoDomain"),
    clientId: requireString(value.clientId, "clientId"),
  };
  return { ...config, apiUrl: config.apiUrl.replace(/\/+$/, ""), cognitoDomain: config.cognitoDomain.replace(/\/+$/, "") };
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`The console configuration is missing ${name}.`);
  }
  return value;
}

function requireHttpsUrl(value: unknown, name: string): string {
  const text = requireString(value, name);
  if (new URL(text).protocol !== "https:") {
    throw new Error(`The console configuration value ${name} must use https.`);
  }
  return text;
}
