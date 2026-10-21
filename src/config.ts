import { isLoopback } from "./services/ssl.js";
import type { DatabaseOptions } from "./services/database.js";
import { parsePolicyConfig, type PolicyConfig } from "./config/policy.js";
import { isEmptyPolicy } from "./auth/policy.js";
import { parseDegradedConfig } from "./config/degraded.js";
import { parseJwtConfig, type JwtConfig } from "./config/jwt.js";

const PREFIX = "STEAMPIPE_MCP_";

/**
 * Thrown by `loadConfig` for any invalid or unsafe setting. The message
 * always names the offending env var and never echoes a secret value
 * (token, connection string password) back to the caller.
 */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export interface ServerConfig {
  transport: "stdio" | "http";
  db: Omit<DatabaseOptions, "connectionString" | "exposeConnectionDetails"> & { connectionString: string };
  http: {
    host: string;
    port: number;
    path: string;
    publicUrl?: URL;
    allowedOrigins: string[];
    allowedHosts: string[];
    maxBodyBytes: number;
    rateLimitPerMin: number;
    // Hop count or boolean for Express's `trust proxy` setting. Consumed by
    // Task 7 (rate limiting keyed by client IP behind a proxy).
    trustProxy?: number | boolean;
  };
  auth: {
    mode: "none" | "token" | "google" | "jwt";
    token?: string;
    googleClientId?: string;
    allowedEmails: string[];
    allowedDomains: string[];
    // Google mode: start even when discovery fails, retrying it in the
    // background (STEAMPIPE_MCP_ALLOW_DEGRADED_START). Parsed in http mode
    // only; unset means false.
    allowDegradedStart?: boolean;
    // AUTH_MODE=jwt settings, parsed in http mode only.
    jwt?: JwtConfig;
  };
  allowInsecureRemote: boolean;
  // Identity policy (REQUIRED_CLAIMS, ALLOWED_SUBJECTS, SUBJECT_PREFIXES),
  // parsed in http mode only. Consumed by the verifier adapters.
  policy?: PolicyConfig;
}

const DEFAULT_CONNECTION_STRING = "postgresql://steampipe@localhost:9193/steampipe";
const DEFAULT_HTTP_HOST = "127.0.0.1";
const DEFAULT_HTTP_PORT = 27123;
const DEFAULT_HTTP_PATH = "/mcp";
const DEFAULT_MAX_BODY_BYTES = 1048576;
const DEFAULT_RATE_LIMIT_PER_MIN = 60;
const DEFAULT_STATEMENT_TIMEOUT_MS = 120000;
const DEFAULT_POOL_MAX = 20;
const DEFAULT_MAX_ROWS_HTTP = 10000;
const DEFAULT_MAX_ROWS_STDIO = 0;
const MIN_AUTH_TOKEN_LENGTH = 32;

function raw(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[`${PREFIX}${name}`];
  return value === undefined || value === "" ? undefined : value;
}

/**
 * Integer parse shared by every numeric setting (R1 + Task 1 review + R12).
 * `min` is 0 for settings where 0 is a meaningful value (MAX_ROWS: unlimited)
 * and 1 for settings where 0 would silently disable the feature it bounds
 * (body size, rate limit, statement timeout - R12).
 */
function parseIntWithMin(env: NodeJS.ProcessEnv, name: string, defaultValue: number, min: 0 | 1): number {
  const value = raw(env, name);
  if (value === undefined) {
    return defaultValue;
  }
  const description = min === 0 ? "a non-negative integer" : `an integer >= ${min}`;
  if (!/^\d+$/.test(value.trim())) {
    throw new ConfigError(`${PREFIX}${name} must be ${description}, got ${JSON.stringify(value)}`);
  }
  const parsed = Number(value);
  if (parsed < min) {
    throw new ConfigError(`${PREFIX}${name} must be ${description}, got ${parsed}`);
  }
  return parsed;
}

function parseNonNegativeInt(env: NodeJS.ProcessEnv, name: string, defaultValue: number): number {
  return parseIntWithMin(env, name, defaultValue, 0);
}

function parsePort(env: NodeJS.ProcessEnv, name: string, defaultValue: number): number {
  const port = parseIntWithMin(env, name, defaultValue, 1);
  if (port > 65535) {
    throw new ConfigError(`${PREFIX}${name} must be between 1 and 65535, got ${port}`);
  }
  return port;
}

function parseBool(env: NodeJS.ProcessEnv, name: string, defaultValue: boolean): boolean {
  const value = raw(env, name);
  if (value === undefined) {
    return defaultValue;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  throw new ConfigError(`${PREFIX}${name} must be "true" or "false", got ${JSON.stringify(value)}`);
}

function parseCsv(env: NodeJS.ProcessEnv, name: string): string[] {
  const value = raw(env, name);
  if (value === undefined) {
    return [];
  }
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * Normalise each ALLOWED_ORIGINS entry to the serialised origin a browser
 * sends (`https://App.example.com/` -> `https://app.example.com`), so the
 * exact-match Origin check is not defeated by case, a trailing slash or a
 * default port. The literal `null` is kept as-is. An entry whose origin is
 * opaque (`new URL("app.example.com:443").origin` is "null") is rejected
 * rather than silently allowlisting `Origin: null`.
 */
function parseOrigins(env: NodeJS.ProcessEnv): string[] {
  return parseCsv(env, "ALLOWED_ORIGINS").map((entry) => {
    if (entry === "null") {
      return entry;
    }
    let origin: string;
    try {
      origin = new URL(entry).origin;
    } catch {
      origin = "null";
    }
    if (origin === "null") {
      throw new ConfigError(
        `${PREFIX}ALLOWED_ORIGINS entries must be origins like "https://app.example.com" (or the literal null), ` +
          `got ${JSON.stringify(entry)}`,
      );
    }
    return origin;
  });
}

/** ALLOWED_HOSTS entries are `host` or `host:port`, never URLs or paths. */
function parseHosts(env: NodeJS.ProcessEnv): string[] {
  const hosts = parseCsv(env, "ALLOWED_HOSTS");
  for (const entry of hosts) {
    if (entry.includes("://") || entry.includes("/")) {
      throw new ConfigError(
        `${PREFIX}ALLOWED_HOSTS entries must be a hostname or hostname:port without a scheme or path, ` +
          `got ${JSON.stringify(entry)}`,
      );
    }
  }
  return hosts;
}

function parseCsvLower(env: NodeJS.ProcessEnv, name: string): string[] {
  return parseCsv(env, name).map((entry) => entry.toLowerCase());
}

function parseTrustProxy(env: NodeJS.ProcessEnv): number | boolean | undefined {
  const value = raw(env, "TRUST_PROXY");
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "true") return true;
  if (trimmed === "false") return false;
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  throw new ConfigError(
    `${PREFIX}TRUST_PROXY must be "true", "false", or a non-negative integer hop count, got ${JSON.stringify(value)}`,
  );
}

function parsePublicUrl(env: NodeJS.ProcessEnv): URL | undefined {
  const value = raw(env, "PUBLIC_URL");
  if (value === undefined) {
    return undefined;
  }
  // The raw value may carry userinfo (e.g. a password) and must never be
  // echoed back in an error message. Syntactic validity is checked
  // regardless of transport (a malformed URL is just a bad setting); the
  // https-required check is applied separately and only in http mode (R11).
  try {
    return new URL(value);
  } catch {
    throw new ConfigError(`${PREFIX}PUBLIC_URL must be a valid URL`);
  }
}

/** HTTP-only (R11): a non-loopback PUBLIC_URL must use https. */
function assertPublicUrlIsSecure(publicUrl: URL | undefined): void {
  if (!publicUrl) {
    return;
  }
  if (publicUrl.protocol !== "https:" && !isLoopback(publicUrl.hostname)) {
    throw new ConfigError(
      `${PREFIX}PUBLIC_URL must use https unless the host is loopback, ` +
        `got protocol ${JSON.stringify(publicUrl.protocol)} for host ${JSON.stringify(publicUrl.hostname)}`,
    );
  }
}

function resolveConnectionString(env: NodeJS.ProcessEnv, argv: string[]): string {
  // Empty-string fallback preserved from the pre-config index.ts behaviour:
  // an empty argv[2] or env var is treated as "not set", not as an explicit
  // empty connection string.
  return argv[2] || env.STEAMPIPE_MCP_WORKSPACE_DATABASE || DEFAULT_CONNECTION_STRING;
}

function resolveMaxRows(env: NodeJS.ProcessEnv, transport: "stdio" | "http"): number {
  const defaultValue = transport === "http" ? DEFAULT_MAX_ROWS_HTTP : DEFAULT_MAX_ROWS_STDIO;
  return parseNonNegativeInt(env, "MAX_ROWS", defaultValue);
}

function parseTransport(env: NodeJS.ProcessEnv): "stdio" | "http" {
  const value = raw(env, "TRANSPORT");
  if (value === undefined) {
    return "stdio";
  }
  if (value !== "stdio" && value !== "http") {
    throw new ConfigError(`${PREFIX}TRANSPORT must be "stdio" or "http", got ${JSON.stringify(value)}`);
  }
  return value;
}

function parseAuthMode(env: NodeJS.ProcessEnv): ServerConfig["auth"]["mode"] {
  const value = raw(env, "AUTH_MODE");
  if (value === undefined) {
    return "none";
  }
  if (value !== "none" && value !== "token" && value !== "google" && value !== "jwt") {
    throw new ConfigError(
      `${PREFIX}AUTH_MODE must be "none", "token", "google", or "jwt", got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

/**
 * R6: a policy is only worth configuring if something enforces it. Only
 * google mode does; in none or token mode it would be silently ignored, so
 * refuse to start instead. Names the variables that are set, never their
 * values.
 */
function assertPolicyEnforceable(policy: PolicyConfig, authMode: ServerConfig["auth"]["mode"]): void {
  if (isEmptyPolicy(policy) || authMode === "google") {
    return;
  }
  const names = [
    Object.keys(policy.requiredClaims).length > 0 && "REQUIRED_CLAIMS",
    policy.allowedSubjects.size > 0 && "ALLOWED_SUBJECTS",
    policy.subjectPrefixes.length > 0 && "SUBJECT_PREFIXES",
  ]
    .filter((name): name is string => name !== false)
    .map((name) => `${PREFIX}${name}`);
  throw new ConfigError(
    `${names.join(", ")} set, but ${PREFIX}AUTH_MODE=${authMode} cannot enforce an identity policy; ` +
      `use ${PREFIX}AUTH_MODE=google or unset the policy`,
  );
}

/**
 * Load and validate the full server configuration from the environment and
 * argv in one place. Defaults are safe-by-default: a non-loopback HTTP bind
 * is refused unless auth is enabled or `ALLOW_INSECURE_REMOTE` is set, and a
 * non-loopback `PUBLIC_URL` must use https. Throws `ConfigError` - naming the
 * offending env var, never echoing a secret value - for any invalid setting.
 */
export function loadConfig(env: NodeJS.ProcessEnv, argv: string[]): ServerConfig {
  const transport = parseTransport(env);

  const db = {
    connectionString: resolveConnectionString(env, argv),
    maxRows: resolveMaxRows(env, transport),
    // R12: unlike MAX_ROWS, 0 would silently disable the statement timeout,
    // so the minimum is 1.
    statementTimeoutMs: parseIntWithMin(env, "STATEMENT_TIMEOUT_MS", DEFAULT_STATEMENT_TIMEOUT_MS, 1),
    poolMax: DEFAULT_POOL_MAX,
  };

  const httpHost = raw(env, "HTTP_HOST") ?? DEFAULT_HTTP_HOST;
  const publicUrl = parsePublicUrl(env);

  const http: ServerConfig["http"] = {
    host: httpHost,
    port: parsePort(env, "HTTP_PORT", DEFAULT_HTTP_PORT),
    path: raw(env, "HTTP_PATH") ?? DEFAULT_HTTP_PATH,
    publicUrl,
    allowedOrigins: parseOrigins(env),
    allowedHosts: parseHosts(env),
    // R12: 0 would silently accept unbounded bodies / disable rate limiting,
    // so the minimum is 1.
    maxBodyBytes: parseIntWithMin(env, "MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES, 1),
    rateLimitPerMin: parseIntWithMin(env, "RATE_LIMIT_PER_MIN", DEFAULT_RATE_LIMIT_PER_MIN, 1),
    trustProxy: parseTrustProxy(env),
  };

  const authMode = parseAuthMode(env);
  const allowedEmails = parseCsvLower(env, "ALLOWED_EMAILS");
  const allowedDomains = parseCsvLower(env, "ALLOWED_DOMAINS");
  const token = raw(env, "AUTH_TOKEN");
  const googleClientId = raw(env, "GOOGLE_CLIENT_ID");
  const allowInsecureRemote = parseBool(env, "ALLOW_INSECURE_REMOTE", false);
  let policy: PolicyConfig | undefined;
  let allowDegradedStart: boolean | undefined;
  let jwt: JwtConfig | undefined;

  // R11: stdio never binds a port or serves auth/PUBLIC_URL, so none of
  // these settings can make stdio unsafe or unable to start. Scope all of
  // them to http mode so a stray HTTP_HOST/AUTH_MODE/PUBLIC_URL left over in
  // a stdio user's env never blocks startup.
  if (transport === "http") {
    assertPublicUrlIsSecure(publicUrl);
    policy = parsePolicyConfig(env);
    assertPolicyEnforceable(policy, authMode);
    allowDegradedStart = parseDegradedConfig(env).allowDegradedStart;

    if (authMode === "token") {
      if (!token || token.length < MIN_AUTH_TOKEN_LENGTH) {
        throw new ConfigError(
          `${PREFIX}AUTH_TOKEN must be set and at least ${MIN_AUTH_TOKEN_LENGTH} characters when ${PREFIX}AUTH_MODE=token`,
        );
      }
    }

    if (authMode === "google") {
      if (!publicUrl) {
        throw new ConfigError(`${PREFIX}PUBLIC_URL is required when ${PREFIX}AUTH_MODE=google`);
      }
      if (!googleClientId) {
        throw new ConfigError(`${PREFIX}GOOGLE_CLIENT_ID is required when ${PREFIX}AUTH_MODE=google`);
      }
      if (allowedEmails.length === 0 && allowedDomains.length === 0) {
        throw new ConfigError(
          `${PREFIX}ALLOWED_EMAILS or ${PREFIX}ALLOWED_DOMAINS must be set when ${PREFIX}AUTH_MODE=google`,
        );
      }
    }

    if (authMode === "jwt") {
      if (!publicUrl) {
        throw new ConfigError(`${PREFIX}PUBLIC_URL is required when ${PREFIX}AUTH_MODE=jwt`);
      }
      jwt = parseJwtConfig(env, publicUrl);
    }

    if (!isLoopback(httpHost) && authMode === "none" && !allowInsecureRemote) {
      throw new ConfigError(
        `Refusing to bind a non-loopback ${PREFIX}HTTP_HOST with ${PREFIX}AUTH_MODE=none; ` +
          `set ${PREFIX}ALLOW_INSECURE_REMOTE=true to override (not recommended), or enable auth`,
      );
    }
  }

  return {
    transport,
    db,
    http,
    auth: {
      mode: authMode,
      token,
      googleClientId,
      allowedEmails,
      allowedDomains,
      allowDegradedStart,
      jwt,
    },
    allowInsecureRemote,
    policy,
  };
}
