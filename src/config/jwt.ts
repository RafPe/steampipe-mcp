import { ConfigError } from "../config.js";
import { isLoopback } from "../services/ssl.js";

export interface JwtConfig {
  /** Exact issuer identifier, kept as written. */
  issuer: string;
  /** Accepted `aud` values, compared as exact strings. */
  audiences: string[];
  algorithms: string[];
  /** Accepted header `typ` values, lowercased (compared case-insensitively). */
  acceptedTyp: string[];
  clockSkewS: number;
  /** 0 means off. */
  maxTokenAgeS: number;
  jwksCooldownS: number;
  scopesSupported: string[];
  challengeScope: string[];
  /** Extra https hosts discovery may point at (the issuer host is always allowed). */
  allowedHosts: string[];
}

const PREFIX = "STEAMPIPE_MCP_";
const DEFAULT_ALGORITHMS = ["RS256", "ES256"];
// RFC 9068 §4: "at+jwt", with the "application/" prefix optional (RFC 7515 §4.1.9).
const DEFAULT_ACCEPTED_TYP = ["at+jwt", "application/at+jwt"];
const DEFAULT_JWKS_COOLDOWN_S = 30;
const MAX_JWKS_COOLDOWN_S = 3600;
// Asymmetric JWS algorithms only. HMAC (HS*) would let anyone holding the
// issuer's public key mint tokens, and `none` is no signature at all.
const SUPPORTED_ALGORITHMS = new Set([
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519",
]);
// RFC 6750 §3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

function raw(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[`${PREFIX}${name}`];
  return value === undefined || value === "" ? undefined : value;
}

/** Comma-separated list; `undefined` when unset, so callers can tell unset from empty. */
function csv(env: NodeJS.ProcessEnv, name: string): string[] | undefined {
  const value = raw(env, name);
  if (value === undefined) {
    return undefined;
  }
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function nonEmptyCsv(env: NodeJS.ProcessEnv, name: string, defaultValue: string[]): string[] {
  const list = csv(env, name);
  if (list === undefined) {
    return defaultValue;
  }
  if (list.length === 0) {
    throw new ConfigError(`${PREFIX}${name} must list at least one value`);
  }
  return list;
}

function int(env: NodeJS.ProcessEnv, name: string, defaultValue: number, min: number, max?: number): number {
  const value = raw(env, name);
  if (value === undefined) {
    return defaultValue;
  }
  const range = max === undefined ? `an integer >= ${min}` : `an integer between ${min} and ${max}`;
  const parsed = /^\d+$/.test(value.trim()) ? Number(value) : NaN;
  if (!Number.isSafeInteger(parsed) || parsed < min || (max !== undefined && parsed > max)) {
    throw new ConfigError(`${PREFIX}${name} must be ${range}`);
  }
  return parsed;
}

/**
 * The issuer is an exact identifier string (RFC 8414 §2): https, or http on
 * a loopback host only, with no query or fragment. Errors never echo the
 * value, which could carry userinfo.
 */
function parseIssuer(env: NodeJS.ProcessEnv): string {
  const name = `${PREFIX}JWT_ISSUER`;
  const value = raw(env, "JWT_ISSUER");
  if (value === undefined) {
    throw new ConfigError(`${name} is required when ${PREFIX}AUTH_MODE=jwt`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(`${name} must be a valid URL`);
  }
  if (url.username || url.password) {
    throw new ConfigError(`${name} must not contain credentials`);
  }
  if (url.search || url.hash || value.includes("?") || value.includes("#")) {
    throw new ConfigError(`${name} must not contain a query or fragment`);
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname))) {
    throw new ConfigError(`${name} must use https unless the host is loopback`);
  }
  return value;
}

function parseAlgorithms(env: NodeJS.ProcessEnv): string[] {
  const name = "JWT_ALGORITHMS";
  const algorithms = nonEmptyCsv(env, name, DEFAULT_ALGORITHMS);
  for (const alg of algorithms) {
    if (!SUPPORTED_ALGORITHMS.has(alg)) {
      throw new ConfigError(
        `${PREFIX}${name} entries must be asymmetric JWS algorithms (${[...SUPPORTED_ALGORITHMS].join(", ")}); ` +
          `none and HS* are refused`,
      );
    }
  }
  return algorithms;
}

function parseScopes(env: NodeJS.ProcessEnv, name: string): string[] {
  const scopes = csv(env, name) ?? [];
  for (const scope of scopes) {
    if (!SCOPE_TOKEN.test(scope)) {
      throw new ConfigError(`${PREFIX}${name} entries must be RFC 6750 scope tokens`);
    }
  }
  return scopes;
}

function parseAllowedHosts(env: NodeJS.ProcessEnv): string[] {
  const name = "JWT_ALLOWED_HOSTS";
  const hosts = csv(env, name) ?? [];
  for (const host of hosts) {
    if (host.includes("://") || host.includes("/")) {
      throw new ConfigError(`${PREFIX}${name} entries must be hostnames without a scheme or path`);
    }
  }
  return hosts;
}

/**
 * Parse the `AUTH_MODE=jwt` settings. `publicUrl` is the parsed PUBLIC_URL;
 * its canonical href is the default audience, the same value the PRM
 * document advertises as `resource` (R12). Throws `ConfigError` naming the
 * variable, never echoing its value.
 */
export function parseJwtConfig(env: NodeJS.ProcessEnv, publicUrl: URL): JwtConfig {
  return {
    issuer: parseIssuer(env),
    audiences: nonEmptyCsv(env, "JWT_AUDIENCES", [publicUrl.href]),
    algorithms: parseAlgorithms(env),
    acceptedTyp: nonEmptyCsv(env, "JWT_ACCEPTED_TYP", DEFAULT_ACCEPTED_TYP).map((t) => t.toLowerCase()),
    clockSkewS: int(env, "JWT_CLOCK_SKEW_S", 0, 0),
    maxTokenAgeS: int(env, "JWT_MAX_TOKEN_AGE_S", 0, 0),
    jwksCooldownS: int(env, "JWT_JWKS_COOLDOWN_S", DEFAULT_JWKS_COOLDOWN_S, 1, MAX_JWKS_COOLDOWN_S),
    scopesSupported: parseScopes(env, "JWT_SCOPES_SUPPORTED"),
    challengeScope: parseScopes(env, "JWT_CHALLENGE_SCOPE"),
    allowedHosts: parseAllowedHosts(env),
  };
}
