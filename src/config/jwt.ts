import { isEmptyPolicy, type IdentityPolicy } from "../auth/policy.js";
import { ConfigError } from "../config.js";
import { isLoopback } from "../services/ssl.js";
import { policyFromValues, type PolicyConfig, type PolicyValues } from "./policy.js";

/**
 * `rfc9068` (the default): RFC 9068 access tokens only. `lenient` (R27):
 * also GitHub Actions / Entra v2 style tokens, see `createJwtVerifier`.
 */
export type JwtProfile = "rfc9068" | "lenient";

/** One trusted issuer: its identifier and the claims settings for its tokens. */
export interface JwtIssuerConfig {
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
  /** Listed in the PRM document's `authorization_servers`. */
  advertise: boolean;
  /**
   * This issuer's identity policy, replacing the global one. Absent when
   * the entry sets none of the policy fields, so the global policy applies.
   */
  policy?: IdentityPolicy;
  /** Present only for `lenient`; absent means `rfc9068`. */
  profile?: "lenient";
}

export interface JwtConfig {
  /** In config order; at least one, at least one advertised, no duplicates. */
  issuers: JwtIssuerConfig[];
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
// The lenient profile's default: also the generic "JWT" that GitHub Actions
// and Entra v2 put on their access tokens. A missing typ is still refused.
const LENIENT_ACCEPTED_TYP = [...DEFAULT_ACCEPTED_TYP, "jwt"];
const PROFILES: readonly JwtProfile[] = ["rfc9068", "lenient"];
const DEFAULT_JWKS_COOLDOWN_S = 30;
const MAX_JWKS_COOLDOWN_S = 3600;
// More skew than this is a broken clock to fix (NTP), not leeway to grant (R26).
const MAX_CLOCK_SKEW_S = 300;
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
 * An issuer is an exact identifier string (RFC 8414 §2): https, or http on
 * a loopback host only, with no query or fragment, and no `|`, which
 * separates issuer and subject in the principal `iss|sub` (R26). Errors name
 * `name` and never echo the value, which could carry userinfo.
 */
function validateIssuer(value: string, name: string): string {
  // Checked first: a `|` in the host would otherwise fail as an invalid URL.
  if (value.includes("|")) {
    throw new ConfigError(`${name} must not contain "|"`);
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

function validateAlgorithms(algorithms: string[], name: string): string[] {
  for (const alg of algorithms) {
    if (!SUPPORTED_ALGORITHMS.has(alg)) {
      throw new ConfigError(
        `${name} entries must be asymmetric JWS algorithms (${[...SUPPORTED_ALGORITHMS].join(", ")}); ` +
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

const ISSUER_FIELDS = new Set([
  "issuer",
  "audiences",
  "algorithms",
  "acceptedTyp",
  "clockSkewS",
  "maxTokenAgeS",
  "advertise",
  "requiredClaims",
  "allowedSubjects",
  "subjectPrefixes",
  "profile",
]);

const POLICY_FIELDS = ["requiredClaims", "allowedSubjects", "subjectPrefixes"] as const;

type IssuerDefaults = Omit<JwtIssuerConfig, "issuer" | "advertise" | "policy" | "profile"> & {
  /** Whether `JWT_ACCEPTED_TYP` was set, which keeps the lenient `typ` default out. */
  acceptedTypExplicit: boolean;
};

/** Errors name `name` and never echo the value. */
function parseProfile(value: unknown, name: string): JwtProfile {
  if (typeof value !== "string" || !(PROFILES as readonly string[]).includes(value)) {
    throw new ConfigError(`${name} must be "rfc9068" or "lenient"`);
  }
  return value as JwtProfile;
}

/**
 * R27: a lenient issuer's tokens need not carry `client_id` or an RFC 9068
 * `typ`, so the audience and the identity policy are the only per-principal
 * controls left. Refuse to start unless its effective policy (its own
 * override, else the global one) has at least one rule.
 */
function assertLenientPolicy(effective: IdentityPolicy | undefined, name: string): void {
  if (!effective || isEmptyPolicy(effective)) {
    throw new ConfigError(
      `${name} "lenient" requires a non-empty identity policy for this issuer ` +
        `(e.g. subjectPrefixes / requiredClaims, or the global ${PREFIX}SUBJECT_PREFIXES / ${PREFIX}REQUIRED_CLAIMS)`,
    );
  }
}

/** The issuer fields a profile decides: `profile` itself (lenient only) and the default `typ` list. */
function profileFields(
  profile: JwtProfile,
  acceptedTyp: string[] | undefined,
  defaults: IssuerDefaults,
): Pick<JwtIssuerConfig, "acceptedTyp" | "profile"> {
  const lenient = profile === "lenient";
  return {
    acceptedTyp: acceptedTyp ?? (lenient && !defaults.acceptedTypExplicit ? LENIENT_ACCEPTED_TYP : defaults.acceptedTyp),
    ...(lenient && { profile: "lenient" as const }),
  };
}

function stringList(value: unknown, name: string): string[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((entry) => typeof entry === "string" && entry.length > 0)
  ) {
    throw new ConfigError(`${name} must be a non-empty array of non-empty strings`);
  }
  return value as string[];
}

function seconds(value: unknown, name: string, max?: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || (max !== undefined && value > max)) {
    const range = max === undefined ? "an integer >= 0" : `an integer between 0 and ${max}`;
    throw new ConfigError(`${name} must be ${range}`);
  }
  return value;
}

/**
 * The entry's own policy, or `undefined` when it sets no policy field. It
 * replaces the global policy as a whole: a field the entry leaves out is
 * empty, never inherited. Validated with the global parser's limits. An
 * override with no rules is refused, since it would silently drop the
 * global policy for this issuer.
 */
function parseIssuerPolicy(fields: Record<string, unknown>, at: string): IdentityPolicy | undefined {
  const present = POLICY_FIELDS.filter((key) => Object.hasOwn(fields, key));
  if (present.length === 0) {
    return undefined;
  }
  const values: PolicyValues = {};
  for (const key of present) {
    // A JSON null stays null, so it is validated (and refused), not unset.
    values[key] = fields[key];
  }
  const policy = policyFromValues(values, (field) => `${at}.${field}`);
  if (isEmptyPolicy(policy)) {
    throw new ConfigError(
      `${at} policy fields set no rules; remove them to use the global policy, or list at least one rule`,
    );
  }
  return policy;
}

/**
 * One `JWT_ISSUERS` entry. Unknown fields are refused, so a misspelt field
 * cannot silently fall back to its default; missing ones take `defaults`
 * (the single-issuer env values). Errors name the entry by index only.
 */
function parseIssuerEntry(
  entry: unknown,
  index: number,
  defaults: IssuerDefaults,
  globalPolicy: PolicyConfig,
): JwtIssuerConfig {
  const at = `${PREFIX}JWT_ISSUERS[${index}]`;
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    throw new ConfigError(`${at} must be an object`);
  }
  const fields = entry as Record<string, unknown>;
  for (const key of Object.keys(fields)) {
    if (!ISSUER_FIELDS.has(key)) {
      // Field names come from the operator's config, but bound them anyway.
      throw new ConfigError(`${at} has an unknown field ${JSON.stringify(key.slice(0, 64))}`);
    }
  }
  if (typeof fields.issuer !== "string" || fields.issuer.length === 0) {
    throw new ConfigError(`${at}.issuer must be a non-empty string`);
  }
  const has = (key: string) => Object.hasOwn(fields, key);
  if (has("advertise") && typeof fields.advertise !== "boolean") {
    throw new ConfigError(`${at}.advertise must be a boolean`);
  }
  const policy = parseIssuerPolicy(fields, at);
  const profile = has("profile") ? parseProfile(fields.profile, `${at}.profile`) : "rfc9068";
  if (profile === "lenient") {
    assertLenientPolicy(policy ?? globalPolicy, `${at}.profile`);
  }
  return {
    issuer: validateIssuer(fields.issuer, `${at}.issuer`),
    audiences: has("audiences") ? stringList(fields.audiences, `${at}.audiences`) : defaults.audiences,
    algorithms: has("algorithms")
      ? validateAlgorithms(stringList(fields.algorithms, `${at}.algorithms`), `${at}.algorithms`)
      : defaults.algorithms,
    ...profileFields(
      profile,
      has("acceptedTyp") ? stringList(fields.acceptedTyp, `${at}.acceptedTyp`).map((t) => t.toLowerCase()) : undefined,
      defaults,
    ),
    clockSkewS: has("clockSkewS")
      ? seconds(fields.clockSkewS, `${at}.clockSkewS`, MAX_CLOCK_SKEW_S)
      : defaults.clockSkewS,
    maxTokenAgeS: has("maxTokenAgeS") ? seconds(fields.maxTokenAgeS, `${at}.maxTokenAgeS`) : defaults.maxTokenAgeS,
    advertise: has("advertise") ? (fields.advertise as boolean) : true,
    ...(policy && { policy }),
  };
}

function issuerFromDefaults(issuer: string, defaults: IssuerDefaults): JwtIssuerConfig {
  const { acceptedTypExplicit: _, ...settings } = defaults;
  return { issuer, ...settings, advertise: true };
}

/**
 * `JWT_ISSUER` (one issuer) or `JWT_ISSUERS` (a JSON array of entries),
 * never both. Duplicate issuers, compared as exact strings, are refused,
 * and at least one issuer must be advertised in the PRM document.
 *
 * `JWT_PROFILE` applies to `JWT_ISSUER` only. Unlike the other single-issuer
 * settings it is not a default for `JWT_ISSUERS` entries, which set
 * `profile` each (R27: lenient is opt-in per issuer), so setting it with
 * `JWT_ISSUERS` is refused rather than silently ignored.
 */
function parseIssuers(env: NodeJS.ProcessEnv, defaults: IssuerDefaults, globalPolicy: PolicyConfig): JwtIssuerConfig[] {
  const single = raw(env, "JWT_ISSUER");
  const many = raw(env, "JWT_ISSUERS");
  const profileEnv = raw(env, "JWT_PROFILE");
  const name = `${PREFIX}JWT_ISSUERS`;
  if (single !== undefined && many !== undefined) {
    throw new ConfigError(`${PREFIX}JWT_ISSUER and ${name} are mutually exclusive`);
  }
  if (single !== undefined) {
    const profileName = `${PREFIX}JWT_PROFILE`;
    const profile = profileEnv === undefined ? "rfc9068" : parseProfile(profileEnv, profileName);
    if (profile === "lenient") {
      assertLenientPolicy(globalPolicy, profileName);
    }
    const cfg = issuerFromDefaults(validateIssuer(single, `${PREFIX}JWT_ISSUER`), defaults);
    return [{ ...cfg, ...profileFields(profile, undefined, defaults) }];
  }
  if (many === undefined) {
    throw new ConfigError(`${PREFIX}JWT_ISSUER or ${name} is required when ${PREFIX}AUTH_MODE=jwt`);
  }
  if (profileEnv !== undefined) {
    throw new ConfigError(`${PREFIX}JWT_PROFILE applies to ${PREFIX}JWT_ISSUER only; set "profile" per ${name} entry`);
  }
  let entries: unknown;
  try {
    entries = JSON.parse(many);
  } catch {
    // The parser's message quotes the input, which could carry credentials.
    throw new ConfigError(`${name} must be valid JSON`);
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new ConfigError(`${name} must be a non-empty JSON array of issuer objects`);
  }
  const issuers = entries.map((entry, index) => parseIssuerEntry(entry, index, defaults, globalPolicy));
  const seen = new Set<string>();
  issuers.forEach((cfg, index) => {
    if (seen.has(cfg.issuer)) {
      throw new ConfigError(`${name}[${index}].issuer duplicates an earlier entry`);
    }
    seen.add(cfg.issuer);
  });
  if (!issuers.some((cfg) => cfg.advertise)) {
    throw new ConfigError(`${name} must have at least one entry with advertise: true`);
  }
  return issuers;
}

/**
 * Parse the `AUTH_MODE=jwt` settings. `publicUrl` is the parsed PUBLIC_URL;
 * its canonical href is the default audience, the same value the PRM
 * document advertises as `resource` (R12). The single-issuer claims
 * variables (except `JWT_PROFILE`) are the defaults for every `JWT_ISSUERS`
 * entry. `globalPolicy` is the parsed global identity policy, which a
 * lenient issuer without its own needs to be non-empty. Throws
 * `ConfigError` naming the variable, never echoing its value.
 */
export function parseJwtConfig(env: NodeJS.ProcessEnv, publicUrl: URL, globalPolicy: PolicyConfig): JwtConfig {
  const defaults: IssuerDefaults = {
    audiences: nonEmptyCsv(env, "JWT_AUDIENCES", [publicUrl.href]),
    algorithms: validateAlgorithms(nonEmptyCsv(env, "JWT_ALGORITHMS", DEFAULT_ALGORITHMS), `${PREFIX}JWT_ALGORITHMS`),
    acceptedTyp: nonEmptyCsv(env, "JWT_ACCEPTED_TYP", DEFAULT_ACCEPTED_TYP).map((t) => t.toLowerCase()),
    acceptedTypExplicit: raw(env, "JWT_ACCEPTED_TYP") !== undefined,
    clockSkewS: int(env, "JWT_CLOCK_SKEW_S", 0, 0, MAX_CLOCK_SKEW_S),
    maxTokenAgeS: int(env, "JWT_MAX_TOKEN_AGE_S", 0, 0),
  };
  return {
    issuers: parseIssuers(env, defaults, globalPolicy),
    jwksCooldownS: int(env, "JWT_JWKS_COOLDOWN_S", DEFAULT_JWKS_COOLDOWN_S, 1, MAX_JWKS_COOLDOWN_S),
    scopesSupported: parseScopes(env, "JWT_SCOPES_SUPPORTED"),
    challengeScope: parseScopes(env, "JWT_CHALLENGE_SCOPE"),
    allowedHosts: parseAllowedHosts(env),
  };
}
