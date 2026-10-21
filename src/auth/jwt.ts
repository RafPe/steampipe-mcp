import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { errors, importJWK, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import { logger } from "../services/logger.js";
import type { TokenVerifier } from "./bearer.js";
import { VerifyError } from "./errors.js";
import { FetchRefused } from "./fetch-guard.js";
import { peekIssuer } from "./issuer-peek.js";
import { checkPolicy, isEmptyPolicy, PolicyViolation, type IdentityPolicy } from "./policy.js";
import { DEFAULT_INITIAL_DELAY_MS, DEFAULT_MAX_DELAY_MS } from "./retry-loader.js";

export interface IssuerConfig {
  issuer: string;
  audiences: string[];
  algorithms: string[];
  /** Accepted header `typ` values, compared case-insensitively. */
  acceptedTyp: string[];
  clockSkewS: number;
  /** 0 means off. */
  maxTokenAgeS: number;
  /** This issuer's identity policy; replaces `JwtVerifierOptions.policy` when set. */
  policy?: IdentityPolicy;
  /** Claims profile; absent means `rfc9068`. */
  profile?: "rfc9068" | "lenient";
}

export interface JwtVerifierOptions {
  issuers: IssuerConfig[];
  /** Identity policy for every issuer without its own. Absent or empty: none. */
  policy?: IdentityPolicy;
  /** The resource every accepted token is reported for (`AuthInfo.resource`). */
  publicUrl: URL;
  /** Key resolver per issuer, normally jose's `createRemoteJWKSet`. */
  keys: Map<string, JWTVerifyGetKey>;
  now?: () => number;
}

const SEGMENT = /^[A-Za-z0-9_-]+$/;
// Far past any real timestamp, short of anything that loses precision or
// overflows downstream (same bound as lib-go-sso's maxTimestampSeconds).
const MAX_TIMESTAMP_S = 2 ** 40;
const MAX_SUB_LENGTH = 256;
// RFC 9068 §2.2 mandatory claims (iss and aud are enforced by the
// issuer/audience options).
const REQUIRED_CLAIMS = ["exp", "sub", "iat", "client_id", "jti"];
// The lenient profile (R27): client_id and jti become optional.
const LENIENT_REQUIRED_CLAIMS = ["exp", "sub", "iat"];
// Lenient only: identifier claims that, when present, must be non-empty
// strings. client_id, azp, appid are also the clientId fallbacks, in order.
const LENIENT_OPTIONAL_STRINGS = ["client_id", "jti", "azp", "appid", "uti"];

/** The key resolver could not reach or use the issuer's JWKS. */
class KeysUnavailable extends Error {
  constructor() {
    super("JWKS unavailable");
    this.name = "KeysUnavailable";
  }
}

/** jose returned a key it will refuse inside `jwtVerify` (see `assertUsableKey`). */
class KeyUnusable extends Error {
  constructor() {
    super("JWKS key unusable");
    this.name = "KeyUnusable";
  }
}

// jose refuses smaller RSA keys only inside `jwtVerify`, with a TypeError.
const MIN_RSA_MODULUS_BITS = 2048;

/** Refuse, as `KeyUnusable`, an RSA key that jose would reject for its size. */
function assertUsableKey(key: unknown): void {
  const algorithm = (key as { algorithm?: { modulusLength?: unknown } } | null)?.algorithm;
  if (typeof algorithm?.modulusLength === "number" && algorithm.modulusLength < MIN_RSA_MODULUS_BITS) {
    throw new KeyUnusable();
  }
}

/**
 * The issuer's JWKS holds a key that matched the token but cannot be used:
 * Web Crypto refused its key data (a `DOMException`, e.g. RSA without
 * `n`/`e` or an EC point off the curve), jose refused it (a private key,
 * `JWKSInvalid`), or `assertUsableKey` did. Never caused by the token alone:
 * a healthy key imports for every algorithm jose lets the token select it
 * with.
 */
function isKeyMaterialError(error: unknown): boolean {
  return error instanceof DOMException || error instanceof errors.JWKSInvalid || error instanceof KeyUnusable;
}

function malformed(): VerifyError {
  return new VerifyError("malformed", "Malformed access token");
}

function decodeObject(segment: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw malformed();
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw malformed();
  }
  return value as Record<string, unknown>;
}

function isAudience(value: unknown): boolean {
  return typeof value === "string" || (Array.isArray(value) && value.every((v) => typeof v === "string"));
}

function isTimestamp(value: unknown): boolean {
  return typeof value === "number" && Number.isFinite(value) && Math.abs(value) <= MAX_TIMESTAMP_S;
}

/**
 * Wrap a jose key resolver so that a failure to fetch or use the JWKS is
 * told apart from a key that simply does not match. No matching key (or
 * several) and an unsupported `alg` pass through for `classify`.
 */
function guardKeys(getKey: JWTVerifyGetKey): JWTVerifyGetKey {
  return async (header, token) => {
    try {
      const key = await getKey(header, token);
      assertUsableKey(key);
      return key;
    } catch (error) {
      if (
        error instanceof errors.JWKSNoMatchingKey ||
        error instanceof errors.JWKSMultipleMatchingKeys ||
        error instanceof errors.JOSENotSupported
      ) {
        throw error;
      }
      // JWKSTimeout, a non-200 or non-JSON JWKS (generic JOSEError), an
      // invalid key set, a key that cannot be used, or the fetch guard
      // refusing the request.
      if (
        error instanceof FetchRefused ||
        error instanceof VerifyError ||
        error instanceof errors.JOSEError ||
        isKeyMaterialError(error)
      ) {
        throw new KeysUnavailable();
      }
      throw error;
    }
  };
}

/**
 * Wrap the `fetch` an issuer's JWKS is loaded with (jose's `customFetch`)
 * in a backoff (R16). jose retries a cold or stale cache on every request,
 * so without this each request during a JWKS outage would wait for its own
 * failing fetch. After a failure (a throw, a non-200 answer, a 200 whose
 * body is not a JSON object with a `keys` array of objects, or a 200 with a
 * signing key that does not import, see `signingKeyUsable`) every call is
 * refused with `issuer_unavailable` and no network I/O until a window has
 * passed: 1 s, doubling after each further failure up to 60 s (the retry
 * loader's schedule, without jitter). The first call after the window
 * fetches again, and calls made while that fetch is in flight share it (each
 * gets its own copy of the response), so a burst sends one probe and counts
 * as at most one failure. A usable 200 resets the schedule. Each issuer has
 * its own wrapper, so one issuer's outage never gates another's fetches.
 *
 * The gate sits on the fetch, not on the key resolver, so while jose's
 * cached JWKS is fresh (`cacheMaxAge`, 10 minutes by default) tokens whose
 * key is cached keep working during an outage: only requests that need the
 * network are refused. Once the cache is stale every request needs a
 * refetch, and gets 503 until the JWKS is back.
 *
 * jose keeps a 200 with an unusable key, so `reloadOnUnusableKeys` asks
 * for it again once the window is over; `unusableKeys()` is how it reports
 * a key that failed in use although its set looked usable.
 *
 * Each window opened logs one warning, and the first usable 200 after
 * failures logs one info line. Both name the issuer by `origin` only and
 * the cause by a fixed word (the `FetchRefused` cause or the HTTP status),
 * never a URL path or an error message.
 */
export function jwksBackoff(fetchImpl: typeof fetch, origin: string, now: () => number = Date.now): JwksFetch {
  let failures = 0;
  let retryAt = 0;
  // The last 200 (or a key from it) was unusable, and already counted.
  let keysUnusable = false;
  const failed = (cause: string) => {
    const delay = Math.min(DEFAULT_INITIAL_DELAY_MS * 2 ** failures, DEFAULT_MAX_DELAY_MS);
    retryAt = now() + delay;
    failures++;
    logger.warn(
      `JWKS fetch for ${origin} failed (${plural(failures, "consecutive failure")}, cause: ${cause}); backing off ${delay}ms`,
    );
  };
  const probe = async (input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> => {
    let res: Response;
    try {
      res = await fetchImpl(input, init);
    } catch (error) {
      failed(error instanceof FetchRefused ? error.cause_ : "fetch error");
      throw error;
    }
    // A 200 counts only if jose can use it: a JSON object whose `keys` is an
    // array of objects, each signing key of which imports. Anything else
    // fails in jose as `issuer_unavailable` too, so it backs off like an
    // error status. The guarded fetch buffers the body, so the clone costs
    // no network I/O.
    let cause: string | undefined = `HTTP ${res.status}`;
    if (res.status === 200) {
      cause = "invalid key set";
      try {
        const body: unknown = await res.clone().json();
        if (isObject(body) && Array.isArray(body.keys) && body.keys.every(isObject)) {
          cause = (await everyAsync(body.keys, signingKeyUsable)) ? undefined : "invalid key material";
        }
      } catch {
        // Not JSON: "invalid key set".
      }
    }
    if (cause === undefined) {
      if (failures > 0) {
        logger.info(`JWKS fetch for ${origin} recovered after ${plural(failures, "consecutive failure")}`);
      }
      failures = 0;
      keysUnusable = false;
    } else {
      keysUnusable = res.status === 200;
      failed(cause);
    }
    return res;
  };
  // One fetch at a time: concurrent callers share the in-flight one, so a
  // burst at the end of a window sends a single probe and counts as a single
  // failure. jose already merges its own reloads; this does not rely on it.
  let inFlight: Promise<Response> | undefined;
  const gated: typeof fetch = async (input, init) => {
    if (failures > 0 && now() < retryAt) {
      throw new VerifyError("issuer_unavailable", "Token validation unavailable");
    }
    if (!inFlight) {
      inFlight = probe(input, init).finally(() => {
        inFlight = undefined;
      });
    }
    // Each caller reads its own copy of the (buffered) body.
    return (await inFlight).clone();
  };
  return Object.assign(gated, {
    unusableKeys() {
      if (!keysUnusable) {
        keysUnusable = true;
        failed("invalid key material");
      }
    },
  });
}

/** `jwksBackoff`'s fetch, plus the hook `reloadOnUnusableKeys` reports to. */
export type JwksFetch = typeof fetch & {
  /**
   * A key from the last usable 200 failed in use: count it as a failed
   * fetch, unless that set was already counted as unusable.
   */
  unusableKeys(): void;
};

/** jose's remote key set: a resolver with a forced refetch. */
export type RemoteKeySet = JWTVerifyGetKey & { reload(): Promise<void> };

/**
 * Wrap jose's remote key set so that a JWKS whose key cannot be used is
 * fetched again after the backoff window, instead of being served from
 * jose's cache until `cacheMaxAge` (10 minutes) runs out. On a key material
 * failure (see `isKeyMaterialError`) the set is reported to `gate` and
 * reloaded through it: inside the window that refuses at once
 * (`issuer_unavailable`, no network I/O); after it, one shared probe
 * refetches, and a repaired set serves the same request. A set that is
 * still unusable leaves the error for `guardKeys` (503).
 */
export function reloadOnUnusableKeys(keySet: RemoteKeySet, gate: JwksFetch): JWTVerifyGetKey {
  const resolve: JWTVerifyGetKey = async (header, token) => {
    const key = await keySet(header, token);
    assertUsableKey(key);
    return key;
  };
  return async (header, token) => {
    try {
      return await resolve(header, token);
    } catch (error) {
      if (!isKeyMaterialError(error)) {
        throw error;
      }
      gate.unusableKeys();
    }
    await keySet.reload();
    try {
      return await resolve(header, token);
    } catch (error) {
      if (isKeyMaterialError(error)) {
        gate.unusableKeys();
      }
      throw error;
    }
  };
}

const EC_ALGORITHMS: Record<string, string> = { "P-256": "ES256", "P-384": "ES384", "P-521": "ES512" };

/**
 * The algorithm to test-import a signing key with, by `kty` (and `crv`),
 * and the `alg` values jose lets select that key; `undefined` for a key
 * type jose has no signature algorithm for.
 */
function importAlgorithm(jwk: Record<string, unknown>): { alg: string; selects: string[] } | undefined {
  switch (jwk.kty) {
    case "RSA":
      return { alg: "RS256", selects: ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] };
    case "EC": {
      if (typeof jwk.crv !== "string" || !Object.hasOwn(EC_ALGORITHMS, jwk.crv)) return undefined;
      const alg = EC_ALGORITHMS[jwk.crv];
      return { alg, selects: [alg] };
    }
    case "OKP":
      return jwk.crv === "Ed25519" ? { alg: "Ed25519", selects: ["EdDSA", "Ed25519"] } : undefined;
    default:
      return undefined;
  }
}

/**
 * Whether jose could verify with `jwk` when a token selects it. Keys jose
 * never selects for a signature (`use` other than `sig`, `key_ops` without
 * `verify`, a non-signature `alg`, or a `kty`/`crv` it has no signature
 * algorithm for) are not checked. A private key, key data that does not
 * import, or an RSA modulus under 2048 bits is unusable.
 */
async function signingKeyUsable(jwk: Record<string, unknown>): Promise<boolean> {
  if (jwk.use !== undefined && jwk.use !== "sig") return true;
  if (Array.isArray(jwk.key_ops) && !jwk.key_ops.includes("verify")) return true;
  const spec = importAlgorithm(jwk);
  if (!spec || (jwk.alg !== undefined && !spec.selects.includes(jwk.alg as string))) return true;
  if (jwk.d !== undefined || jwk.priv !== undefined) return false;
  try {
    assertUsableKey(await importJWK(jwk, spec.alg));
    return true;
  } catch {
    return false;
  }
}

async function everyAsync<T>(items: T[], test: (item: T) => Promise<boolean>): Promise<boolean> {
  for (const item of items) {
    if (!(await test(item))) return false;
  }
  return true;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}

/** Map a `jwtVerify` failure to a `VerifyError`; anything unknown is rethrown (500). */
function classify(error: unknown): VerifyError {
  if (error instanceof VerifyError) {
    return error;
  }
  if (error instanceof KeysUnavailable) {
    return new VerifyError("issuer_unavailable", "Token validation unavailable");
  }
  if (error instanceof errors.JWTExpired) {
    return error.claim === "iat"
      ? new VerifyError("too_old", "Access token is too old")
      : new VerifyError("expired", "Access token expired");
  }
  if (error instanceof errors.JWTClaimValidationFailed) {
    switch (error.claim) {
      case "aud":
        return new VerifyError("audience", "Access token was not issued for this resource");
      case "nbf":
        return new VerifyError("not_yet_valid", "Access token is not yet valid");
      case "iss":
        return new VerifyError("unknown_issuer", "Access token issuer is not trusted");
      case "sub":
        return new VerifyError("subject_missing", "Access token has no subject");
      default:
        return malformed();
    }
  }
  if (
    error instanceof errors.JWSSignatureVerificationFailed ||
    error instanceof errors.JWKSNoMatchingKey ||
    error instanceof errors.JWKSMultipleMatchingKeys
  ) {
    return new VerifyError("signature", "Access token signature is invalid");
  }
  if (
    error instanceof errors.JOSEAlgNotAllowed ||
    error instanceof errors.JOSENotSupported ||
    error instanceof errors.JWSInvalid ||
    error instanceof errors.JWTInvalid
  ) {
    return malformed();
  }
  throw error;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** RFC 9068: `client_id` and `jti` non-empty strings; returns `client_id`. */
function strictClientId(payload: JWTPayload): string {
  const { client_id: clientId, jti } = payload as JWTPayload & { client_id?: unknown };
  if (!isNonEmptyString(clientId) || !isNonEmptyString(jti)) {
    throw malformed();
  }
  return clientId;
}

/**
 * Lenient (R27): refuse `nonce` (ID-token substitution guard), check the
 * optional identifier claims, and return `client_id ?? azp ?? appid ??
 * "unknown"`. Presence is an own property, so a JSON null counts.
 */
function lenientClientId(payload: JWTPayload): string {
  if (Object.hasOwn(payload, "nonce")) {
    throw malformed();
  }
  for (const name of LENIENT_OPTIONAL_STRINGS) {
    if (Object.hasOwn(payload, name) && !isNonEmptyString(payload[name])) {
      throw malformed();
    }
  }
  const { client_id: clientId, azp, appid } = payload as JWTPayload & Record<string, string | undefined>;
  return clientId ?? azp ?? appid ?? "unknown";
}

function effectivePolicy(policy: IdentityPolicy | undefined): IdentityPolicy | undefined {
  return policy && !isEmptyPolicy(policy) ? policy : undefined;
}

function enforcePolicy(policy: IdentityPolicy, payload: JWTPayload, sub: string): void {
  try {
    checkPolicy(policy, payload, sub);
  } catch (error) {
    if (!(error instanceof PolicyViolation)) {
      throw error;
    }
    // A fixed message: the violation names a claim key at most, but nothing
    // token-derived reaches error_description.
    throw new VerifyError("not_allowed", "Principal not allowed");
  }
}

interface RoutedIssuer {
  cfg: IssuerConfig;
  getKey: JWTVerifyGetKey;
  acceptedTyp: Set<string>;
  policy: IdentityPolicy | undefined;
  lenient: boolean;
}

/**
 * Verifier for RFC 9068 JWT access tokens from one or more issuers, each
 * checked against its own JWKS. In order:
 *
 * 1. Pre-checks, all `malformed`: three non-empty base64url segments; an
 *    `iss` that `peekIssuer` can read (an unconfigured one is
 *    `unknown_issuer`, with no network I/O; otherwise only that issuer's
 *    keys and settings are used); JSON object header and payload; header
 *    `typ` in the issuer's `acceptedTyp`
 *    (case-insensitive, so an ID token or generic JWT is refused unless the
 *    operator allows its type); `exp`/`nbf`/`iat`, when present, finite
 *    numbers within ±2^40; `aud`, when present, a string or an array of
 *    strings.
 * 2. `jwtVerify`: algorithm allowlist (checked before any key lookup, so
 *    `none` and HS* never reach the JWKS), signature, exact issuer, any of
 *    the audiences, `exp`/`nbf` with `clockSkewS` and no other leeway,
 *    optional maximum age from `iat`, and the RFC 9068 §2.2 claims present.
 * 3. `sub` a non-empty string of at most 256 characters
 *    (`subject_missing`); `client_id` and `jti` non-empty strings and
 *    `scope` absent or a string (`malformed`).
 * 4. The identity policy, if any, on the verified payload with subject
 *    `sub` (`not_allowed`, 403). The issuer's own policy replaces the
 *    global one as a whole; it is never merged with it.
 *
 * An issuer with `profile: "lenient"` (R27; config refuses one without a
 * non-empty identity policy) differs in steps 2 and 3 only: the required
 * claims are `exp`, `sub` and `iat`; `client_id`, `jti`, `azp`, `appid` and
 * `uti` are optional but, when present, non-empty strings; a token carrying
 * `nonce` is refused, since ID tokens carry one and these issuers' access
 * tokens do not (all `malformed`); and `AuthInfo.clientId` is
 * `client_id ?? azp ?? appid ?? "unknown"`. Its default `acceptedTyp` also
 * holds `JWT` (set by config); a missing `typ` is still refused.
 *
 * Error messages are fixed strings: they reach `error_description`, so they
 * never quote a claim. Every refusal after step 1 has routed the token
 * carries the configured issuer as `VerifyError.iss`.
 */
export function createJwtVerifier(o: JwtVerifierOptions): TokenVerifier {
  const now = o.now ?? Date.now;
  const issuers = new Map<string, RoutedIssuer>(
    o.issuers.map((cfg) => {
      const getKey = o.keys.get(cfg.issuer);
      if (!getKey) {
        throw new Error(`No key resolver for JWT issuer ${cfg.issuer}`);
      }
      return [
        cfg.issuer,
        {
          cfg,
          getKey: guardKeys(getKey),
          acceptedTyp: new Set(cfg.acceptedTyp.map((t) => t.toLowerCase())),
          policy: effectivePolicy(cfg.policy ?? o.policy),
          lenient: cfg.profile === "lenient",
        },
      ];
    }),
  );

  return {
    async verify(token) {
      const segments = token.split(".");
      if (segments.length !== 3 || !segments.every((s) => SEGMENT.test(s))) {
        throw malformed();
      }
      // The unverified iss only chooses the issuer; an unconfigured one is
      // refused here, before any key lookup or other network I/O.
      const iss = peekIssuer(token);
      if (iss === undefined) {
        throw malformed();
      }
      const entry = issuers.get(iss);
      if (!entry) {
        throw new VerifyError("unknown_issuer", "Access token issuer is not trusted");
      }
      try {
        return await verifyRouted(token, segments, entry);
      } catch (error) {
        // From here on the issuer is known: tag the refusal with the
        // configured string so the reject audit line can name it.
        if (error instanceof VerifyError) {
          throw new VerifyError(error.reason, error.message, entry.cfg.issuer);
        }
        throw error;
      }
    },
  };

  async function verifyRouted(token: string, segments: string[], entry: RoutedIssuer): Promise<AuthInfo> {
    const { cfg, getKey, acceptedTyp, policy, lenient } = entry;
    const header = decodeObject(segments[0]);
    const unverified = decodeObject(segments[1]);
    if (typeof header.typ !== "string" || !acceptedTyp.has(header.typ.toLowerCase())) {
      throw malformed();
    }
    for (const name of ["exp", "nbf", "iat"]) {
      if (name in unverified && !isTimestamp(unverified[name])) {
        throw malformed();
      }
    }
    // RFC 7519 §4.1.3: a string or an array of strings. Checked here because
    // jose reports a non-string aud as an audience mismatch.
    if ("aud" in unverified && !isAudience(unverified.aud)) {
      throw malformed();
    }

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, getKey, {
        issuer: cfg.issuer,
        audience: cfg.audiences,
        algorithms: cfg.algorithms,
        clockTolerance: cfg.clockSkewS,
        maxTokenAge: cfg.maxTokenAgeS || undefined,
        currentDate: new Date(now()),
        requiredClaims: lenient ? LENIENT_REQUIRED_CLAIMS : REQUIRED_CLAIMS,
      }));
    } catch (error) {
      throw classify(error);
    }

    const { sub, scope } = payload as JWTPayload & { scope?: unknown };
    if (typeof sub !== "string" || sub.length === 0 || sub.length > MAX_SUB_LENGTH) {
      throw new VerifyError("subject_missing", "Access token has no subject");
    }
    const clientId = lenient ? lenientClientId(payload) : strictClientId(payload);
    if (scope !== undefined && typeof scope !== "string") {
      throw malformed();
    }
    if (policy) {
      enforcePolicy(policy, payload, sub);
    }

    const info: AuthInfo = {
      token,
      clientId,
      scopes: typeof scope === "string" ? scope.split(" ").filter((s) => s.length > 0) : [],
      expiresAt: payload.exp,
      resource: o.publicUrl,
      extra: { iss: cfg.issuer, sub, principal: `${cfg.issuer}|${sub}`, claims: payload },
    };
    return info;
  }
}
