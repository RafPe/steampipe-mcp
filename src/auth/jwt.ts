import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import type { TokenVerifier } from "./bearer.js";
import { VerifyError } from "./errors.js";
import { FetchRefused } from "./fetch-guard.js";

export interface IssuerConfig {
  issuer: string;
  audiences: string[];
  algorithms: string[];
  /** Accepted header `typ` values, compared case-insensitively. */
  acceptedTyp: string[];
  clockSkewS: number;
  /** 0 means off. */
  maxTokenAgeS: number;
}

export interface JwtVerifierOptions {
  issuers: IssuerConfig[];
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

/** The key resolver could not reach or use the issuer's JWKS. */
class KeysUnavailable extends Error {
  constructor() {
    super("JWKS unavailable");
    this.name = "KeysUnavailable";
  }
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
      return await getKey(header, token);
    } catch (error) {
      if (
        error instanceof errors.JWKSNoMatchingKey ||
        error instanceof errors.JWKSMultipleMatchingKeys ||
        error instanceof errors.JOSENotSupported
      ) {
        throw error;
      }
      // JWKSTimeout, a non-200 or non-JSON JWKS (generic JOSEError), an
      // invalid key set, or the fetch guard refusing the request.
      if (error instanceof FetchRefused || error instanceof VerifyError || error instanceof errors.JOSEError) {
        throw new KeysUnavailable();
      }
      throw error;
    }
  };
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

/**
 * Verifier for RFC 9068 JWT access tokens, checked against each issuer's
 * JWKS. In order:
 *
 * 1. Pre-checks, all `malformed`: three non-empty base64url segments; JSON
 *    object header and payload; a string `iss` (an unconfigured one is
 *    `unknown_issuer`); header `typ` in the issuer's `acceptedTyp`
 *    (case-insensitive, so an ID token or generic JWT is refused unless the
 *    operator allows its type); `exp`/`nbf`/`iat`, when present, finite
 *    numbers within ±2^40.
 * 2. `jwtVerify`: algorithm allowlist (checked before any key lookup, so
 *    `none` and HS* never reach the JWKS), signature, exact issuer, any of
 *    the audiences, `exp`/`nbf` with `clockSkewS` and no other leeway,
 *    optional maximum age from `iat`, and the RFC 9068 §2.2 claims present.
 * 3. `sub` a non-empty string of at most 256 characters
 *    (`subject_missing`); `client_id` a non-empty string and `scope` absent
 *    or a string (`malformed`).
 *
 * Error messages are fixed strings: they reach `error_description`, so they
 * never quote a claim.
 */
export function createJwtVerifier(o: JwtVerifierOptions): TokenVerifier {
  const now = o.now ?? Date.now;
  const issuers = new Map(
    o.issuers.map((cfg) => {
      const getKey = o.keys.get(cfg.issuer);
      if (!getKey) {
        throw new Error(`No key resolver for JWT issuer ${cfg.issuer}`);
      }
      return [
        cfg.issuer,
        { cfg, getKey: guardKeys(getKey), acceptedTyp: new Set(cfg.acceptedTyp.map((t) => t.toLowerCase())) },
      ];
    }),
  );

  return {
    async verify(token) {
      const segments = token.split(".");
      if (segments.length !== 3 || !segments.every((s) => SEGMENT.test(s))) {
        throw malformed();
      }
      const header = decodeObject(segments[0]);
      const unverified = decodeObject(segments[1]);
      if (typeof unverified.iss !== "string") {
        throw malformed();
      }
      const entry = issuers.get(unverified.iss);
      if (!entry) {
        throw new VerifyError("unknown_issuer", "Access token issuer is not trusted");
      }
      const { cfg, getKey, acceptedTyp } = entry;
      if (typeof header.typ !== "string" || !acceptedTyp.has(header.typ.toLowerCase())) {
        throw malformed();
      }
      for (const name of ["exp", "nbf", "iat"]) {
        if (name in unverified && !isTimestamp(unverified[name])) {
          throw malformed();
        }
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
          requiredClaims: REQUIRED_CLAIMS,
        }));
      } catch (error) {
        throw classify(error);
      }

      const { sub, client_id: clientId, scope } = payload as JWTPayload & { client_id?: unknown; scope?: unknown };
      if (typeof sub !== "string" || sub.length === 0 || sub.length > MAX_SUB_LENGTH) {
        throw new VerifyError("subject_missing", "Access token has no subject");
      }
      if (typeof clientId !== "string" || clientId.length === 0) {
        throw malformed();
      }
      if (scope !== undefined && typeof scope !== "string") {
        throw malformed();
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
    },
  };
}
