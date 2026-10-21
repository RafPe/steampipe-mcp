import { createHash } from "node:crypto";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthMetadataSchema, type OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { boundForLog } from "../services/logbound.js";
import { logger } from "../services/logger.js";
import type { TokenVerifier } from "./bearer.js";
import { VerifyError } from "./errors.js";
import { FetchRefused, GOOGLE_FETCH_POLICY, guardedFetch } from "./fetch-guard.js";
import { checkPolicy, isEmptyPolicy, PolicyViolation, type IdentityPolicy } from "./policy.js";

export const GOOGLE_ISSUER = "https://accounts.google.com";
const DEFAULT_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo";
const DEFAULT_DISCOVERY_URL = `${GOOGLE_ISSUER}/.well-known/openid-configuration`;
const CACHE_TTL_MS = 60_000;
const CACHE_MAX_ENTRIES = 1000;

export interface GoogleVerifierOptions {
  clientId: string;
  allowedEmails: string[];
  allowedDomains: string[];
  publicUrl: URL;
  tokeninfoUrl?: string;
  /** Identity policy applied after the allowlist. Absent or empty: none. */
  policy?: IdentityPolicy;
  /** tokeninfo request timeout, headers and body. Default 5000. */
  timeoutMs?: number;
  now?: () => number;
}

interface TokenInfo {
  aud?: string;
  azp?: string;
  sub?: string;
  email?: string;
  email_verified?: string;
  hd?: string;
  scope?: string;
  exp?: string;
}

/**
 * Verifier for Google OAuth access tokens. Google access tokens are opaque,
 * so each one is checked against Google's tokeninfo endpoint, through
 * `guardedFetch(GOOGLE_FETCH_POLICY)`:
 *
 * - tokeninfo unreachable, timed out (headers or body), dropping the
 *   connection mid-body, answering 429/5xx, or refused by the fetch guard (a
 *   host outside the policy, any redirect, a body over 64 KiB):
 *   `issuer_unavailable` (503). Never accepted.
 * - any other non-200 (400/401 for a bad token): `invalid`.
 * - a 200 whose complete body is not a JSON object: `malformed`.
 * - issued to another client (`aud` differs from `clientId`; R17: a matching
 *   `azp` alone is not enough): `audience`.
 * - `exp` absent, non-numeric or past: `expired`.
 * - email unverified, neither the email nor its domain allowlisted, or
 *   admitted only by domain while `hd` names a different domain:
 *   `not_allowed` (403).
 * - the identity policy, if any, not satisfied: `not_allowed` (403). It runs
 *   after the allowlist and both must pass. Its claims are the tokeninfo
 *   fields sub, email, email_verified, hd, aud, azp and scope, as Google
 *   sent them; its subject is `sub`.
 *
 * Successful results are cached in memory for at most 60s (and never past
 * the token's own expiry), keyed by the token's sha256. Failures are never
 * cached. Every call returns a fresh copy, so a caller mutating its
 * AuthInfo cannot change what later requests see.
 */
export function createGoogleVerifier(o: GoogleVerifierOptions): TokenVerifier {
  const tokeninfoUrl = o.tokeninfoUrl ?? DEFAULT_TOKENINFO_URL;
  const guarded = guardedFetch({ ...GOOGLE_FETCH_POLICY, timeoutMs: o.timeoutMs ?? GOOGLE_FETCH_POLICY.timeoutMs });
  const now = o.now ?? Date.now;
  const allowedEmails = new Set(o.allowedEmails.map((e) => e.toLowerCase()));
  const allowedDomains = new Set(o.allowedDomains.map((d) => d.toLowerCase()));
  // Map iteration order is insertion order, so the first key is the oldest.
  const cache = new Map<string, { info: AuthInfo; until: number }>();
  const policy = o.policy && !isEmptyPolicy(o.policy) ? o.policy : undefined;

  async function lookup(token: string): Promise<TokenInfo> {
    let res: Response;
    try {
      // POST with a form body keeps the token out of URLs and access logs.
      res = await guarded(tokeninfoUrl, {
        method: "POST",
        body: new URLSearchParams({ access_token: token }),
      });
    } catch (error) {
      logger.error("Google tokeninfo request failed", describeFailure(error));
      throw new VerifyError("issuer_unavailable", "Token validation unavailable");
    }
    if (res.status === 429 || res.status >= 500) {
      logger.error("Google tokeninfo unavailable", `HTTP ${res.status}`);
      throw new VerifyError("issuer_unavailable", "Token validation unavailable");
    }
    if (res.status !== 200) {
      throw new VerifyError("invalid", "Invalid token");
    }
    // Read and parse separately: a stall or dropped connection mid-body is
    // an outage, not a malformed answer. The guard has already buffered the
    // body (and refused a stalled one as a timeout), so this read failing is
    // not expected, but it is classified the same way.
    let text: string;
    try {
      text = await res.text();
    } catch (error) {
      logger.error("Google tokeninfo body read failed", describeFailure(error));
      throw new VerifyError("issuer_unavailable", "Token validation unavailable");
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw new VerifyError("malformed", "Invalid token");
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new VerifyError("malformed", "Invalid token");
    }
    return body as TokenInfo;
  }

  function isAllowed(email: string, hd: string | undefined): boolean {
    if (allowedEmails.has(email)) {
      return true;
    }
    const domain = email.slice(email.lastIndexOf("@") + 1);
    if (!allowedDomains.has(domain)) {
      return false;
    }
    // Anyone can register a consumer Google account on an address in a
    // Workspace domain, so a domain match alone does not prove membership.
    // When Google reports the hosted domain, it must agree. tokeninfo for
    // access tokens often omits `hd`, so its absence is not a rejection;
    // the Internal consent screen is what makes domains a real boundary.
    if (hd === undefined) {
      return true;
    }
    return typeof hd === "string" && hd.toLowerCase() === domain;
  }

  function enforcePolicy(p: IdentityPolicy, info: TokenInfo, email: string): void {
    // Named fields only: nothing else tokeninfo returns (exp, unknown
    // fields) can satisfy a rule.
    const { sub, email_verified, hd, aud, azp, scope } = info;
    const claims = { sub, email: info.email, email_verified, hd, aud, azp, scope };
    try {
      // A missing sub is "", which no subject rule admits (R10 refuses
      // empty entries).
      checkPolicy(p, claims, typeof sub === "string" ? sub : "");
    } catch (error) {
      if (!(error instanceof PolicyViolation)) {
        throw error;
      }
      // The violation names a claim key at most, never a value.
      logger.debug("Google principal denied by policy", boundForLog(email), error.message);
      throw new VerifyError("not_allowed", "Principal not allowed");
    }
  }

  function copy(info: AuthInfo): AuthInfo {
    return { ...info, scopes: [...info.scopes], extra: { ...info.extra } };
  }

  return {
    async verify(token) {
      const key = createHash("sha256").update(token, "utf8").digest("hex");
      const cached = cache.get(key);
      if (cached && cached.until > now()) {
        return copy(cached.info);
      }
      cache.delete(key);

      const info = await lookup(token);
      if (info.aud !== o.clientId) {
        throw new VerifyError("audience", "Token was not issued to this client");
      }
      const expMs = Number(info.exp) * 1000;
      if (!Number.isFinite(expMs) || expMs <= now()) {
        throw new VerifyError("expired", "Token has expired");
      }
      const email = typeof info.email === "string" ? info.email.toLowerCase() : undefined;
      if (info.email_verified !== "true" || !email || !email.includes("@") || !isAllowed(email, info.hd)) {
        logger.debug("Google principal not allowed", boundForLog(email ?? "(no email)"));
        throw new VerifyError("not_allowed", "Principal not allowed");
      }
      if (policy) {
        enforcePolicy(policy, info, email);
      }
      logger.debug("Google principal authenticated", boundForLog(email));

      const authInfo: AuthInfo = {
        token,
        clientId: info.aud,
        scopes: (info.scope ?? "").split(" ").filter(Boolean),
        expiresAt: Number(info.exp),
        resource: o.publicUrl,
        extra: { sub: info.sub, email: info.email },
      };
      if (cache.size >= CACHE_MAX_ENTRIES) {
        const oldest = cache.keys().next().value;
        if (oldest !== undefined) cache.delete(oldest);
      }
      cache.set(key, { info: authInfo, until: now() + Math.min(CACHE_TTL_MS, expMs - now()) });
      return copy(authInfo);
    },
  };
}

/**
 * Fetch Google's OpenID discovery document through
 * `guardedFetch(GOOGLE_FETCH_POLICY)`. A guard refusal (host outside the
 * policy, redirect, timeout, oversized body, network error) throws
 * `VerifyError("issuer_unavailable")`; otherwise throws unless the answer is
 * a 2xx that parses as RFC 8414 metadata naming Google as its issuer.
 * `signal` aborts the request (the degraded-start loader's `dispose()`).
 */
export async function fetchGoogleMetadata(
  discoveryUrl = DEFAULT_DISCOVERY_URL,
  signal?: AbortSignal,
): Promise<OAuthMetadata> {
  let res: Response;
  try {
    res = await guardedFetch(GOOGLE_FETCH_POLICY)(discoveryUrl, { signal });
  } catch (error) {
    // A caller abort (shutdown) is not a discovery failure worth an error line.
    if (!signal?.aborted) {
      logger.error("Google discovery request failed", describeFailure(error));
    }
    throw new VerifyError("issuer_unavailable", "Google discovery document unavailable");
  }
  if (!res.ok) {
    throw new Error(`Google discovery document request failed with HTTP ${res.status}`);
  }
  const metadata = OAuthMetadataSchema.parse(await res.json());
  if (metadata.issuer !== GOOGLE_ISSUER) {
    throw new Error(`Unexpected issuer in Google discovery document: ${JSON.stringify(metadata.issuer)}`);
  }
  return metadata;
}

// A FetchRefused message names at most the scheme and host, never the path
// or query; anything else is reduced to its error name.
function describeFailure(error: unknown): string {
  if (error instanceof FetchRefused) {
    return `${error.cause_}: ${error.message}`;
  }
  return error instanceof Error ? error.name : "unknown error";
}
