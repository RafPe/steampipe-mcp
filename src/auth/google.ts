import { createHash } from "node:crypto";
import {
  InsufficientScopeError,
  InvalidTokenError,
  ServerError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthMetadataSchema, type OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { logger } from "../services/logger.js";

export const GOOGLE_ISSUER = "https://accounts.google.com";
const DEFAULT_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo";
const DEFAULT_DISCOVERY_URL = `${GOOGLE_ISSUER}/.well-known/openid-configuration`;
const GOOGLE_TIMEOUT_MS = 5000;
const CACHE_TTL_MS = 60_000;
const CACHE_MAX_ENTRIES = 1000;

export interface GoogleVerifierOptions {
  clientId: string;
  allowedEmails: string[];
  allowedDomains: string[];
  publicUrl: URL;
  tokeninfoUrl?: string;
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
 * so each one is checked against Google's tokeninfo endpoint:
 *
 * - not a 200, issued to another client (`aud` differs from `clientId`; R17:
 *   a matching `azp` alone is not enough), or expired: `InvalidTokenError`
 *   (401).
 * - email unverified, neither the email nor its domain allowlisted, or
 *   admitted only by domain while `hd` names a different domain:
 *   `InsufficientScopeError` (403).
 * - tokeninfo unreachable or timed out: `ServerError` (500). Never accepted.
 *
 * Successful results are cached in memory for at most 60s (and never past
 * the token's own expiry), keyed by the token's sha256. Failures are never
 * cached. Every call returns a fresh copy, so a caller mutating its
 * AuthInfo cannot change what later requests see.
 */
export function createGoogleVerifier(o: GoogleVerifierOptions): OAuthTokenVerifier {
  const tokeninfoUrl = o.tokeninfoUrl ?? DEFAULT_TOKENINFO_URL;
  const now = o.now ?? Date.now;
  const allowedEmails = new Set(o.allowedEmails.map((e) => e.toLowerCase()));
  const allowedDomains = new Set(o.allowedDomains.map((d) => d.toLowerCase()));
  // Map iteration order is insertion order, so the first key is the oldest.
  const cache = new Map<string, { info: AuthInfo; until: number }>();

  async function lookup(token: string): Promise<TokenInfo> {
    let res: Response;
    try {
      // POST with a form body keeps the token out of URLs and access logs.
      res = await fetch(tokeninfoUrl, {
        method: "POST",
        body: new URLSearchParams({ access_token: token }),
        signal: AbortSignal.timeout(GOOGLE_TIMEOUT_MS),
      });
    } catch (error) {
      logger.error("Google tokeninfo request failed", error instanceof Error ? error.name : "unknown error");
      throw new ServerError("Token validation unavailable");
    }
    if (res.status !== 200) {
      throw new InvalidTokenError("Invalid token");
    }
    try {
      const body: unknown = await res.json();
      if (typeof body !== "object" || body === null) {
        throw new Error("not an object");
      }
      return body as TokenInfo;
    } catch {
      throw new InvalidTokenError("Invalid token");
    }
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

  function copy(info: AuthInfo): AuthInfo {
    return { ...info, scopes: [...info.scopes], extra: { ...info.extra } };
  }

  return {
    async verifyAccessToken(token) {
      const key = createHash("sha256").update(token, "utf8").digest("hex");
      const cached = cache.get(key);
      if (cached && cached.until > now()) {
        return copy(cached.info);
      }
      cache.delete(key);

      const info = await lookup(token);
      if (info.aud !== o.clientId) {
        throw new InvalidTokenError("Token was not issued to this client");
      }
      const expMs = Number(info.exp) * 1000;
      if (!Number.isFinite(expMs) || expMs <= now()) {
        throw new InvalidTokenError("Token has expired");
      }
      const email = typeof info.email === "string" ? info.email.toLowerCase() : undefined;
      if (info.email_verified !== "true" || !email || !email.includes("@") || !isAllowed(email, info.hd)) {
        logger.debug("Google principal not allowed", email ?? "(no email)");
        throw new InsufficientScopeError("principal not allowed");
      }
      logger.debug("Google principal authenticated", email);

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
 * Fetch Google's OpenID discovery document as RFC 8414 metadata, for the
 * Protected Resource Metadata router. Throws unless it parses and names
 * Google as its issuer.
 */
export async function fetchGoogleMetadata(discoveryUrl = DEFAULT_DISCOVERY_URL): Promise<OAuthMetadata> {
  const res = await fetch(discoveryUrl, { signal: AbortSignal.timeout(GOOGLE_TIMEOUT_MS) });
  if (!res.ok) {
    throw new Error(`Google discovery document request failed with HTTP ${res.status}`);
  }
  const metadata = OAuthMetadataSchema.parse(await res.json());
  if (metadata.issuer !== GOOGLE_ISSUER) {
    throw new Error(`Unexpected issuer in Google discovery document: ${JSON.stringify(metadata.issuer)}`);
  }
  return metadata;
}
