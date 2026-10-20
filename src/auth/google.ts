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
  scope?: string;
  exp?: string;
}

/**
 * Verifier for Google OAuth access tokens. Google access tokens are opaque,
 * so each one is checked against Google's tokeninfo endpoint:
 *
 * - not a 200, issued to another client (`aud` and `azp` both differ from
 *   `clientId`), or expired: `InvalidTokenError` (401).
 * - email unverified, or neither the email nor its domain allowlisted:
 *   `InsufficientScopeError` (403).
 * - tokeninfo unreachable or timed out: `ServerError` (500). Never accepted.
 *
 * Successful results are cached in memory for at most 60s (and never past
 * the token's own expiry), keyed by the token's sha256. Failures are never
 * cached, so a fixed allowlist or revoked token takes effect on the next call.
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

  function isAllowed(email: string): boolean {
    const domain = email.slice(email.lastIndexOf("@") + 1);
    return allowedEmails.has(email) || allowedDomains.has(domain);
  }

  return {
    async verifyAccessToken(token) {
      const key = createHash("sha256").update(token, "utf8").digest("hex");
      const cached = cache.get(key);
      if (cached && cached.until > now()) {
        return cached.info;
      }
      cache.delete(key);

      const info = await lookup(token);
      if (info.aud !== o.clientId && info.azp !== o.clientId) {
        throw new InvalidTokenError("Token was not issued to this client");
      }
      const expMs = Number(info.exp) * 1000;
      if (!Number.isFinite(expMs) || expMs <= now()) {
        throw new InvalidTokenError("Token has expired");
      }
      const email = typeof info.email === "string" ? info.email.toLowerCase() : undefined;
      if (info.email_verified !== "true" || !email || !email.includes("@") || !isAllowed(email)) {
        logger.debug("Google principal not allowed", email ?? "(no email)");
        throw new InsufficientScopeError("principal not allowed");
      }
      logger.debug("Google principal authenticated", email);

      const authInfo: AuthInfo = {
        token,
        clientId: info.azp ?? info.aud ?? o.clientId,
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
      return authInfo;
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
