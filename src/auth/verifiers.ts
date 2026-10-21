import { createHash, timingSafeEqual } from "node:crypto";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";

// A static token never expires, but `requireBearerAuth` rejects any AuthInfo
// without a numeric `expiresAt`. Report a rolling expiry an hour out.
const STATIC_EXPIRY_SECONDS = 3600;

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/**
 * Verifier for a single shared bearer token. Compares sha256 digests with
 * `timingSafeEqual`, so neither the content nor the length of the configured
 * token leaks through response timing.
 */
export function createStaticTokenVerifier(token: string): OAuthTokenVerifier {
  const expected = sha256(token);
  return {
    async verifyAccessToken(candidate) {
      if (!timingSafeEqual(sha256(candidate), expected)) {
        throw new InvalidTokenError("Invalid token");
      }
      return {
        token: candidate,
        clientId: "static",
        scopes: [],
        expiresAt: Math.floor(Date.now() / 1000) + STATIC_EXPIRY_SECONDS,
        extra: { sub: "static" },
      };
    },
  };
}
