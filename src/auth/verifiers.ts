import { createHash, timingSafeEqual } from "node:crypto";
import type { TokenVerifier } from "./bearer.js";
import { VerifyError } from "./errors.js";

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/**
 * Verifier for a single shared bearer token. Compares sha256 digests with
 * `timingSafeEqual`, so neither the content nor the length of the configured
 * token leaks through response timing. A static token never expires, so the
 * AuthInfo carries no `expiresAt`.
 */
export function createStaticTokenVerifier(token: string): TokenVerifier {
  const expected = sha256(token);
  return {
    async verify(candidate) {
      if (!timingSafeEqual(sha256(candidate), expected)) {
        throw new VerifyError("invalid", "Invalid token");
      }
      return {
        token: candidate,
        clientId: "static",
        scopes: [],
        extra: { sub: "static" },
      };
    },
  };
}
