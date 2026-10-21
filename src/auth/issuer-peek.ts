const SEGMENT = /^[A-Za-z0-9_-]+$/;
// Far longer than any real issuer identifier; bounds what a routing lookup
// is ever asked to compare.
const MAX_ISSUER_LENGTH = 2048;

/**
 * Read `iss` from a compact JWS without verifying anything. Returns
 * `undefined` for anything that is not three non-empty base64url segments
 * whose middle one decodes to a JSON object with a non-empty string `iss`
 * of at most 2048 characters. Never throws.
 *
 * The result is a ROUTING HINT AND NOTHING ELSE: nobody signed it, so it
 * must never become an identity, a network destination or a log field. Its
 * only use is choosing which configured issuer's verifier checks the token.
 * It runs after `bearerAuth`'s `maxTokenBytes` check, which bounds the
 * decode below.
 */
export function peekIssuer(token: string): string | undefined {
  const segments = token.split(".");
  // All three segments, so a JSON serialization that happens to contain
  // two dots is not read as a compact token.
  if (segments.length !== 3 || !segments.every((s) => SEGMENT.test(s))) {
    return undefined;
  }
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(segments[1], "base64url").toString("utf8"));
  } catch {
    return undefined;
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload) || !Object.hasOwn(payload, "iss")) {
    return undefined;
  }
  const iss: unknown = (payload as { iss: unknown }).iss;
  if (typeof iss !== "string" || iss.length === 0 || iss.length > MAX_ISSUER_LENGTH) {
    return undefined;
  }
  return iss;
}
