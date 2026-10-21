/**
 * Why a bearer token was refused. Verifiers throw a `VerifyError` carrying
 * one of these; `bearerAuth` turns it into the HTTP answer via `statusFor`.
 */
export type Reason =
  | "missing"
  | "malformed"
  | "unknown_issuer"
  | "issuer_unavailable"
  | "invalid"
  | "signature"
  | "expired"
  | "not_yet_valid"
  | "too_old"
  | "audience"
  | "subject_missing"
  | "not_allowed";

/** A verifier's refusal. Anything else a verifier throws is a programming error (500). */
export class VerifyError extends Error {
  constructor(
    readonly reason: Reason,
    message: string,
  ) {
    super(message);
    this.name = "VerifyError";
  }
}

export function reasonOf(err: unknown): Reason | undefined {
  return err instanceof VerifyError ? err.reason : undefined;
}

/**
 * `not_allowed` is a policy denial (403). `issuer_unavailable` means the
 * token could not be checked at all (503, so clients retry rather than
 * re-authenticate). Every other reason is a bad token (401).
 */
export function statusFor(reason: Reason): 401 | 403 | 503 {
  switch (reason) {
    case "not_allowed":
      return 403;
    case "issuer_unavailable":
      return 503;
    default:
      return 401;
  }
}
