import type { RequestHandler, Response } from "express";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { logger } from "../services/logger.js";
import { statusFor, VerifyError, type Reason } from "./errors.js";

export interface TokenVerifier {
  /** Resolves with the principal (`token` set to the raw token), or throws a `VerifyError`. */
  verify(token: string): Promise<AuthInfo>;
}

/**
 * One refused request. Never carries the token or any claim value beyond
 * `iss`/`sub`; `iss` is the configured issuer the verifier routed the token
 * to (`VerifyError.iss`), absent when it routed it to none.
 */
export interface RejectEvent {
  reason: Reason;
  status: number;
  ip: string | undefined;
  iss?: string;
  sub?: string;
  durationMs: number;
}

export interface BearerOptions {
  verifier: TokenVerifier;
  /** Exact string compare against `AuthInfo.resource?.href`, fragments removed. */
  expectedResource?: string;
  resourceMetadataUrl?: string;
  /** Advertised as `scope` on every 401. Each entry must be an RFC 6750 scope-token. */
  challengeScope?: string[];
  /** Longer tokens are `malformed` before the verifier sees them. Default 8192. */
  maxTokenBytes?: number;
  onReject?: (e: RejectEvent) => void;
}

const DEFAULT_MAX_TOKEN_BYTES = 8192;
const MAX_DESCRIPTION_CHARS = 200;
const RETRY_AFTER_SECONDS = "5";
// RFC 6750 §3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
// RFC 6750 §3: error_description = *( %x20-21 / %x23-5B / %x5D-7E ). No
// quote, backslash, control character or non-ASCII survives, so a value
// can neither break out of its quoted-string nor split the header.
const NOT_QUOTABLE = /[^\x20-\x21\x23-\x5B\x5D-\x7E]/g;

/**
 * Build a `WWW-Authenticate` Bearer challenge from ordered auth-params. Every
 * value is stripped to the RFC 6750 quoted-string character set;
 * `error_description` is also cut to 200 characters.
 */
export function challenge(params: Array<[string, string]>): string {
  if (params.length === 0) {
    return "Bearer";
  }
  const parts = params.map(([key, value]) => {
    const clean = key === "error_description" ? description(value) : value.replace(NOT_QUOTABLE, "");
    return `${key}="${clean}"`;
  });
  return `Bearer ${parts.join(", ")}`;
}

function description(message: string): string {
  return message.replace(NOT_QUOTABLE, "").slice(0, MAX_DESCRIPTION_CHARS);
}

function withoutFragment(value: string): string {
  const hash = value.indexOf("#");
  return hash === -1 ? value : value.slice(0, hash);
}

/**
 * Extract the token from `Authorization: Bearer <token>`. No header, or
 * another scheme, is `missing` (RFC 6750 §3.1: the client sent no Bearer
 * credentials at all). A Bearer header with no token, more than one, or an
 * oversized one is `malformed`.
 */
function extractToken(header: string | undefined, maxBytes: number): string | VerifyError {
  if (!header) {
    return new VerifyError("missing", "Missing Authorization header");
  }
  const scheme = header.split(/\s/, 1)[0];
  if (scheme.toLowerCase() !== "bearer") {
    return new VerifyError("missing", "Missing Authorization header");
  }
  const token = header.slice(scheme.length).trim();
  if (!token || /\s/.test(token) || Buffer.byteLength(token, "utf8") > maxBytes) {
    return new VerifyError("malformed", "Malformed Authorization header");
  }
  return token;
}

/**
 * Bearer token middleware (replaces the SDK's `requireBearerAuth`). The
 * verifier owns every token check, expiry included; this layer parses the
 * header, enforces `expectedResource`, and maps a `VerifyError` to:
 *
 * - 401 with a Bearer challenge (`resource_metadata`, `scope`); `error=
 *   "invalid_token"` only when a token was actually presented.
 * - 403 `access_denied` for `not_allowed`, with no challenge: a policy
 *   denial that re-authenticating or step-up cannot fix.
 * - 503 `temporarily_unavailable` with `Retry-After` for `issuer_unavailable`.
 *
 * Anything else thrown is a bug: 500, logged by error name only, since a
 * message may quote the token.
 */
export function bearerAuth(o: BearerOptions): RequestHandler {
  const scope = o.challengeScope ?? [];
  for (const s of scope) {
    if (!SCOPE_TOKEN.test(s)) {
      throw new Error(`Invalid challenge scope ${JSON.stringify(s)}: not an RFC 6750 scope-token`);
    }
  }
  const maxTokenBytes = o.maxTokenBytes ?? DEFAULT_MAX_TOKEN_BYTES;
  const expectedResource = o.expectedResource === undefined ? undefined : withoutFragment(o.expectedResource);

  function unauthorizedChallenge(err?: VerifyError): string {
    const params: Array<[string, string]> = [];
    if (err) {
      params.push(["error", "invalid_token"], ["error_description", err.message]);
    }
    if (o.resourceMetadataUrl) {
      params.push(["resource_metadata", o.resourceMetadataUrl]);
    }
    if (scope.length > 0) {
      params.push(["scope", scope.join(" ")]);
    }
    return challenge(params);
  }

  function reject(res: Response, err: VerifyError, ip: string | undefined, start: number): void {
    const status = statusFor(err.reason);
    try {
      o.onReject?.({
        reason: err.reason,
        status,
        ip,
        ...(err.iss !== undefined && { iss: err.iss }),
        durationMs: Date.now() - start,
      });
    } catch (hookError) {
      logger.error("bearerAuth onReject hook failed", hookError instanceof Error ? hookError.name : "unknown error");
    }
    if (status === 503) {
      res.set("Retry-After", RETRY_AFTER_SECONDS);
      res.status(503).json({ error: "temporarily_unavailable", error_description: "Token validation unavailable" });
    } else if (status === 403) {
      res.status(403).json({ error: "access_denied", error_description: description(err.message) });
    } else {
      res.set("WWW-Authenticate", unauthorizedChallenge(err.reason === "missing" ? undefined : err));
      res.status(401).json({ error: "invalid_token", error_description: description(err.message) });
    }
  }

  return async (req, res, next) => {
    const start = Date.now();
    let authInfo: AuthInfo;
    try {
      const token = extractToken(req.headers.authorization, maxTokenBytes);
      if (token instanceof VerifyError) {
        throw token;
      }
      authInfo = await o.verifier.verify(token);
      if (expectedResource !== undefined) {
        const reported = authInfo.resource?.href;
        if (reported === undefined || withoutFragment(reported) !== expectedResource) {
          throw new VerifyError("audience", "Token was not issued for this resource");
        }
      }
    } catch (error) {
      if (error instanceof VerifyError) {
        reject(res, error, req.ip, start);
        return;
      }
      logger.error("Token verifier failed", error instanceof Error ? error.name : "unknown error");
      res.status(500).json({ error: "server_error", error_description: "Internal Server Error" });
      return;
    }
    req.auth = authInfo;
    next();
  };
}
