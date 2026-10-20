import type { RequestHandler } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import type { ServerConfig } from "../config.js";

const BATCH_NOT_SUPPORTED = {
  jsonrpc: "2.0",
  error: { code: -32600, message: "Batch requests are not supported" },
};

const TOO_MANY_REQUESTS = {
  jsonrpc: "2.0",
  error: { code: -32000, message: "Too many requests" },
};

/**
 * Refuses a JSON-RPC batch (array) body with 400 (Review Focus 1). The
 * stateless Streamable HTTP transport (one `Server`/transport per request,
 * no session) has no notion of a batch, so accepting one would either
 * silently drop every entry but the first or require multiplexing we don't
 * support.
 */
export function rejectBatch(): RequestHandler {
  return (req, res, next) => {
    if (Array.isArray(req.body)) {
      res.status(400).json(BATCH_NOT_SUPPORTED);
      return;
    }
    next();
  };
}

/** Shared by both limiters below: the same JSON-RPC-shaped 429, rather
 * than express-rate-limit's default plain text body. */
const rateLimitExceeded: RequestHandler = (_req, res) => {
  res.status(429).json(TOO_MANY_REQUESTS);
};

/**
 * Per-principal rate limiting (`rateLimitPerMin` per rolling 60s window).
 * Keyed by the authenticated `sub` when auth set `req.auth` (token/google
 * mode), falling back to the client IP otherwise (`none` mode). Standard
 * `RateLimit-*` headers only; answers over-limit requests with a
 * JSON-RPC-shaped 429 rather than express-rate-limit's default plain text.
 */
export function createRateLimiter(http: ServerConfig["http"]): RequestHandler {
  return rateLimit({
    windowMs: 60_000,
    limit: http.rateLimitPerMin,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => (req.auth?.extra?.sub as string | undefined) ?? ipKeyGenerator(req.ip ?? "unknown"),
    handler: rateLimitExceeded,
  });
}

/**
 * Coarse, pre-auth rate limit keyed on IP alone, mounted ahead of bearer
 * auth (R18). Without it, an unauthenticated flood - each request costing
 * a real `verifyAccessToken` call, which in `google` mode is an uncached
 * outbound call to Google's `tokeninfo` for every rejected token - bypasses
 * the per-principal limiter entirely, since that one only sees `req.auth`
 * once bearer auth has already run. Set 10x looser than the per-principal
 * limit so it only trips on a flood, not on normal traffic from many
 * distinct principals behind the same IP/proxy.
 */
export function createPreAuthIpLimiter(http: ServerConfig["http"]): RequestHandler {
  return rateLimit({
    windowMs: 60_000,
    limit: 10 * http.rateLimitPerMin,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(req.ip ?? "unknown"),
    handler: rateLimitExceeded,
  });
}
