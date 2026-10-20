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
    handler: (_req, res) => {
      res.status(429).json(TOO_MANY_REQUESTS);
    },
  });
}
