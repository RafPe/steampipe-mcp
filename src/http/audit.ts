import { createHash } from "node:crypto";
import type { RequestHandler } from "express";
import { boundForLog } from "../services/logbound.js";
import { logger } from "../services/logger.js";

export interface AuditEvent {
  sub: string;
  clientId: string;
  method: string;
  tool?: string;
  durationMs: number;
  status: number;
  sqlSha256?: string;
}

/**
 * Writes one structured audit line at info level. Never includes a token,
 * an Authorization header, an email, or SQL text - callers must not pass
 * any of those in `e`.
 */
export function auditLog(e: AuditEvent): void {
  logger.info(JSON.stringify(e));
}

/** First 16 hex chars of the SQL's sha256 - enough to correlate requests
 * without the audit line ever carrying the query text itself. */
function sqlSha256(sql: string): string {
  return createHash("sha256").update(sql, "utf8").digest("hex").slice(0, 16);
}

interface JsonRpcBody {
  method?: unknown;
  params?: {
    name?: unknown;
    arguments?: {
      sql?: unknown;
    };
  };
}

/**
 * One audit line per MCP request, written on `res.on('finish')` so it
 * carries the real status and duration. Reads `method`/`params.name`/
 * `params.arguments.sql` from the parsed JSON-RPC body only - never from
 * headers, so the bearer token can never leak into it. `sub`/`clientId`
 * come from `req.auth` (set by the bearer middleware upstream), defaulting
 * to `"anonymous"`/`"none"` in `none` mode. `method` and `tool` are
 * client-controlled, so they pass through `boundForLog` first. A 401/403
 * never reaches this middleware: bearer auth rejects those first.
 *
 * The SQL text itself is logged separately, at debug level only, so it
 * never appears at the default `info` level.
 */
export function auditMiddleware(): RequestHandler {
  return (req, res, next) => {
    const start = Date.now();
    const body = req.body as JsonRpcBody | undefined;
    const method = typeof body?.method === "string" ? body.method : "unknown";
    const toolName = typeof body?.params?.name === "string" ? body.params.name : undefined;
    const sql = typeof body?.params?.arguments?.sql === "string" ? body.params.arguments.sql : undefined;

    if (toolName === "steampipe_query" && sql !== undefined) {
      logger.debug(`steampipe_query SQL (tool=${toolName}): ${sql}`);
    }

    res.on("finish", () => {
      auditLog({
        sub: (req.auth?.extra?.sub as string | undefined) ?? "anonymous",
        clientId: req.auth?.clientId ?? "none",
        method: boundForLog(method),
        ...(toolName !== undefined ? { tool: boundForLog(toolName) } : {}),
        durationMs: Date.now() - start,
        status: res.statusCode,
        ...(toolName === "steampipe_query" && sql !== undefined ? { sqlSha256: sqlSha256(sql) } : {}),
      });
    });

    next();
  };
}
