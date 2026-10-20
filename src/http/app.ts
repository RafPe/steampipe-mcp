import express, { type ErrorRequestHandler, type Express, type RequestHandler } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  hostHeaderValidation,
  localhostHostValidation,
} from "@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js";
import type { ServerConfig } from "../config.js";
import { createServer } from "../server.js";
import type { DatabaseService } from "../services/database.js";
import { logger } from "../services/logger.js";
import { isLoopback } from "../services/ssl.js";
import { auditMiddleware } from "./audit.js";
import { createRateLimiter, rejectBatch } from "./guards.js";
import { originValidation } from "./origin.js";

function jsonRpcError(status: number, code: number, message: string): { status: number; body: object } {
  return { status, body: { jsonrpc: "2.0", error: { code, message }, id: null } };
}

/**
 * Normalise a configured host entry to the shape the SDK middleware compares
 * against: `new URL("http://" + Host).hostname`, i.e. lowercased, port-free,
 * IPv6 kept in brackets. Without this, `ALLOWED_HOSTS=MCP.example.com:443`
 * would never match anything.
 */
function toHostname(entry: string): string {
  try {
    return new URL(`http://${entry}`).hostname;
  } catch {
    return entry.toLowerCase();
  }
}

/**
 * Pick the DNS-rebinding Host check for this bind (R2). Returns `undefined`
 * when no Host check can be derived from config; the caller warns once.
 */
function hostValidation(http: ServerConfig["http"]): RequestHandler | undefined {
  if (isLoopback(http.host)) {
    return localhostHostValidation();
  }
  if (http.allowedHosts.length > 0) {
    return hostHeaderValidation(http.allowedHosts.map(toHostname));
  }
  if (http.publicUrl) {
    return hostHeaderValidation([http.publicUrl.hostname]);
  }
  return undefined;
}

/**
 * Express error handler for body-parser failures and anything thrown by a
 * route. Always answers with a JSON-RPC error (never Express's HTML page or a
 * stack trace) and never logs or echoes the request body.
 */
const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  let reply;
  if (err?.type === "entity.too.large") {
    reply = jsonRpcError(413, -32000, "Request body too large");
  } else if (err?.type === "entity.parse.failed") {
    reply = jsonRpcError(400, -32700, "Parse error: Invalid JSON");
  } else if (typeof err?.status === "number" && err.status >= 400 && err.status < 500) {
    reply = jsonRpcError(err.status, -32000, "Bad request");
  } else {
    logger.error("HTTP request failed", err instanceof Error ? err.message : String(err));
    reply = jsonRpcError(500, -32603, "Internal server error");
  }
  if (res.headersSent) {
    return;
  }
  res.status(reply.status).json(reply.body);
};

/**
 * Build the stateless Streamable HTTP app (MCP spec 2025-11-25). Every POST
 * gets its own `Server` and transport, with no session IDs, so nothing is
 * shared between requests except the `db` pool.
 *
 * Middleware order: `GET /healthz` first (R14: static, no DB, so probes
 * that send a pod IP or `localhost` as Host still pass), then Host
 * validation, Origin validation, JSON body parsing (capped at
 * `maxBodyBytes`), then `rootRouters` at the app root (R15: public
 * `/.well-known/*` metadata, still Host/Origin-checked), then on
 * `POST {path}` only: `extraMiddleware` (bearer auth), per-principal rate
 * limiting, JSON-RPC batch rejection, and the audit log, in that order, so
 * route guards see the parsed body and the authenticated principal while
 * the metadata and the 405s stay reachable without auth, and a 401/403
 * never reaches the rate limiter, the batch check, or the audit log.
 */
export function buildHttpApp(
  cfg: ServerConfig,
  db: DatabaseService,
  extraMiddleware: RequestHandler[] = [],
  rootRouters: RequestHandler[] = [],
): Express {
  const { http } = cfg;
  const app = express();
  app.disable("x-powered-by");
  if (http.trustProxy !== undefined) {
    app.set("trust proxy", http.trustProxy);
  }

  // Mounted before Host/Origin validation (R14): it returns only static
  // data, so a DNS-rebinding or cross-origin read of it gains nothing.
  app.get("/healthz", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  const hostCheck = hostValidation(http);
  if (hostCheck) {
    app.use(hostCheck);
  } else {
    logger.warn(
      "Host header validation is disabled: non-loopback bind with neither " +
        "STEAMPIPE_MCP_ALLOWED_HOSTS nor STEAMPIPE_MCP_PUBLIC_URL set",
    );
  }
  app.use(originValidation(http.allowedOrigins));
  app.use(express.json({ limit: http.maxBodyBytes }));
  for (const router of rootRouters) {
    app.use(router);
  }

  app.post(http.path, ...extraMiddleware, createRateLimiter(http), rejectBatch(), auditMiddleware(), async (req, res) => {
    // express.json() only parses application/json. Refuse anything it
    // skipped, so the transport never reads an unparsed (and so uncapped)
    // body stream itself.
    if (req.body === undefined) {
      const reply = jsonRpcError(415, -32000, "Unsupported Media Type: Content-Type must be application/json");
      res.status(reply.status).json(reply.body);
      return;
    }

    const server = createServer(db);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
      maxRequestBodySize: http.maxBodyBytes,
    });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error("MCP request failed", error instanceof Error ? error.message : String(error));
      if (!res.headersSent) {
        const reply = jsonRpcError(500, -32603, "Internal server error");
        res.status(reply.status).json(reply.body);
      }
    }
  });

  const methodNotAllowed: RequestHandler = (_req, res) => {
    res.set("Allow", "POST");
    const reply = jsonRpcError(405, -32000, "Method not allowed");
    res.status(reply.status).json(reply.body);
  };
  app.get(http.path, methodNotAllowed);
  app.delete(http.path, methodNotAllowed);

  app.use((_req, res) => {
    const reply = jsonRpcError(404, -32000, "Not found");
    res.status(reply.status).json(reply.body);
  });
  app.use(errorHandler);

  return app;
}
