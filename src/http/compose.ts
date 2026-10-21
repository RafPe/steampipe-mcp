import type { Server as HttpServer } from "node:http";
import type { Express } from "express";
import type { ServerConfig } from "../config.js";
import { authMiddleware, type AuthMiddleware, type AuthMiddlewareOptions } from "../auth/index.js";
import type { DatabaseService } from "../services/database.js";
import { boundForLog } from "../services/logbound.js";
import { logger } from "../services/logger.js";
import { setupShutdownHandlers, type SignalTarget } from "../shutdown.js";
import { buildHttpApp } from "./app.js";
import { buildReadiness, type Readiness } from "./ready.js";

export interface ComposeOptions extends AuthMiddlewareOptions {
  /** Passed to `Readiness` (tests use `{ cacheMs: 0 }`). */
  readiness?: ConstructorParameters<typeof Readiness>[0];
}

export interface ServeOptions extends ComposeOptions {
  /** Where the SIGTERM/SIGINT handlers go. Default `process`. */
  proc?: SignalTarget;
}

/**
 * Thrown by `composeHttp` when the configured auth cannot be built. It has
 * already been logged once, so the caller only has to exit.
 */
export class AuthInitError extends Error {
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = "AuthInitError";
  }
}

/**
 * Build the HTTP app exactly as the server runs it: the auth layer for
 * `cfg.auth.mode`, readiness with the `db` check plus auth's checks, and
 * the app wired with auth's routers and guards.
 *
 * Fails closed: if auth cannot be built (e.g. Google discovery unreachable
 * without degraded start), it logs one error naming the failure, never a
 * token, and throws `AuthInitError`.
 */
export async function composeHttp(
  cfg: ServerConfig,
  db: DatabaseService,
  opts: ComposeOptions = {},
): Promise<{ app: Express; readiness: Readiness; auth: AuthMiddleware }> {
  let auth: AuthMiddleware;
  try {
    auth = await authMiddleware(cfg, opts);
  } catch (error) {
    logger.error(
      `Failed to initialise STEAMPIPE_MCP_AUTH_MODE=${cfg.auth.mode}:`,
      boundForLog(error instanceof Error ? error.message : error),
    );
    throw new AuthInitError(error);
  }
  logger.info(`HTTP auth mode: ${cfg.auth.mode}`);
  const readiness = buildReadiness(db, auth.readiness, opts.readiness);
  const app = buildHttpApp(cfg, db, auth.mcpMiddleware, auth.rootRouters, readiness);
  return { app, readiness, auth };
}

/**
 * `composeHttp`, then listen on `cfg.http.host:port` and register the
 * shutdown handlers (auth is disposed before the database closes).
 */
export async function serveHttp(
  cfg: ServerConfig,
  db: DatabaseService,
  opts: ServeOptions = {},
): Promise<{ server: HttpServer; app: Express; readiness: Readiness; auth: AuthMiddleware }> {
  const { app, readiness, auth } = await composeHttp(cfg, db, opts);
  const { host, port } = cfg.http;
  const server = await new Promise<HttpServer>((resolve, reject) => {
    const s = app.listen(port, host, (error?: Error) => (error ? reject(error) : resolve(s)));
  });
  setupShutdownHandlers(db, server, auth, opts.proc);
  return { server, app, readiness, auth };
}
