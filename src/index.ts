#!/usr/bin/env node

import type { Server as HttpServer } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { DatabaseService } from "./services/database.js";
import { configureTypeParser } from "./services/database-config.js";
import { createServer } from "./server.js";
import { logger } from "./services/logger.js";
import { ConfigError, loadConfig, type ServerConfig } from "./config.js";
import { buildHttpApp } from "./http/app.js";
import { authMiddleware, type AuthMiddleware } from "./auth/index.js";
import { closeHttpServerGracefully } from "./shutdown.js";

let serverStartTime: Date;

// Handle graceful shutdown: stop accepting HTTP requests first (when
// serving HTTP), then close the database pool. `httpServer.close()` alone
// can hang indefinitely on a connection that never drains (e.g. a client
// holding the Streamable HTTP response open), so it is bounded by a 10s
// forced-close timeout (Task 9 / Task 5 review). That matches - not safely
// beats - docker's and docker compose's own default 10s stop grace period,
// so a caller relying on the default would still have SIGKILL land at
// roughly the same moment this timeout fires, with no guarantee the
// `db.close()` step below ever runs. Deployments (see
// docker-compose.example.yml) should raise their own stop timeout past 10s
// (e.g. `docker stop -t 15`, or compose's `stop_grace_period: 15s`) so this
// handler has room to finish on its own.
function setupShutdownHandlers(db: DatabaseService, httpServer?: HttpServer) {
  const gracefulShutdown = async () => {
    if (httpServer) {
      await closeHttpServerGracefully(httpServer);
    }
    if (db) {
      try {
        await db.close();
      } catch (error) {
        // Note: Avoid logging during shutdown as it may interfere with MCP protocol
        process.exit(1);
      }
    }
    process.exit(0);
  };
  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);
}

export function getServerStartTime(): Date {
  return serverStartTime;
}

export async function startServer() {
  serverStartTime = new Date();

  let cfg: ServerConfig;
  try {
    cfg = loadConfig(process.env, process.argv);
  } catch (error) {
    if (error instanceof ConfigError) {
      // Never let a ConfigError's stack or wrapping context leak a secret;
      // its message alone names the offending env var.
      console.error(error.message);
      process.exit(1);
    }
    throw error;
  }

  logger.info(`Starting server (transport=${cfg.transport})`);

  try {
    // Configure global type parsers
    configureTypeParser();

    // Create the database service (it connects lazily on first query)
    if (process.argv[2]) {
      logger.info('Using connection string from command line argument');
    }
    const db = new DatabaseService({
      connectionString: cfg.db.connectionString,
      maxRows: cfg.db.maxRows,
      statementTimeoutMs: cfg.db.statementTimeoutMs,
      poolMax: cfg.db.poolMax,
      exposeConnectionDetails: cfg.transport === 'stdio',
    });

    if (cfg.transport === 'http') {
      await startHttp(cfg, db);
      return;
    }

    // Set up shutdown handlers
    setupShutdownHandlers(db);
    logger.info('Shutdown handlers configured');

    // Initialize server (capabilities, tools, prompts, resources, templates)
    logger.info('Creating MCP server instance...');
    const serverStartTime = Date.now();
    const server = createServer(db);
    logger.info(`MCP server instance created (took ${Date.now() - serverStartTime}ms)`);

    // Connect transport
    logger.info('Connecting transport...');
    const transportStartTime = Date.now();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logger.info(`Transport connected successfully (took ${Date.now() - transportStartTime}ms)`);

    const totalTime = Date.now() - serverStartTime;
    logger.info(`Server started successfully (total initialization time: ${totalTime}ms)`);
  } catch (error) {
    logger.error('Failed to start server:', error);
    throw error;
  }
}

async function startHttp(cfg: ServerConfig, db: DatabaseService) {
  let auth: AuthMiddleware;
  try {
    auth = await authMiddleware(cfg);
  } catch (error) {
    // Fail closed: never serve without the configured auth. The message
    // names the failure (e.g. Google metadata unreachable), never a token.
    logger.error(`Failed to initialise STEAMPIPE_MCP_AUTH_MODE=${cfg.auth.mode}:`, error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
  logger.info(`HTTP auth mode: ${cfg.auth.mode}`);
  const { host, port, path } = cfg.http;
  const app = buildHttpApp(cfg, db, auth.mcpMiddleware, auth.rootRouters);
  const httpServer = await new Promise<HttpServer>((resolve, reject) => {
    const s = app.listen(port, host, (error?: Error) => (error ? reject(error) : resolve(s)));
  });
  setupShutdownHandlers(db, httpServer);
  logger.info(`Streamable HTTP server listening on http://${host.includes(':') ? `[${host}]` : host}:${port}${path}`);
}

// Start the server
startServer().catch(() => process.exit(1));
