#!/usr/bin/env node

import type { Server as HttpServer } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { DatabaseService } from "./services/database.js";
import { configureTypeParser } from "./services/database-config.js";
import { createServer } from "./server.js";
import { logger } from "./services/logger.js";
import { ConfigError, loadConfig, type ServerConfig } from "./config.js";
import { buildHttpApp } from "./http/app.js";

let serverStartTime: Date;

// Handle graceful shutdown: stop accepting HTTP requests first (when
// serving HTTP), then close the database pool.
function setupShutdownHandlers(db: DatabaseService, httpServer?: HttpServer) {
  const gracefulShutdown = async () => {
    if (httpServer) {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
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
  if (cfg.auth.mode !== 'none') {
    // Task 6 replaces this with the real auth middleware. Until then, never
    // serve unauthenticated while the operator believes auth is enforced.
    logger.error(`STEAMPIPE_MCP_AUTH_MODE=${cfg.auth.mode} is not available in this build`);
    process.exit(1);
  }
  const { host, port, path } = cfg.http;
  const app = buildHttpApp(cfg, db);
  const httpServer = await new Promise<HttpServer>((resolve, reject) => {
    const s = app.listen(port, host, (error?: Error) => (error ? reject(error) : resolve(s)));
  });
  setupShutdownHandlers(db, httpServer);
  logger.info(`Streamable HTTP server listening on http://${host.includes(':') ? `[${host}]` : host}:${port}${path}`);
}

// Start the server
startServer().catch(() => process.exit(1));
