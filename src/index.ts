#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { DatabaseService } from "./services/database.js";
import { configureTypeParser } from "./services/database-config.js";
import { createServer } from "./server.js";
import { logger } from "./services/logger.js";
import { ConfigError, loadConfig, type ServerConfig } from "./config.js";

let serverStartTime: Date;

// Handle graceful shutdown
function setupShutdownHandlers(db: DatabaseService) {
  const gracefulShutdown = async () => {
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

  if (cfg.transport === 'http') {
    // Task 5 replaces this with the real HTTP transport.
    logger.error('HTTP transport not available in this build');
    process.exit(1);
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

// Start the server
startServer();
