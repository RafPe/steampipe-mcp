#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { DatabaseService } from "./services/database.js";
import { configureTypeParser } from "./services/database-config.js";
import { createServer } from "./server.js";
import { logger } from "./services/logger.js";

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

export async function startServer(port: number = 27123) {
  serverStartTime = new Date();
  logger.info(`Starting server on port ${port}`);

  try {
    // Configure global type parsers
    configureTypeParser();

    // Create the database service (it connects lazily on first query)
    const argConnectionString = process.argv[2];
    if (argConnectionString) {
      logger.info('Using connection string from command line argument');
    }
    const db = new DatabaseService({
      connectionString: argConnectionString
        || process.env.STEAMPIPE_MCP_WORKSPACE_DATABASE
        || 'postgresql://steampipe@localhost:9193/steampipe',
      maxRows: 0,
      statementTimeoutMs: 120000,
      poolMax: 20,
      exposeConnectionDetails: true,
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
    logger.info(`Server started successfully on port ${port} (total initialization time: ${totalTime}ms)`);
  } catch (error) {
    logger.error('Failed to start server:', error);
    throw error;
  }
}

// Start the server
startServer();
