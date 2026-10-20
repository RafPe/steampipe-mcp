import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { DatabaseService } from "./services/database.js";
import { setupTools } from "./tools/index.js";
import { setupPromptHandlers } from "./prompts/index.js";
import { setupResourceHandlers } from "./resources/index.js";
import { setupResourceTemplateHandlers } from "./resourceTemplates/index.js";
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Load package.json
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));

// Server metadata
export const SERVER_INFO = {
  name: "steampipe",
  version: pkg.version,
  description: pkg.description,
  vendor: pkg.author,
  license: pkg.license,
  homepage: pkg.homepage,
} as const;

/**
 * Build a fresh MCP `Server` wired up to the given database. Each call
 * returns an independent instance with its own request handlers, so a
 * caller (stdio today, HTTP in a later task) can construct one server per
 * connection/request without shared mutable state between them.
 *
 * Capabilities are declared spec-shaped: an empty object per capability
 * signals "this capability is supported", rather than carrying the actual
 * tool/prompt/resource maps (which the MCP spec never expects here, and
 * which used to leak internal handler functions into `getServerCapabilities()`).
 */
export function createServer(db: DatabaseService): Server {
  const server = new Server(SERVER_INFO, {
    capabilities: {
      tools: {},
      prompts: {},
      resources: {},
    },
  });

  setupTools(server, db);
  setupPromptHandlers(server);
  setupResourceHandlers(server, db);
  setupResourceTemplateHandlers(server);

  return server;
}
