import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolRequest, type Tool, type ServerResult } from "@modelcontextprotocol/sdk/types.js";
import { DatabaseService } from "../services/database.js";
import AjvModule, { type ValidateFunction } from "ajv";
import { logger } from "../services/logger.js";
import { boundForLog, errorText } from "../services/logbound.js";

// Import tools
import { tool as queryTool } from './steampipe_query.js';
import { tool as tableListTool } from './steampipe_table_list.js';
import { tool as tableShowTool } from './steampipe_table_show.js';
import { tool as pluginListTool } from './steampipe_plugin_list.js';
import { tool as pluginShowTool } from './steampipe_plugin_show.js';

// Initialize JSON Schema validator
const Ajv = AjvModule.default || AjvModule;
const ajv = new Ajv();

// Define tool type
type DbTool = Tool & {
  handler: (db: DatabaseService, args: any) => Promise<ServerResult>;
};

// Export all tools for server capabilities
export const tools = {
  steampipe_query: queryTool as DbTool,
  steampipe_table_list: tableListTool as DbTool,
  steampipe_table_show: tableShowTool as DbTool,
  steampipe_plugin_list: pluginListTool as DbTool,
  steampipe_plugin_show: pluginShowTool as DbTool,
} as const;

// Compile each tool's input-schema validator once at module load, rather than
// on every tool call (ajv.compile() parses/builds a validator function from
// the JSON schema, which is wasted work to repeat per request).
const validators: Record<string, ValidateFunction> = Object.fromEntries(
  Object.entries(tools)
    .filter(([, tool]) => Boolean(tool.inputSchema))
    .map(([name, tool]) => [name, ajv.compile(tool.inputSchema)])
);

// Initialize tool handlers
export function setupTools(server: Server, db: DatabaseService) {
  // Register tool list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { 
      tools: Object.entries(tools).map(([name, tool]) => ({
        name,
        description: tool.description,
        inputSchema: tool.inputSchema
      }))
    };
  });

  // Register tool handlers
  server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
    try {
      const { name, arguments: args = {} } = request.params;
      const tool = tools[name as keyof typeof tools];

      if (!tool) {
        throw new Error(`Unknown tool: ${name}`);
      }

      // Validate arguments against the tool's schema
      const validate = validators[name];
      if (validate) {
        if (!validate(args)) {
          // Diagnostics echo client-chosen argument keys and values, so bound them
          logger.error(`Invalid arguments for tool ${boundForLog(name)}:`, boundForLog(JSON.stringify(validate.errors), 512));
          
          // Format validation errors in a user-friendly way
          const errors = validate.errors || [];
          const errorMessages = errors.map(err => {
            const path = err.instancePath.replace(/^\//, '') || 'input';
            switch (err.keyword) {
              case 'required':
                return `Missing required field: ${err.params.missingProperty}`;
              case 'type':
                return `${path} must be a ${err.params.type}`;
              case 'enum':
                return `${path} must be one of: ${err.params.allowedValues?.join(', ')}`;
              case 'additionalProperties':
                return `Unexpected field: ${err.params.additionalProperty}`;
              default:
                return `${path}: ${err.message}`;
            }
          });

          return {
            content: [{
              type: "text",
              text: errorMessages.join('\n')
            }],
            isError: true
          };
        }
      }

      // Call the tool handler with database
      return await (tool as DbTool).handler(db, args);
    } catch (error) {
      // The message can echo the client-supplied tool name, so bound it
      logger.error('Error executing tool:', errorText(error));
      return {
        content: [{
          type: "text",
          text: error instanceof Error ? error.message : 'An unknown error occurred'
        }],
        isError: true
      };
    }
  });
} 