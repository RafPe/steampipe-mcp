import { DatabaseService } from "../services/database.js";
import type { Resource } from "@modelcontextprotocol/sdk/types.js";
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { version } = require('../../package.json');

type ResourceHandler = (db: DatabaseService) => Promise<{
  contents: Array<{
    uri: string;
    mimeType: string;
    text: string;
  }>;
}>;

export const resource: Resource & { handler: ResourceHandler } = {
  uri: "steampipe://status",
  name: "status",
  description: "Get the current status of the Steampipe connection",
  handler: async (db: DatabaseService) => {
    // Get the current connection state. The connection string is only
    // included (password-masked) when exposeConnectionDetails is set; it is
    // otherwise omitted so the resource never reveals the DB host/user.
    const isConnected = db.isConnected;

    return {
      contents: [{
        uri: "steampipe://status",
        mimeType: "application/json",
        text: JSON.stringify({
          version,
          ...(db.exposeConnectionDetails ? { connection_string: db.safeConnectionString } : {}),
          status: isConnected ? "connected" : "disconnected"
        })
      }]
    };
  }
};