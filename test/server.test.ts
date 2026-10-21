import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.js";
import { DatabaseService } from "../src/services/database.js";
import { testDbUrl } from "./helpers/db.js";

// No real DB connection is needed for any case here: initialize/listTools and
// argument validation never touch it (DatabaseService connects lazily on
// first query, and ajv validation runs before the handler is called).
function newDb(): DatabaseService {
  return new DatabaseService({
    connectionString: testDbUrl() || "postgresql://steampipe@localhost:9193/steampipe",
    maxRows: 0,
    statementTimeoutMs: 120000,
    poolMax: 1,
    exposeConnectionDetails: false,
  });
}

async function linkedClient(server: Server): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport),
  ]);
  return client;
}

describe("createServer", () => {
  it("registers the 5 tools and exposes spec-shaped capabilities", async () => {
    const server = createServer(newDb());
    const client = await linkedClient(server);

    try {
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual([
        "steampipe_plugin_list",
        "steampipe_plugin_show",
        "steampipe_query",
        "steampipe_table_list",
        "steampipe_table_show",
      ]);

      const capabilities = client.getServerCapabilities();
      expect(Object.keys(capabilities ?? {}).sort()).toEqual([
        "prompts",
        "resources",
        "tools",
      ]);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("validates tool arguments with the module-load-compiled ajv validator before calling the handler", async () => {
    const server = createServer(newDb());
    const client = await linkedClient(server);

    try {
      const result = await client.callTool({
        name: "steampipe_query",
        arguments: {},
      });
      expect(result.isError).toBe(true);
      expect((result.content as Array<{ type: string; text: string }>)[0].text).toContain(
        "Missing required field: sql"
      );
    } finally {
      await client.close();
      await server.close();
    }
  });
});
