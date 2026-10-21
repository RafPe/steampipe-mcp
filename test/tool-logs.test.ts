import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { loadConfig, type ServerConfig } from "../src/config.js";
import { DatabaseService } from "../src/services/database.js";
import { buildHttpApp } from "../src/http/app.js";
import { logger, LogLevel } from "../src/services/logger.js";
import { describeDb, testDbUrl } from "./helpers/db.js";

// Tool-layer error logs carry client- and database-supplied text (tool names,
// argument keys, driver messages). Every request here goes through the full
// HTTP app, and every ERROR line it produces must be a single bounded line.

const MAX_ERROR_LINE = 1024;
const FORGED = "\n[2026-01-01T00:00:00.000Z] [INFO] forged\r\u2028\u202e";
const LONG = "x".repeat(5000);

let servers: HttpServer[] = [];

beforeEach(() => {
  // INFO, not DEBUG: the debug SQL line is deliberately allowed up to 8192 chars.
  logger.configure({ isTestEnvironment: true, level: LogLevel.INFO });
  logger.clearLogs();
});

afterEach(async () => {
  for (const s of servers) s.closeAllConnections();
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
  vi.restoreAllMocks();
});

function httpConfig(): ServerConfig {
  return loadConfig({ STEAMPIPE_MCP_TRANSPORT: "http" }, ["node", "index.js"]);
}

async function start(db: DatabaseService): Promise<number> {
  const app = buildHttpApp(httpConfig(), db);
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

function callTool(port: number, name: string, args: Record<string, unknown>): Promise<{ status: number; body: string }> {
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/mcp", headers }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on("error", reject);
    req.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }));
  });
}

/** Asserts at least one ERROR line was written and that none can forge or flood the log; returns them. */
function expectSafeErrorLines(): string[] {
  const lines = logger.getCollectedLogs();
  for (const line of lines) {
    expect(line).not.toMatch(/[\r\n\u2028\u2029\u202a-\u202e]/);
  }
  const errors = lines.filter((line) => line.includes("[ERROR]"));
  expect(errors.length).toBeGreaterThan(0);
  for (const line of errors) {
    expect(line.length).toBeLessThan(MAX_ERROR_LINE);
  }
  return errors;
}

/** A DatabaseService whose every query rejects with `error`. */
function failingDb(error: Error): DatabaseService {
  return {
    executeUserQuery: async () => { throw error; },
    executeQuery: async () => { throw error; },
  } as unknown as DatabaseService;
}

describe("tool-layer error logs (full HTTP request)", () => {
  it("bounds and sanitises an unknown tool name containing a newline", async () => {
    const port = await start({} as unknown as DatabaseService);
    const res = await callTool(port, `nope${FORGED}${LONG}`, {});
    expect(res.status).toBe(200);
    const errors = expectSafeErrorLines();
    expect(errors.some((line) => line.includes("Unknown tool: nope"))).toBe(true);
  });

  it("bounds and sanitises validation diagnostics carrying a client-chosen argument key", async () => {
    const port = await start({} as unknown as DatabaseService);
    const res = await callTool(port, "steampipe_query", { sql: "select 1", [`evil${FORGED}${LONG}`]: 1 });
    expect(res.status).toBe(200);
    const errors = expectSafeErrorLines();
    expect(errors.some((line) => line.includes("Invalid arguments for tool steampipe_query"))).toBe(true);
  });

  const toolCalls: Array<[string, Record<string, unknown>]> = [
    ["steampipe_query", { sql: "select 1" }],
    ["steampipe_table_list", {}],
    ["steampipe_table_show", { name: "t" }],
    ["steampipe_plugin_list", {}],
    ["steampipe_plugin_show", { name: "p" }],
  ];

  for (const [name, args] of toolCalls) {
    it(`bounds and sanitises a database error raised under ${name}`, async () => {
      const port = await start(failingDb(new Error(`db failed${FORGED}${LONG}`)));
      const res = await callTool(port, name, args);
      expect(res.status).toBe(200);
      const errors = expectSafeErrorLines();
      expect(errors.some((line) => line.includes("db failed"))).toBe(true);
    });
  }
});

// The local test Postgres has no TLS, so force sslmode=disable.
function noTlsUrl(): string {
  const url = new URL(testDbUrl()!);
  if (!url.searchParams.has("sslmode")) {
    url.searchParams.set("sslmode", "disable");
  }
  return url.toString();
}

describeDb("tool-layer error logs (real database)", () => {
  it("bounds and sanitises a Postgres error that echoes client input", async () => {
    const db = new DatabaseService({
      connectionString: noTlsUrl(),
      maxRows: 100,
      statementTimeoutMs: 10000,
      poolMax: 1,
      exposeConnectionDetails: false,
    });
    try {
      const port = await start(db);
      // Postgres echoes the whole literal, newline included, in the error.
      const res = await callTool(port, "steampipe_query", { sql: `select 'bad${FORGED}${LONG}'::int` });
      expect(res.status).toBe(200);
      expect(res.body).toContain("invalid input syntax");
      const errors = expectSafeErrorLines();
      expect(errors.some((line) => line.includes("invalid input syntax"))).toBe(true);
    } finally {
      await db.close();
    }
  });
});
