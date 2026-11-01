import { afterEach, describe, expect, it } from "vitest";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { loadConfig, type ServerConfig } from "../src/config.js";
import { DatabaseService } from "../src/services/database.js";
import { composeHttp } from "../src/http/compose.js";
import { describeDb, testDbUrl } from "./helpers/db.js";

// R38: the total number of JSON values in a request body is capped, so a
// small body cannot fan out into one validation issue per element (an
// initialize with a 1 MiB `clientInfo.icons` array used to answer with a
// ~127 MB JSON-RPC error and peak at ~1.36 GB RSS). The limit is a literal
// here on purpose: it is part of the documented contract.
const LIMIT = 10_000;
const TOKEN = "t".repeat(40);
const SMALL_RESPONSE = 64 * 1024;

// sslmode=disable as in database.test.ts: the test Postgres has no TLS.
function dbUrl(): string {
  const raw = testDbUrl();
  if (!raw) return "postgresql://steampipe@localhost:9193/steampipe";
  const url = new URL(raw);
  if (!url.searchParams.has("sslmode")) url.searchParams.set("sslmode", "disable");
  return url.toString();
}

function newDb(): DatabaseService {
  return new DatabaseService({
    connectionString: dbUrl(),
    maxRows: 10000,
    statementTimeoutMs: 120000,
    poolMax: 1,
    exposeConnectionDetails: false,
  });
}

function tokenConfig(): ServerConfig {
  return loadConfig(
    {
      STEAMPIPE_MCP_TRANSPORT: "http",
      STEAMPIPE_MCP_AUTH_MODE: "token",
      STEAMPIPE_MCP_AUTH_TOKEN: TOKEN,
      // Concurrency and repeated requests below must not trip rate limits.
      STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1000",
    },
    ["node", "index.js"],
  );
}

let servers: HttpServer[] = [];
let dbs: DatabaseService[] = [];

afterEach(async () => {
  for (const s of servers) s.closeAllConnections();
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  await Promise.all(dbs.map((d) => d.close()));
  servers = [];
  dbs = [];
});

async function start(): Promise<number> {
  const db = newDb();
  dbs.push(db);
  const { app } = await composeHttp(tokenConfig(), db);
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

interface Response {
  status: number;
  body: string;
}

function post(port: number, body: string, auth = true): Promise<Response> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (auth) headers.Authorization = `Bearer ${TOKEN}`;
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/mcp", headers }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

/** An `initialize` whose `clientInfo.icons` holds `n` invalid elements (M3's reproducer). */
function initializeWithIcons(n: number): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "attacker", version: "1.0.0", icons: new Array(n).fill(0) },
    },
  });
}

/**
 * A `tools/list` with exactly `total` JSON values. JSON.parse calls a
 * reviver once per value, the root included: root (1) + jsonrpc, id, method,
 * params (4) + _meta (1) + pad (1) = 7, plus one per array element.
 */
function toolsListWithValues(total: number): string {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: { _meta: { pad: new Array(total - 7).fill(0) } },
  });
  let count = 0;
  JSON.parse(body, (_k, v) => (count++, v));
  expect(count).toBe(total);
  return body;
}

const TOO_MANY = {
  jsonrpc: "2.0",
  error: { code: -32000, message: `Request body too large: more than ${LIMIT} JSON values` },
  id: null,
};

describe("JSON value-count limit (R38)", () => {
  it("answers M3's oversized initialize with a small 413 JSON-RPC error instead of an amplified one", async () => {
    const port = await start();
    // ~40 KB in; the unbounded path answered with ~5 MB of zod issues.
    const res = await post(port, initializeWithIcons(20_000));
    expect(res.body.length).toBeLessThan(SMALL_RESPONSE);
    expect(res.status).toBe(413);
    expect(JSON.parse(res.body)).toEqual(TOO_MANY);
  });

  it("accepts a body of exactly the limit and rejects one value more", async () => {
    const port = await start();
    const atLimit = await post(port, toolsListWithValues(LIMIT));
    expect(atLimit.status).toBe(200);
    expect(JSON.parse(atLimit.body).result.tools.length).toBeGreaterThan(0);

    const over = await post(port, toolsListWithValues(LIMIT + 1));
    expect(over.status).toBe(413);
    expect(JSON.parse(over.body)).toEqual(TOO_MANY);
  });

  it("rejects before authentication: an unauthenticated oversized body gets 413, not 401", async () => {
    const port = await start();
    const res = await post(port, toolsListWithValues(LIMIT + 1), false);
    expect(res.status).toBe(413);
    expect(JSON.parse(res.body)).toEqual(TOO_MANY);
    // Below the limit, auth still applies.
    expect((await post(port, toolsListWithValues(LIMIT), false)).status).toBe(401);
  });

  it("never echoes body content or a stack trace in the error", async () => {
    const port = await start();
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/list",
      params: { _meta: { secret: "do-not-echo-me", pad: new Array(LIMIT).fill(0) } },
    });
    const res = await post(port, body);
    expect(res.status).toBe(413);
    expect(res.body).not.toContain("do-not-echo-me");
    expect(res.body).not.toMatch(/at .*\.(js|ts):\d+/);
  });

  it("cannot be reset mid-parse by nested empty-string keys", async () => {
    const port = await start();
    // The root's reviver key is "" too; a counter that reset on key "" would
    // let this body through.
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/list",
      params: { _meta: { pad: Array.from({ length: LIMIT }, () => ({ "": 0 })) } },
    });
    const res = await post(port, body);
    expect(res.status).toBe(413);
    expect(JSON.parse(res.body)).toEqual(TOO_MANY);
  });

  it("counts per request: concurrent bodies just under the limit pass while oversized ones fail", async () => {
    const port = await start();
    const ok = toolsListWithValues(LIMIT);
    const bad = toolsListWithValues(LIMIT + 1);
    const bodies = Array.from({ length: 12 }, (_, i) => (i % 3 === 0 ? bad : ok));
    const results = await Promise.all(bodies.map((b) => post(port, b)));
    results.forEach((res, i) => expect(res.status).toBe(i % 3 === 0 ? 413 : 200));
  });

  it("still serves a normal initialize", async () => {
    const port = await start();
    const res = await post(port, initializeWithIcons(0).replace(',"icons":[]', ""));
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).result.serverInfo.name).toBe("steampipe");
  });
});

describeDb("JSON value-count limit (R38): real queries", () => {
  it("still serves tools/call steampipe_query", async () => {
    const port = await start();
    const res = await post(
      port,
      JSON.stringify({
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: { name: "steampipe_query", arguments: { sql: "select 1 as one" } },
      }),
    );
    expect(res.status).toBe(200);
    const result = JSON.parse(res.body).result;
    expect(result.isError).toBeFalsy();
    expect(JSON.stringify(result.content)).toContain("one");
  });
});
