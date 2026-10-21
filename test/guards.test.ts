import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import type { RequestHandler } from "express";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { loadConfig, type ServerConfig } from "../src/config.js";
import type { DatabaseService } from "../src/services/database.js";
import { buildHttpApp } from "../src/http/app.js";
import { authMiddleware } from "../src/auth/index.js";
import { logger, LogLevel } from "../src/services/logger.js";

const STATIC_TOKEN = "s".repeat(40);

// steampipe_query always touches the DB; a fake lets guards tests run fast
// and without a real Postgres/Steampipe backend.
function fakeDb(): DatabaseService {
  return { executeUserQuery: async () => ({ rows: [{ ok: 1 }], truncated: false }) } as unknown as DatabaseService;
}

function httpConfig(env: Record<string, string> = {}): ServerConfig {
  return loadConfig({ STEAMPIPE_MCP_TRANSPORT: "http", ...env }, ["node", "index.js"]);
}

interface Response {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

let servers: HttpServer[] = [];

beforeEach(() => {
  // Pin the level explicitly rather than trust the module's env-derived
  // default: a stray STEAMPIPE_MCP_LOG_LEVEL=debug in the environment must
  // not make the "no SQL at info" assertions pass for the wrong reason.
  logger.configure({ isTestEnvironment: true, level: LogLevel.INFO });
  logger.clearLogs();
});

afterEach(async () => {
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
  vi.restoreAllMocks();
});

async function start(cfg: ServerConfig): Promise<number> {
  const app = buildHttpApp(cfg, fakeDb());
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

async function startWithAuth(cfg: ServerConfig): Promise<number> {
  const { rootRouters, mcpMiddleware } = await authMiddleware(cfg);
  const app = buildHttpApp(cfg, fakeDb(), mcpMiddleware, rootRouters);
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

function send(
  port: number,
  opts: { method?: string; path?: string; headers?: Record<string, string>; body?: string },
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        method: opts.method ?? "POST",
        path: opts.path ?? "/mcp",
        headers: opts.headers,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    req.on("error", reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

const MCP_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

function rpc(port: number, message: object, headers: Record<string, string> = {}): Promise<Response> {
  return send(port, { headers: { ...MCP_HEADERS, ...headers }, body: JSON.stringify(message) });
}

const TOOLS_LIST = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };

describe("buildHttpApp: JSON-RPC batch rejection (Review Focus 1)", () => {
  it("rejects an array body with 400 and a JSON-RPC -32600 error", async () => {
    const port = await start(httpConfig());
    const res = await rpc(port, [TOOLS_LIST, TOOLS_LIST] as unknown as object);
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body)).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32600, message: "Batch requests are not supported" },
    });
  });

  it("still accepts a single, non-array request", async () => {
    const port = await start(httpConfig());
    const res = await rpc(port, TOOLS_LIST);
    expect(res.status).toBe(200);
  });
});

describe("buildHttpApp: per-principal rate limiting", () => {
  it("gives 429 with a JSON-RPC error on the 61st request within a minute", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "60" }));
    let last: Response | undefined;
    for (let i = 0; i < 61; i++) {
      last = await rpc(port, TOOLS_LIST);
      if (i < 60) {
        expect(last.status).toBe(200);
      }
    }
    expect(last?.status).toBe(429);
    expect(JSON.parse(last!.body)).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32000, message: "Too many requests" },
    });
  });

  it("does not rate limit /healthz", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1" }));
    for (let i = 0; i < 5; i++) {
      const res = await send(port, { method: "GET", path: "/healthz" });
      expect(res.status).toBe(200);
    }
  });

  // A stand-in for the bearer middleware: sets req.auth.extra.sub from a
  // test-only header, so the rate limiter's per-principal keying can be
  // exercised without going through a real verifier.
  const fakeAuth: RequestHandler = (req, _res, next) => {
    const sub = req.headers["x-sub"];
    if (typeof sub === "string") {
      req.auth = { token: "t", clientId: "c", scopes: [], extra: { sub } };
    }
    next();
  };

  it("keys the limit per principal (sub), not per connection: a different sub gets its own quota", async () => {
    const cfg = httpConfig({ STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1" });
    const app = buildHttpApp(cfg, fakeDb(), [fakeAuth]);
    const server = await new Promise<HttpServer>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    servers.push(server);
    const port = (server.address() as AddressInfo).port;

    expect((await rpc(port, TOOLS_LIST, { "X-Sub": "alice" })).status).toBe(200);
    expect((await rpc(port, TOOLS_LIST, { "X-Sub": "alice" })).status).toBe(429);
    // bob has his own quota: alice being over limit doesn't affect him.
    expect((await rpc(port, TOOLS_LIST, { "X-Sub": "bob" })).status).toBe(200);
  });
});

describe("buildHttpApp: pre-auth IP rate limiting (R18)", () => {
  it("limits an unauthenticated-request flood before it reaches the per-principal limiter: 401 x10 then 429", async () => {
    const cfg = httpConfig({
      STEAMPIPE_MCP_AUTH_MODE: "token",
      STEAMPIPE_MCP_AUTH_TOKEN: STATIC_TOKEN,
      STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1",
    });
    const port = await startWithAuth(cfg);

    for (let i = 0; i < 10; i++) {
      const res = await rpc(port, TOOLS_LIST);
      expect(res.status).toBe(401);
    }
    const eleventh = await rpc(port, TOOLS_LIST);
    expect(eleventh.status).toBe(429);
    expect(JSON.parse(eleventh.body)).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32000, message: "Too many requests" },
    });
  });

  it("stops a flood before it ever reaches the token verifier", async () => {
    const cfg = httpConfig({ STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1" });
    const calls = { count: 0 };
    const countingVerifier: OAuthTokenVerifier = {
      async verifyAccessToken(token) {
        calls.count++;
        throw new InvalidTokenError(`test: always invalid (saw ${token})`);
      },
    };
    const app = buildHttpApp(cfg, fakeDb(), [requireBearerAuth({ verifier: countingVerifier })]);
    const server = await new Promise<HttpServer>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    servers.push(server);
    const port = (server.address() as AddressInfo).port;

    for (let i = 0; i < 10; i++) {
      const res = await rpc(port, TOOLS_LIST, { Authorization: "Bearer whatever" });
      expect(res.status).toBe(401);
    }
    expect(calls.count).toBe(10);

    const eleventh = await rpc(port, TOOLS_LIST, { Authorization: "Bearer whatever" });
    expect(eleventh.status).toBe(429);
    // The verifier was never called for the 11th request: the pre-auth
    // limiter rejected it before extraMiddleware (bearer) ran.
    expect(calls.count).toBe(10);
  });

  it("ignores a spoofed, rotating X-Forwarded-For when TRUST_PROXY is unset: all requests still share one pre-auth bucket", async () => {
    // TRUST_PROXY is deliberately left unset (the default). Express then
    // never consults X-Forwarded-For for req.ip, so a client claiming a
    // different IP on every request must not get itself a fresh pre-auth
    // bucket per claimed IP - it should still trip the real, single bucket
    // keyed on the actual (loopback) socket address.
    const cfg = httpConfig({
      STEAMPIPE_MCP_AUTH_MODE: "token",
      STEAMPIPE_MCP_AUTH_TOKEN: STATIC_TOKEN,
      STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1",
    });
    const port = await startWithAuth(cfg);

    for (let i = 0; i < 10; i++) {
      const res = await rpc(port, TOOLS_LIST, { "X-Forwarded-For": `10.0.0.${i}` });
      expect(res.status).toBe(401);
    }
    const eleventh = await rpc(port, TOOLS_LIST, { "X-Forwarded-For": "10.0.0.99" });
    expect(eleventh.status).toBe(429);
  });
});

describe("buildHttpApp: audit log", () => {
  it("logs tool and sqlSha256 for a steampipe_query call, and never logs the token or SQL text", async () => {
    const cfg = httpConfig({ STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_AUTH_TOKEN: STATIC_TOKEN });
    const port = await startWithAuth(cfg);

    const sql = "select * from aws_account";
    const call = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "steampipe_query", arguments: { sql } },
    };
    const res = await rpc(port, call, { Authorization: `Bearer ${STATIC_TOKEN}` });
    expect(res.status).toBe(200);

    const expectedSha = createHash("sha256").update(sql, "utf8").digest("hex").slice(0, 16);
    const logs = logger.getCollectedLogs();
    const auditLine = logs.find((line) => line.includes('"tool":"steampipe_query"'));
    expect(auditLine).toBeDefined();
    expect(auditLine).toContain(`"sqlSha256":"${expectedSha}"`);
    expect(auditLine).toContain('"method":"tools/call"');
    expect(auditLine).toContain('"sub":"static"');
    expect(auditLine).toContain('"clientId":"static"');
    expect(auditLine).toContain('"status":200');

    const joined = logs.join("\n");
    expect(joined).not.toContain(STATIC_TOKEN);
    expect(joined).not.toContain(sql);
  });

  it("logs the SQL text at debug level only, never at info level", async () => {
    logger.configure({ isTestEnvironment: true, level: LogLevel.DEBUG });
    logger.clearLogs();
    const cfg = httpConfig({ STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_AUTH_TOKEN: STATIC_TOKEN });
    const port = await startWithAuth(cfg);

    const sql = "select * from aws_account where account_id = 'debug-marker'";
    const call = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "steampipe_query", arguments: { sql } },
    };
    await rpc(port, call, { Authorization: `Bearer ${STATIC_TOKEN}` });

    const logs = logger.getCollectedLogs();
    const debugLines = logs.filter((line) => line.includes("[DEBUG]"));
    const infoLines = logs.filter((line) => line.includes("[INFO]"));
    expect(debugLines.some((line) => line.includes(sql))).toBe(true);
    expect(infoLines.some((line) => line.includes(sql))).toBe(false);
  });

  it("logs sub=anonymous and clientId=none for an unauthenticated request in none mode", async () => {
    const port = await start(httpConfig());
    await rpc(port, TOOLS_LIST);
    const logs = logger.getCollectedLogs();
    const auditLine = logs.find((line) => line.includes('"method":"tools/list"'));
    expect(auditLine).toBeDefined();
    expect(auditLine).toContain('"sub":"anonymous"');
    expect(auditLine).toContain('"clientId":"none"');
  });

  it("does not write an audit line for a 401 (no token)", async () => {
    const cfg = httpConfig({ STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_AUTH_TOKEN: STATIC_TOKEN });
    const port = await startWithAuth(cfg);
    const res = await rpc(port, TOOLS_LIST);
    expect(res.status).toBe(401);
    const logs = logger.getCollectedLogs();
    expect(logs.some((line) => line.includes('"method":"tools/list"'))).toBe(false);
  });
});
