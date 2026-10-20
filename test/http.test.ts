import { afterEach, describe, expect, it, vi } from "vitest";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { loadConfig, type ServerConfig } from "../src/config.js";
import { DatabaseService } from "../src/services/database.js";
import { logger } from "../src/services/logger.js";
import { buildHttpApp } from "../src/http/app.js";
import { testDbUrl } from "./helpers/db.js";

// tools/list and initialize never touch the DB (the pool is lazy), so these
// tests run without TEST_DATABASE_URL.
function newDb(): DatabaseService {
  return new DatabaseService({
    connectionString: testDbUrl() || "postgresql://steampipe@localhost:9193/steampipe",
    maxRows: 10000,
    statementTimeoutMs: 120000,
    poolMax: 1,
    exposeConnectionDetails: false,
  });
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

afterEach(async () => {
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
  vi.restoreAllMocks();
});

// Always bind the test listener to loopback, whatever cfg.http.host says:
// the non-loopback branches only change which Host validation is chosen.
async function start(cfg: ServerConfig): Promise<number> {
  const app = buildHttpApp(cfg, newDb());
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

// node:http rather than fetch: undici does not let callers override `Host`.
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

const INITIALIZE = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "http-test", version: "1.0.0" },
  },
};

const TOOLS_LIST = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };

describe("buildHttpApp: stateless Streamable HTTP", () => {
  it("serves initialize then tools/list without a session header and never issues mcp-session-id", async () => {
    const port = await start(httpConfig());

    const init = await rpc(port, INITIALIZE);
    expect(init.status).toBe(200);
    expect(init.headers["mcp-session-id"]).toBeUndefined();
    expect(JSON.parse(init.body).result.serverInfo.name).toBe("steampipe");

    const list = await rpc(port, TOOLS_LIST);
    expect(list.status).toBe(200);
    expect(list.headers["mcp-session-id"]).toBeUndefined();
    const tools = JSON.parse(list.body).result.tools.map((t: { name: string }) => t.name).sort();
    expect(tools).toEqual([
      "steampipe_plugin_list",
      "steampipe_plugin_show",
      "steampipe_query",
      "steampipe_table_list",
      "steampipe_table_show",
    ]);
  });

  it("answers GET and DELETE on the MCP path with 405 and Allow: POST", async () => {
    const port = await start(httpConfig());
    for (const method of ["GET", "DELETE"]) {
      const res = await send(port, { method });
      expect(res.status).toBe(405);
      expect(res.headers["allow"]).toBe("POST");
    }
  });

  it("serves /healthz with 200 {status: ok}", async () => {
    const port = await start(httpConfig());
    const res = await send(port, { method: "GET", path: "/healthz" });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: "ok" });
  });

  it("honours a custom HTTP_PATH", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_HTTP_PATH: "/custom" }));
    const res = await send(port, {
      path: "/custom",
      headers: MCP_HEADERS,
      body: JSON.stringify(TOOLS_LIST),
    });
    expect(res.status).toBe(200);
  });

  it("answers unknown routes with a JSON 404, not Express's HTML page", async () => {
    const port = await start(httpConfig());
    const res = await send(port, { method: "POST", path: "/healthz" });
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body)).toMatchObject({ jsonrpc: "2.0", error: { code: -32000 } });
  });

  it("does not advertise Express via X-Powered-By", async () => {
    const port = await start(httpConfig());
    const res = await send(port, { method: "GET", path: "/healthz" });
    expect(res.headers["x-powered-by"]).toBeUndefined();
  });
});

describe("buildHttpApp: Origin validation", () => {
  const FORBIDDEN = { jsonrpc: "2.0", error: { code: -32000, message: "Forbidden origin" } };

  it("rejects a foreign Origin with 403", async () => {
    const port = await start(httpConfig());
    const res = await rpc(port, TOOLS_LIST, { Origin: "https://evil.example" });
    expect(res.status).toBe(403);
    expect(JSON.parse(res.body)).toEqual(FORBIDDEN);
  });

  it("rejects Origin: null with 403 when null is not allowlisted", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_ALLOWED_ORIGINS: "https://app.example" }));
    const res = await rpc(port, TOOLS_LIST, { Origin: "null" });
    expect(res.status).toBe(403);
    expect(JSON.parse(res.body)).toEqual(FORBIDDEN);
  });

  it("accepts Origin: null only when the literal null is allowlisted", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_ALLOWED_ORIGINS: "null" }));
    const res = await rpc(port, TOOLS_LIST, { Origin: "null" });
    expect(res.status).toBe(200);
  });

  it("accepts an allowlisted Origin", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_ALLOWED_ORIGINS: "https://app.example" }));
    const res = await rpc(port, TOOLS_LIST, { Origin: "https://app.example" });
    expect(res.status).toBe(200);
  });

  it("requires an exact Origin match (no prefix or suffix tricks)", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_ALLOWED_ORIGINS: "https://app.example" }));
    for (const origin of ["https://app.example.evil", "https://app.example:8443", "http://app.example"]) {
      const res = await rpc(port, TOOLS_LIST, { Origin: origin });
      expect(res.status).toBe(403);
    }
  });

  it("lets a request without an Origin header through", async () => {
    const port = await start(httpConfig());
    const res = await rpc(port, TOOLS_LIST);
    expect(res.status).toBe(200);
  });

  it("applies Origin validation to /healthz too", async () => {
    const port = await start(httpConfig());
    const res = await send(port, { method: "GET", path: "/healthz", headers: { Origin: "https://evil.example" } });
    expect(res.status).toBe(403);
  });
});

describe("buildHttpApp: Host validation (R2)", () => {
  it("loopback bind: accepts localhost Hosts and rejects Host: evil.example", async () => {
    const port = await start(httpConfig());
    expect((await rpc(port, TOOLS_LIST, { Host: `localhost:${port}` })).status).toBe(200);
    expect((await rpc(port, TOOLS_LIST, { Host: `127.0.0.1:${port}` })).status).toBe(200);
    expect((await rpc(port, TOOLS_LIST, { Host: "evil.example" })).status).toBe(403);
  });

  it("non-loopback bind with ALLOWED_HOSTS: allows listed hostnames (case/port-insensitive) only", async () => {
    const warn = vi.spyOn(logger, "warn");
    const port = await start(
      httpConfig({
        STEAMPIPE_MCP_HTTP_HOST: "0.0.0.0",
        STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE: "true",
        STEAMPIPE_MCP_ALLOWED_HOSTS: "MCP.example.com:443",
      }),
    );
    expect((await rpc(port, TOOLS_LIST, { Host: "mcp.example.com" })).status).toBe(200);
    expect((await rpc(port, TOOLS_LIST, { Host: "mcp.example.com:8443" })).status).toBe(200);
    expect((await rpc(port, TOOLS_LIST, { Host: "evil.example" })).status).toBe(403);
    expect((await rpc(port, TOOLS_LIST, { Host: `127.0.0.1:${port}` })).status).toBe(403);
    expect(warn).not.toHaveBeenCalled();
  });

  it("non-loopback bind without ALLOWED_HOSTS falls back to the PUBLIC_URL hostname", async () => {
    const warn = vi.spyOn(logger, "warn");
    const port = await start(
      httpConfig({
        STEAMPIPE_MCP_HTTP_HOST: "0.0.0.0",
        STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE: "true",
        STEAMPIPE_MCP_PUBLIC_URL: "https://mcp.example.com/mcp",
      }),
    );
    expect((await rpc(port, TOOLS_LIST, { Host: "mcp.example.com" })).status).toBe(200);
    expect((await rpc(port, TOOLS_LIST, { Host: "evil.example" })).status).toBe(403);
    expect(warn).not.toHaveBeenCalled();
  });

  it("non-loopback bind with neither ALLOWED_HOSTS nor PUBLIC_URL skips Host validation and warns once", async () => {
    const warn = vi.spyOn(logger, "warn");
    const port = await start(
      httpConfig({
        STEAMPIPE_MCP_HTTP_HOST: "0.0.0.0",
        STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE: "true",
      }),
    );
    expect((await rpc(port, TOOLS_LIST, { Host: "anything.example" })).status).toBe(200);
    expect((await rpc(port, TOOLS_LIST, { Host: "evil.example" })).status).toBe(200);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toMatch(/Host header validation is disabled/);
  });
});

describe("buildHttpApp: request body limits", () => {
  it("rejects a 4 KB body with 413 when MAX_BODY_BYTES=2048", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_MAX_BODY_BYTES: "2048" }));
    const padded = { ...TOOLS_LIST, params: { _meta: { pad: "x".repeat(4096) } } };
    const res = await rpc(port, padded);
    expect(res.status).toBe(413);
    expect(JSON.parse(res.body)).toMatchObject({ jsonrpc: "2.0", error: { code: -32000 } });
  });

  it("accepts a body under MAX_BODY_BYTES", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_MAX_BODY_BYTES: "2048" }));
    expect((await rpc(port, TOOLS_LIST)).status).toBe(200);
  });

  it("rejects a non-JSON Content-Type with 415 rather than letting the transport read the raw body", async () => {
    const port = await start(httpConfig({ STEAMPIPE_MCP_MAX_BODY_BYTES: "2048" }));
    for (const contentType of ["text/plain", "application/json-patch+json"]) {
      const res = await send(port, {
        headers: { ...MCP_HEADERS, "Content-Type": contentType },
        body: JSON.stringify({ ...TOOLS_LIST, params: { _meta: { pad: "x".repeat(4096) } } }),
      });
      expect([413, 415]).toContain(res.status);
      expect(res.body).not.toContain("steampipe_query");
    }
  });

  it("answers malformed JSON with 400 and a JSON-RPC parse error, not an HTML page", async () => {
    const port = await start(httpConfig());
    const res = await send(port, { headers: MCP_HEADERS, body: "{not json" });
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body)).toMatchObject({ jsonrpc: "2.0", error: { code: -32700 } });
    expect(res.body).not.toContain("not json");
  });
});

describe("buildHttpApp: extraMiddleware hook", () => {
  it("runs extraMiddleware on the MCP route only, leaving /healthz untouched", async () => {
    const cfg = httpConfig();
    const app = buildHttpApp(cfg, newDb(), [
      (_req, res) => {
        res.status(401).json({ error: "blocked by extra middleware" });
      },
    ]);
    const server = await new Promise<HttpServer>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    servers.push(server);
    const port = (server.address() as AddressInfo).port;

    expect((await rpc(port, TOOLS_LIST)).status).toBe(401);
    expect((await send(port, { method: "GET", path: "/healthz" })).status).toBe(200);
  });
});
