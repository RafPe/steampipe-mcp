import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createServer as createNodeServer,
  request as httpRequest,
  type Server as HttpServer,
} from "node:http";
import type { AddressInfo } from "node:net";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { loadConfig, type ServerConfig } from "../src/config.js";
import type { DatabaseService } from "../src/services/database.js";
import { buildHttpApp } from "../src/http/app.js";
import { auditAuthReject } from "../src/http/audit.js";
import { authMiddleware } from "../src/auth/index.js";
import { logger, LogLevel } from "../src/services/logger.js";

// No test here talks to Google: tokeninfo is served by an in-test HTTP
// server, and the metadata fetcher is injected.

const STATIC_TOKEN = "s".repeat(40);
const CLIENT = "our-client.apps.googleusercontent.com";
const OTHER_CLIENT = "someone-else.apps.googleusercontent.com";
const PUBLIC_URL = "http://127.0.0.1/mcp";

const FAKE_GOOGLE_METADATA: OAuthMetadata = {
  issuer: "https://accounts.google.com",
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint: "https://oauth2.googleapis.com/token",
  response_types_supported: ["code"],
};

// tools/list never touches the database.
function fakeDb(): DatabaseService {
  return {} as unknown as DatabaseService;
}

function httpConfig(env: Record<string, string>): ServerConfig {
  return loadConfig({ STEAMPIPE_MCP_TRANSPORT: "http", ...env }, ["node", "index.js"]);
}

function tokenConfig(): ServerConfig {
  return httpConfig({ STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_AUTH_TOKEN: STATIC_TOKEN });
}

function googleConfig(): ServerConfig {
  return httpConfig({
    STEAMPIPE_MCP_AUTH_MODE: "google",
    STEAMPIPE_MCP_PUBLIC_URL: PUBLIC_URL,
    STEAMPIPE_MCP_GOOGLE_CLIENT_ID: CLIENT,
    STEAMPIPE_MCP_ALLOWED_DOMAINS: "corp.com",
  });
}

let servers: HttpServer[] = [];

beforeEach(() => {
  // DEBUG, so "never contains the token" also covers debug lines.
  logger.configure({ isTestEnvironment: true, level: LogLevel.DEBUG });
  logger.clearLogs();
});

afterEach(async () => {
  for (const s of servers) s.closeAllConnections();
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
  vi.restoreAllMocks();
});

async function listen(server: HttpServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

/** Fake Google tokeninfo: answers from `tokens`, keyed by the form-encoded access_token; anything else is 400. */
async function fakeTokeninfo(tokens: Record<string, { status: number; body: unknown }>): Promise<string> {
  const server = createNodeServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const entry = tokens[new URLSearchParams(body).get("access_token") ?? ""];
      res.writeHead(entry?.status ?? 400, { "Content-Type": "application/json" });
      res.end(JSON.stringify(entry?.body ?? { error: "invalid_token" }));
    });
  });
  return `http://127.0.0.1:${await listen(server)}/tokeninfo`;
}

async function startApp(cfg: ServerConfig, tokeninfoUrl?: string): Promise<number> {
  const { rootRouters, mcpMiddleware } = await authMiddleware(cfg, {
    metadataFetcher: async () => FAKE_GOOGLE_METADATA,
    tokeninfoUrl,
  });
  const app = buildHttpApp(cfg, fakeDb(), mcpMiddleware, rootRouters);
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

function toolsList(port: number, token?: string): Promise<number> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (token !== undefined) headers.Authorization = `Bearer ${token}`;
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/mcp", headers }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }));
  });
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function tokeninfo(overrides: Record<string, unknown> = {}): { status: number; body: unknown } {
  return {
    status: 200,
    body: {
      aud: CLIENT,
      azp: CLIENT,
      sub: "1234",
      email: "a@corp.com",
      email_verified: "true",
      exp: String(nowSec() + 3600),
      ...overrides,
    },
  };
}

/** Every collected line whose JSON payload has `event: "auth_reject"`, parsed. */
function rejectLines(): Array<{ level: string; entry: Record<string, unknown> }> {
  const out: Array<{ level: string; entry: Record<string, unknown> }> = [];
  for (const line of logger.getCollectedLogs()) {
    const brace = line.indexOf("{");
    if (brace === -1) continue;
    let entry: unknown;
    try {
      entry = JSON.parse(line.slice(brace));
    } catch {
      continue;
    }
    if (typeof entry === "object" && entry !== null && (entry as Record<string, unknown>).event === "auth_reject") {
      out.push({ level: line.match(/\[(DEBUG|INFO|WARN|ERROR)\]/)?.[1] ?? "", entry: entry as Record<string, unknown> });
    }
  }
  return out;
}

/** Exactly one auth_reject line was written, at info level; returns it. */
function onlyRejectLine(): Record<string, unknown> {
  const lines = rejectLines();
  expect(lines).toHaveLength(1);
  expect(lines[0].level).toBe("INFO");
  return lines[0].entry;
}

function expectNoLineContains(token: string): void {
  for (const line of logger.getCollectedLogs()) {
    expect(line).not.toContain(token);
  }
}

describe("auth_reject audit: token mode", () => {
  it("logs reason=missing with status 401 when no token is sent", async () => {
    const port = await startApp(tokenConfig());
    expect(await toolsList(port)).toBe(401);
    const entry = onlyRejectLine();
    expect(entry).toMatchObject({ event: "auth_reject", reason: "missing", status: 401, ip: "127.0.0.1" });
    expect(typeof entry.durationMs).toBe("number");
  });

  it("logs reason=invalid for a wrong token, and never the token itself", async () => {
    const wrong = "wrong-token-marker-" + "w".repeat(30);
    const port = await startApp(tokenConfig());
    expect(await toolsList(port, wrong)).toBe(401);
    expect(onlyRejectLine()).toMatchObject({ event: "auth_reject", reason: "invalid", status: 401 });
    expectNoLineContains(wrong);
    expectNoLineContains(STATIC_TOKEN);
  });

  it("writes one normal audit line and no auth_reject line for a successful call", async () => {
    const port = await startApp(tokenConfig());
    expect(await toolsList(port, "x".repeat(40))).toBe(401);
    expect(await toolsList(port, STATIC_TOKEN)).toBe(200);
    // The rejected request accounts for the only auth_reject line.
    expect(onlyRejectLine()).toMatchObject({ reason: "invalid" });
    const auditLines = logger.getCollectedLogs().filter((line) => line.includes('"method":"tools/list"'));
    expect(auditLines).toHaveLength(1);
    expect(auditLines[0]).toContain('"status":200');
    expect(auditLines[0]).not.toContain("auth_reject");
    expectNoLineContains(STATIC_TOKEN);
  });
});

describe("auth_reject audit: google mode", () => {
  const cases: Array<{ name: string; token: string; answer: { status: number; body: unknown }; reason: string; status: number }> = [
    {
      name: "aud names another client",
      token: "google-token-audience-marker",
      answer: tokeninfo({ aud: OTHER_CLIENT }),
      reason: "audience",
      status: 401,
    },
    {
      name: "the token has expired",
      token: "google-token-expired-marker",
      answer: tokeninfo({ exp: String(nowSec() - 60) }),
      reason: "expired",
      status: 401,
    },
    {
      name: "the principal is not allowlisted",
      token: "google-token-not-allowed-marker",
      answer: tokeninfo({ email: "eve@elsewhere.com" }),
      reason: "not_allowed",
      status: 403,
    },
    {
      name: "tokeninfo answers 503",
      token: "google-token-unavailable-marker",
      answer: { status: 503, body: { error: "backend_error" } },
      reason: "issuer_unavailable",
      status: 503,
    },
  ];

  for (const c of cases) {
    it(`logs reason=${c.reason} with status ${c.status} when ${c.name}, and never the token`, async () => {
      const url = await fakeTokeninfo({ [c.token]: c.answer });
      const port = await startApp(googleConfig(), url);
      expect(await toolsList(port, c.token)).toBe(c.status);
      expect(onlyRejectLine()).toMatchObject({ event: "auth_reject", reason: c.reason, status: c.status, ip: "127.0.0.1" });
      expectNoLineContains(c.token);
    });
  }

  it("writes one normal audit line and no auth_reject line for an accepted Google token", async () => {
    const token = "google-token-ok-marker";
    const url = await fakeTokeninfo({ [token]: tokeninfo() });
    const port = await startApp(googleConfig(), url);
    // tokeninfo answers 400 for any unknown token.
    expect(await toolsList(port, "google-token-unknown-marker")).toBe(401);
    expect(await toolsList(port, token)).toBe(200);
    // The rejected request accounts for the only auth_reject line.
    expect(onlyRejectLine()).toMatchObject({ reason: "invalid" });
    expect(logger.getCollectedLogs().filter((line) => line.includes('"method":"tools/list"'))).toHaveLength(1);
    expectNoLineContains(token);
  });
});

describe("auditAuthReject", () => {
  it("writes the fields in order, at info level", () => {
    auditAuthReject({ reason: "expired", status: 401, ip: "10.0.0.1", iss: "https://issuer", sub: "u1", durationMs: 7 });
    const lines = logger.getCollectedLogs();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("[INFO]");
    expect(lines[0].slice(lines[0].indexOf("{"))).toBe(
      '{"event":"auth_reject","reason":"expired","status":401,"ip":"10.0.0.1","iss":"https://issuer","sub":"u1","durationMs":7}',
    );
  });

  it("omits iss and sub when absent, and logs an unknown ip as \"unknown\"", () => {
    auditAuthReject({ reason: "missing", status: 401, ip: undefined, durationMs: 0 });
    expect(onlyRejectLine()).toEqual({ event: "auth_reject", reason: "missing", status: 401, ip: "unknown", durationMs: 0 });
  });

  it("passes ip, iss and sub through boundForLog", () => {
    auditAuthReject({
      reason: "invalid",
      status: 401,
      ip: "1.2.3.4\r\nforged",
      iss: "https://iss‮\u0000x",
      sub: "a".repeat(300),
      durationMs: 1,
    });
    const lines = logger.getCollectedLogs();
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toMatch(/[\r\n‮]/);
    const entry = onlyRejectLine();
    expect(entry.ip).toBe("1.2.3.4forged");
    expect(entry.iss).toBe("https://issx");
    expect(entry.sub).toBe(`${"a".repeat(256)}…(+44)`);
  });
});
