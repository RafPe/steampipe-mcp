import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EventEmitter } from "node:events";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { Request, RequestHandler, Response as ExpressResponse } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { VerifyError } from "../src/auth/errors.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { boundForLog } from "../src/services/logbound.js";
import { auditMiddleware } from "../src/http/audit.js";
import { buildHttpApp } from "../src/http/app.js";
import { createGoogleVerifier } from "../src/auth/google.js";
import { loadConfig } from "../src/config.js";
import { DatabaseService } from "../src/services/database.js";
import { logger, LogLevel } from "../src/services/logger.js";

// Bidi override (U+202E) and isolate (U+2066) characters, written as escapes
// so this file itself stays free of invisible control characters.
const RLO = "\u202e";
const LRI = "\u2066";

let servers: HttpServer[] = [];

beforeEach(() => {
  logger.configure({ isTestEnvironment: true, level: LogLevel.DEBUG });
  logger.clearLogs();
});

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.map((s) => new Promise<void>((resolve) => s.close(() => resolve()))));
  servers = [];
});

/** Lines containing `marker`, with the "[ts] [LEVEL] " prefix kept. */
function linesWith(marker: string): string[] {
  return logger.getCollectedLogs().filter((line) => line.includes(marker));
}

/** Every collected line must be free of control and bidi characters. */
function expectNoUnsafeChars(lines: string[]): void {
  for (const line of lines) {
    expect(line).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/);
  }
}

describe("boundForLog", () => {
  it("strips a newline and a bidi override", () => {
    expect(boundForLog(`a\nb${RLO}c`)).toBe("abc");
  });

  it("keeps 256 characters and appends the overflow count", () => {
    expect(boundForLog("x".repeat(300))).toBe(`${"x".repeat(256)}…(+44)`);
  });

  it("stringifies undefined", () => {
    expect(boundForLog(undefined)).toBe("undefined");
  });

  it("stringifies other non-strings", () => {
    expect(boundForLog(null)).toBe("null");
    expect(boundForLog(42)).toBe("42");
    expect(boundForLog(new Error("e\r\nf"))).toBe("Error: ef");
  });

  it("strips every C0, DEL and C1 control character", () => {
    let all = "";
    for (let c = 0; c <= 0x1f; c++) all += String.fromCharCode(c);
    for (let c = 0x7f; c <= 0x9f; c++) all += String.fromCharCode(c);
    expect(boundForLog(`[${all}]`)).toBe("[]");
  });

  it("strips U+2028/U+2029 and the bidi embedding, override and isolate ranges", () => {
    const unsafe = "\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069";
    expect(boundForLog(`a${unsafe}b`)).toBe("ab");
  });

  it("keeps neighbouring characters outside the stripped ranges", () => {
    // U+00A0, U+2027, U+202F, U+2065, U+206A and an emoji are all kept.
    const kept = "\u00a0\u2027\u202f\u2065\u206a😀é";
    expect(boundForLog(kept)).toBe(kept);
  });

  it("does not append a suffix at exactly max characters", () => {
    expect(boundForLog("x".repeat(256))).toBe("x".repeat(256));
  });

  it("appends +1 at max + 1 characters", () => {
    expect(boundForLog("x".repeat(257))).toBe(`${"x".repeat(256)}…(+1)`);
  });

  it("strips before bounding, so stripped characters do not count", () => {
    expect(boundForLog(`${"x".repeat(256)}\n\n\n${LRI}${RLO}`)).toBe("x".repeat(256));
  });

  it("honours a custom max", () => {
    expect(boundForLog("abcdef", 3)).toBe("abc…(+3)");
  });

  it("counts code points, so a surrogate pair is never split", () => {
    expect(boundForLog("😀😀😀", 2)).toBe("😀😀…(+1)");
  });

  it("does not throw for a value String() cannot convert", () => {
    expect(() => boundForLog(Object.create(null))).not.toThrow();
  });

  it("returns a constant fallback for a value no conversion can handle", () => {
    // A revoked Proxy makes both String() and Object.prototype.toString throw.
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    expect(boundForLog(proxy)).toBe("[unprintable]");
  });
});

/** Run the audit middleware against a fake req/res and return the audit JSON. */
function runAudit(body: unknown, auth?: AuthInfo): { line: string; event: Record<string, unknown> } {
  const req = { body, auth } as unknown as Request;
  const res = Object.assign(new EventEmitter(), { statusCode: 200 }) as unknown as ExpressResponse;
  auditMiddleware()(req, res, () => {});
  logger.clearLogs();
  (res as unknown as EventEmitter).emit("finish");
  const [line] = linesWith("[INFO]");
  expect(line).toBeDefined();
  const json = line.slice(line.indexOf("{"));
  return { line, event: JSON.parse(json) as Record<string, unknown> };
}

describe("audit line", () => {
  it("strips a forged-JSON tool name to one line", () => {
    const { line, event } = runAudit({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: 'x\n{"forged":1}' },
    });
    expect(line).not.toContain("\n");
    expect(line).not.toContain("\\n");
    expect(event.tool).toBe('x{"forged":1}');
  });

  it("bounds and sanitises the method", () => {
    const { event } = runAudit({ jsonrpc: "2.0", id: 1, method: `m${RLO}${"y".repeat(299)}` });
    expect(event.method).toBe(`m${"y".repeat(255)}…(+44)`);
  });

  it("bounds and sanitises the token-derived sub and clientId", () => {
    const forged = `a\nb${"c".repeat(298)}`;
    const auth: AuthInfo = { token: "t", clientId: forged, scopes: [], extra: { sub: forged } };
    const { line, event } = runAudit({ jsonrpc: "2.0", id: 1, method: "tools/list" }, auth);
    expect(line).not.toContain("\n");
    expect(line).not.toContain("\\n");
    const bounded = `ab${"c".repeat(254)}…(+44)`;
    expect(event.sub).toBe(bounded);
    expect(event.clientId).toBe(bounded);
  });
});

describe("debug SQL line", () => {
  /** Run the audit middleware for a steampipe_query call and return its debug SQL lines. */
  function sqlLines(sql: string): string[] {
    const req = {
      body: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "steampipe_query", arguments: { sql } } },
    } as unknown as Request;
    const res = Object.assign(new EventEmitter(), { statusCode: 200 }) as unknown as ExpressResponse;
    auditMiddleware()(req, res, () => {});
    return linesWith("[DEBUG] steampipe_query SQL");
  }

  it("strips control and bidi characters from the SQL", () => {
    const lines = sqlLines(`select 1\n[INFO] forged${RLO} from x`);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("select 1[INFO] forged from x");
    expectNoUnsafeChars(lines);
  });

  it("caps the SQL at 8192 characters", () => {
    const lines = sqlLines("s".repeat(9000));
    expect(lines).toHaveLength(1);
    expect(lines[0].endsWith(`${"s".repeat(8192)}…(+808)`)).toBe(true);
  });
});

describe("app error logs", () => {
  function cfg() {
    return loadConfig({ STEAMPIPE_MCP_TRANSPORT: "http" }, ["node", "index.js"]);
  }

  async function start(rootRouters: RequestHandler[] = []): Promise<number> {
    const db = { executeUserQuery: async () => ({ rows: [], truncated: false }) } as unknown as DatabaseService;
    const app = buildHttpApp(cfg(), db, [], rootRouters);
    const server = await new Promise<HttpServer>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    servers.push(server);
    return (server.address() as AddressInfo).port;
  }

  function post(port: number): Promise<number> {
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          method: "POST",
          path: "/mcp",
          headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        },
      );
      req.on("error", reject);
      req.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }));
    });
  }

  it("sanitises the error text logged by the Express error handler", async () => {
    const port = await start([(_req, _res, next) => next(new Error(`boom\n[ERROR] forged${RLO}`))]);
    expect(await post(port)).toBe(500);
    const lines = linesWith("HTTP request failed");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("boom[ERROR] forged");
    expectNoUnsafeChars(lines);
  });

  it("bounds the error text logged when an MCP request fails", async () => {
    vi.spyOn(StreamableHTTPServerTransport.prototype, "handleRequest").mockRejectedValue(
      new Error(`a\nb${"z".repeat(400)}`),
    );
    const port = await start();
    expect(await post(port)).toBe(500);
    const lines = linesWith("MCP request failed");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain(`ab${"z".repeat(254)}…(+146)`);
    expectNoUnsafeChars(lines);
  });
});

describe("database error logs", () => {
  const UNSAFE = `bad\nline${RLO}`;

  function newDb(): DatabaseService {
    return new DatabaseService({
      connectionString: "postgresql://u@127.0.0.1:1/d",
      maxRows: 0,
      statementTimeoutMs: 1000,
      poolMax: 1,
      exposeConnectionDetails: false,
    });
  }

  /** A fake pg client whose query rejects for the given statement prefixes. */
  function fakePool(failOn: string[]): { connect: () => Promise<unknown> } {
    const client = {
      query: async (q: unknown) => {
        const text = typeof q === "string" ? q : "";
        if (failOn.some((prefix) => text.startsWith(prefix))) {
          throw new Error(`${text}: ${UNSAFE}`);
        }
        return { rows: [] };
      },
      release: () => {},
    };
    return { connect: async () => client };
  }

  function withPool(db: DatabaseService, pool: unknown): DatabaseService {
    (db as unknown as { pool: unknown }).pool = pool;
    return db;
  }

  it("sanitises an idle pool error", async () => {
    const db = newDb();
    const pool = (db as unknown as { getPool(): EventEmitter }).getPool();
    pool.emit("error", new Error(UNSAFE));
    const lines = linesWith("Unexpected pool error");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("badline");
    expectNoUnsafeChars(lines);
    await db.close();
  });

  it("sanitises a connection error logged at debug", async () => {
    const db = withPool(newDb(), {
      connect: async () => {
        throw new Error(UNSAFE);
      },
    });
    await expect(db.executeQuery("select 1")).rejects.toThrow();
    const lines = linesWith("Database connection error");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("badline");
    expectNoUnsafeChars(lines);
  });

  it("sanitises the stale-connection retry log", async () => {
    const db = withPool(newDb(), fakePool(["BEGIN"]));
    await expect(db.executeQuery("select 1")).rejects.toThrow();
    const lines = linesWith("Stale database connection");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("badline");
    expectNoUnsafeChars(lines);
  });

  it("sanitises rollback and discard failures", async () => {
    const db = withPool(newDb(), fakePool(["select", "ROLLBACK", "DISCARD"]));
    await expect(db.executeQuery("select 1")).rejects.toThrow();
    const lines = [...linesWith("Error rolling back"), ...linesWith("Error resetting session")];
    expect(lines).toHaveLength(2);
    for (const line of lines) expect(line).toContain("badline");
    expectNoUnsafeChars(lines);
  });
});

describe("google debug email logs", () => {
  const CLIENT = "our-client.apps.googleusercontent.com";

  function verifier() {
    return createGoogleVerifier({
      clientId: CLIENT,
      allowedEmails: [],
      allowedDomains: ["corp.com"],
      publicUrl: new URL("https://mcp.example"),
      tokeninfoUrl: "https://tokeninfo.invalid",
    });
  }

  function tokeninfo(email: string): void {
    const body = {
      aud: CLIENT,
      sub: "1",
      email,
      email_verified: "true",
      exp: String(Math.floor(Date.now() / 1000) + 3600),
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(body), { status: 200 }));
  }

  it("sanitises the email of an authenticated principal", async () => {
    tokeninfo(`ann${RLO}\n@corp.com`);
    await verifier().verify("t1");
    const lines = linesWith("Google principal authenticated");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("ann@corp.com");
    expectNoUnsafeChars(lines);
  });

  it("sanitises the email of a principal that is not allowed", async () => {
    tokeninfo(`eve\n[INFO] forged${RLO}@other.com`);
    const err: unknown = await verifier()
      .verify("t2")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerifyError);
    expect((err as VerifyError).reason).toBe("not_allowed");
    const lines = linesWith("Google principal not allowed");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("eve[info] forged@other.com");
    expectNoUnsafeChars(lines);
  });
});
