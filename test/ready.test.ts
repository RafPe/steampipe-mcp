import { afterEach, describe, expect, it, vi } from "vitest";
import pg from "pg";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import { createServer as createTcpServer, type AddressInfo, type Server as TcpServer, type Socket } from "node:net";
import { loadConfig, type ServerConfig } from "../src/config.js";
import { DatabaseService } from "../src/services/database.js";
import { buildHttpApp } from "../src/http/app.js";
import { Readiness, type CheckStatus } from "../src/http/ready.js";
import { describeDb, testDbUrl } from "./helpers/db.js";

function newDb(connectionString = testDbUrl() || "postgresql://steampipe@localhost:9193/steampipe"): DatabaseService {
  return new DatabaseService({
    connectionString,
    maxRows: 10000,
    statementTimeoutMs: 120000,
    poolMax: 1,
    exposeConnectionDetails: false,
  });
}

function httpConfig(env: Record<string, string> = {}): ServerConfig {
  return loadConfig({ STEAMPIPE_MCP_TRANSPORT: "http", ...env }, ["node", "index.js"]);
}

let servers: HttpServer[] = [];
let tcpServers: TcpServer[] = [];
let heldSockets: Socket[] = [];

afterEach(async () => {
  for (const s of heldSockets) s.destroy();
  heldSockets = [];
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  await Promise.all(tcpServers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
  tcpServers = [];
  vi.restoreAllMocks();
});

async function start(readiness: Readiness, cfg: ServerConfig = httpConfig()): Promise<number> {
  const app = buildHttpApp(cfg, newDb(), [], [], readiness);
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

// node:http rather than fetch: undici does not let callers override `Host`.
function get(port: number, path = "/readyz", headers: Record<string, string> = {}): Promise<Response> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "GET", path, headers, agent: false }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

const never = () => new Promise<CheckStatus>(() => {});
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("Readiness.evaluate", () => {
  it("is ready with no checks registered", async () => {
    await expect(new Readiness().evaluate()).resolves.toEqual({ ready: true, checks: {} });
  });

  it("is ready only when every check is ready", async () => {
    const r = new Readiness();
    r.register({ name: "a", check: async () => "ready" });
    r.register({ name: "b", check: async () => "pending" });
    await expect(r.evaluate()).resolves.toEqual({ ready: false, checks: { a: "ready", b: "pending" } });
  });

  it("maps a rejecting, synchronously throwing or invalid check to failing", async () => {
    const r = new Readiness();
    r.register({ name: "rejects", check: async () => { throw new Error("boom"); } });
    r.register({ name: "throws", check: () => { throw new Error("sync boom"); } });
    r.register({ name: "bogus", check: async () => "yes" as unknown as CheckStatus });
    await expect(r.evaluate()).resolves.toEqual({
      ready: false,
      checks: { rejects: "failing", throws: "failing", bogus: "failing" },
    });
  });

  it("times out a check that never settles as failing and aborts its signal", async () => {
    const r = new Readiness({ timeoutMs: 50 });
    let seen: AbortSignal | undefined;
    r.register({ name: "hang", check: (signal) => { seen = signal; return never(); } });
    const t0 = Date.now();
    await expect(r.evaluate()).resolves.toEqual({ ready: false, checks: { hang: "failing" } });
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(seen?.aborted).toBe(true);
  });

  it("does not abort the signal of a check that settles in time", async () => {
    const r = new Readiness({ timeoutMs: 50 });
    let seen: AbortSignal | undefined;
    r.register({ name: "ok", check: async (signal) => { seen = signal; return "ready"; } });
    await r.evaluate();
    await delay(80);
    expect(seen?.aborted).toBe(false);
  });

  it("shares one in-flight evaluation between concurrent callers", async () => {
    const r = new Readiness();
    let calls = 0;
    r.register({ name: "x", check: async () => { calls++; await delay(50); return "ready"; } });
    const results = await Promise.all(Array.from({ length: 5 }, () => r.evaluate()));
    expect(calls).toBe(1);
    for (const res of results) expect(res.ready).toBe(true);
  });

  it("reuses a result for cacheMs, then evaluates again", async () => {
    let clock = 1000;
    const r = new Readiness({ cacheMs: 1000, now: () => clock });
    let calls = 0;
    r.register({ name: "x", check: async () => { calls++; return calls === 1 ? "pending" : "ready"; } });
    expect((await r.evaluate()).checks.x).toBe("pending");
    clock += 999;
    expect((await r.evaluate()).checks.x).toBe("pending");
    expect(calls).toBe(1);
    clock += 1;
    expect((await r.evaluate()).checks.x).toBe("ready");
    expect(calls).toBe(2);
  });
});

describe("GET /readyz", () => {
  it("returns 200 ready with no checks", async () => {
    const port = await start(new Readiness());
    const res = await get(port);
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: "ready", checks: {} });
  });

  it("returns 503 not_ready with a pending check", async () => {
    const r = new Readiness();
    r.register({ name: "x", check: async () => "pending" });
    const port = await start(r);
    const res = await get(port);
    expect(res.status).toBe(503);
    expect(JSON.parse(res.body)).toEqual({ status: "not_ready", checks: { x: "pending" } });
  });

  it("reports names and statuses only, never a check's error message", async () => {
    const r = new Readiness();
    r.register({ name: "x", check: async () => { throw new Error("secret detail"); } });
    const port = await start(r);
    const res = await get(port);
    expect(res.status).toBe(503);
    expect(res.body).not.toContain("secret detail");
    expect(JSON.parse(res.body)).toEqual({ status: "not_ready", checks: { x: "failing" } });
  });

  // Review Focus 5
  it("answers 503 in under 2500 ms when a check never settles (default timeout)", async () => {
    const r = new Readiness();
    r.register({ name: "hang", check: never });
    const port = await start(r);
    const t0 = Date.now();
    const res = await get(port);
    expect(Date.now() - t0).toBeLessThan(2500);
    expect(res.status).toBe(503);
    expect(JSON.parse(res.body)).toEqual({ status: "not_ready", checks: { hang: "failing" } });
  });

  // Review Focus 5
  it("coalesces 20 concurrent probes into a single check invocation", async () => {
    const r = new Readiness();
    let calls = 0;
    r.register({ name: "x", check: async () => { calls++; await delay(200); return "ready"; } });
    const port = await start(r);
    const responses = await Promise.all(Array.from({ length: 20 }, () => get(port)));
    expect(calls).toBe(1);
    for (const res of responses) expect(res.status).toBe(200);
  });

  it("is mounted before Host validation (evil Host on a loopback bind is not 403)", async () => {
    const r = new Readiness();
    r.register({ name: "x", check: async () => "pending" });
    const port = await start(r);
    const res = await get(port, "/readyz", { Host: "evil.example" });
    expect(res.status).toBe(503);
    expect(JSON.parse(res.body).status).toBe("not_ready");

    const ok = await start(new Readiness());
    expect((await get(ok, "/readyz", { Host: "evil.example" })).status).toBe(200);
  });

  it("is mounted before Origin validation", async () => {
    const port = await start(new Readiness());
    expect((await get(port, "/readyz", { Origin: "https://evil.example" })).status).toBe(200);
  });

  it("only answers GET", async () => {
    const port = await start(new Readiness());
    const res = await new Promise<number>((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/readyz", agent: false }, (r) => {
        r.resume();
        resolve(r.statusCode ?? 0);
      });
      req.on("error", reject);
      req.end();
    });
    expect(res).toBe(404);
  });

  it("buildHttpApp without a readiness argument serves an always-ready /readyz", async () => {
    const app = buildHttpApp(httpConfig(), newDb());
    const server = await new Promise<HttpServer>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    servers.push(server);
    const res = await get((server.address() as AddressInfo).port);
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: "ready", checks: {} });
  });
});

describe("DatabaseService.ping", () => {
  // Review Focus 5: a wedged DB that accepts TCP but never answers.
  it("rejects within the timeout against a black-hole server and closes its socket", async () => {
    const accepted: Socket[] = [];
    const closed: Promise<void>[] = [];
    const server = createTcpServer((socket) => {
      accepted.push(socket);
      heldSockets.push(socket);
      closed.push(new Promise((resolve) => socket.on("close", () => resolve())));
      socket.on("error", () => {});
      // Read (so EOF is observed) but hold the socket open and never reply.
      socket.resume();
    });
    tcpServers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;

    const db = newDb(`postgresql://u:secretpw@127.0.0.1:${port}/d?sslmode=disable`);
    const t0 = Date.now();
    await expect(db.ping(500)).rejects.toThrow();
    expect(Date.now() - t0).toBeLessThan(1500);
    expect(accepted.length).toBe(1);
    const sawClose = await Promise.race([Promise.all(closed).then(() => true), delay(1000).then(() => false)]);
    expect(sawClose).toBe(true);
    await db.close();
  });

  /**
   * Minimal Postgres wire-protocol server: accepts the startup message with
   * AuthenticationOk + ReadyForQuery, then either answers every query with
   * an empty result or (`answerQueries: false`) never answers.
   */
  async function fakePg(answerQueries: boolean): Promise<{ port: number; closed: Promise<void> }> {
    let onClose!: () => void;
    const closed = new Promise<void>((resolve) => (onClose = resolve));
    const msg = (type: string, body: Buffer) => {
      const len = Buffer.alloc(4);
      len.writeInt32BE(body.length + 4);
      return Buffer.concat([Buffer.from(type), len, body]);
    };
    const authOk = msg("R", Buffer.from([0, 0, 0, 0]));
    const ready = msg("Z", Buffer.from("I"));
    const server = createTcpServer((socket) => {
      heldSockets.push(socket);
      socket.on("error", () => {});
      socket.on("close", () => onClose());
      let started = false;
      socket.on("data", (chunk) => {
        if (!started) {
          started = true;
          socket.write(Buffer.concat([authOk, ready]));
        } else if (answerQueries && chunk[0] === "Q".charCodeAt(0)) {
          socket.write(Buffer.concat([msg("C", Buffer.from("SELECT 0\0")), ready]));
        }
      });
    });
    tcpServers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return { port: (server.address() as AddressInfo).port, closed };
  }

  const settles = (p: Promise<unknown>, ms: number) =>
    Promise.race([p.then(() => true), delay(ms).then(() => false)]);

  // Review Focus 5: connected, but the query never comes back.
  it("rejects within the timeout when the database wedges after connecting, and closes the socket", async () => {
    const { port, closed } = await fakePg(false);
    const db = newDb(`postgresql://u@127.0.0.1:${port}/d?sslmode=disable`);
    const t0 = Date.now();
    await expect(db.ping(500)).rejects.toThrow();
    expect(Date.now() - t0).toBeLessThan(1500);
    expect(await settles(closed, 1000)).toBe(true);
  });

  it("resolves against a database that answers (fake server sanity check)", async () => {
    const { port } = await fakePg(true);
    await expect(newDb(`postgresql://u@127.0.0.1:${port}/d?sslmode=disable`).ping(500)).resolves.toBeUndefined();
  });

  it("destroys the socket when client.end() does not resolve within the timeout", async () => {
    const { port, closed } = await fakePg(true);
    vi.spyOn(pg.Client.prototype, "end").mockImplementation(() => new Promise<void>(() => {}));
    const db = newDb(`postgresql://u@127.0.0.1:${port}/d?sslmode=disable`);
    const t0 = Date.now();
    await expect(db.ping(300)).resolves.toBeUndefined();
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(await settles(closed, 1000)).toBe(true);
  });

  it("does not create the query pool", async () => {
    const db = newDb("postgresql://x@127.0.0.1:1/x?sslmode=disable");
    await expect(db.ping(500)).rejects.toThrow();
    expect((db as unknown as { pool: unknown }).pool).toBeNull();
  });
});

// The local test Postgres has no TLS, and node-postgres does not fall back to
// plaintext (see test/database.test.ts), so force sslmode=disable.
function noTlsUrl(): string {
  const url = new URL(testDbUrl()!);
  if (!url.searchParams.has("sslmode")) {
    url.searchParams.set("sslmode", "disable");
  }
  return url.toString();
}

describeDb("DatabaseService.ping (real database)", () => {
  function dbCheck(db: DatabaseService) {
    return {
      name: "db",
      check: async (): Promise<CheckStatus> => {
        try {
          await db.ping(2000);
          return "ready";
        } catch {
          return "failing";
        }
      },
    };
  }

  it("resolves against the test database without using the pool", async () => {
    const db = newDb(noTlsUrl());
    await expect(db.ping(2000)).resolves.toBeUndefined();
    expect((db as unknown as { pool: unknown }).pool).toBeNull();
    await db.close();
  });

  it("reports db ready against the test database", async () => {
    const db = newDb(noTlsUrl());
    const r = new Readiness();
    r.register(dbCheck(db));
    const port = await start(r);
    const res = await get(port);
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: "ready", checks: { db: "ready" } });
    await db.close();
  });

  it("reports db failing for an unreachable database and never echoes the connection string", async () => {
    const conn = "postgresql://x:topsecret@127.0.0.1:1/x";
    const db = newDb(conn);
    const r = new Readiness();
    r.register(dbCheck(db));
    const port = await start(r);
    const res = await get(port);
    expect(res.status).toBe(503);
    expect(JSON.parse(res.body)).toEqual({ status: "not_ready", checks: { db: "failing" } });
    expect(res.body).not.toContain("topsecret");
    expect(res.body).not.toContain("127.0.0.1:1");
    expect(res.body).not.toContain("postgresql://");
    await db.close();
  });
});
