import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createServer as createNodeServer,
  request as httpRequest,
  type IncomingMessage,
  type Server as HttpServer,
} from "node:http";
import type { AddressInfo } from "node:net";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { ConfigError, loadConfig, type ServerConfig } from "../src/config.js";
import { parseDegradedConfig } from "../src/config/degraded.js";
import { createRetryLoader } from "../src/auth/retry-loader.js";
import { authMiddleware, type AuthMiddleware } from "../src/auth/index.js";
import { VerifyError } from "../src/auth/errors.js";
import { fetchGoogleMetadata } from "../src/auth/google.js";
import { buildHttpApp } from "../src/http/app.js";
import { buildReadiness } from "../src/http/ready.js";
import { gracefulShutdown } from "../src/shutdown.js";
import { serveHttp } from "../src/http/compose.js";
import { EventEmitter } from "node:events";
import { DatabaseService } from "../src/services/database.js";
import { logger } from "../src/services/logger.js";
import { testDbUrl } from "./helpers/db.js";

// No test here talks to Google or really waits: tokeninfo is an in-test
// HTTP server, discovery is an injected fetcher, and retry delays go through
// a fake sleep the test releases by hand.

const CLIENT = "our-client.apps.googleusercontent.com";
const PUBLIC_URL = "http://127.0.0.1/mcp";
const PRM = "/.well-known/oauth-protected-resource/mcp";

const FAKE_GOOGLE_METADATA: OAuthMetadata = {
  issuer: "https://accounts.google.com",
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint: "https://oauth2.googleapis.com/token",
  response_types_supported: ["code"],
};

function googleConfig(env: Record<string, string> = {}): ServerConfig {
  return loadConfig(
    {
      STEAMPIPE_MCP_TRANSPORT: "http",
      STEAMPIPE_MCP_AUTH_MODE: "google",
      STEAMPIPE_MCP_PUBLIC_URL: PUBLIC_URL,
      STEAMPIPE_MCP_GOOGLE_CLIENT_ID: CLIENT,
      STEAMPIPE_MCP_ALLOWED_DOMAINS: "corp.com",
      ...env,
    },
    ["node", "index.js"],
  );
}

const DEGRADED = { STEAMPIPE_MCP_ALLOW_DEGRADED_START: "true" };

let warn: ReturnType<typeof vi.spyOn>;
let info: ReturnType<typeof vi.spyOn>;
let error: ReturnType<typeof vi.spyOn>;
let consoleError: ReturnType<typeof vi.spyOn>;
let servers: HttpServer[] = [];
let auths: AuthMiddleware[] = [];

beforeEach(() => {
  warn = vi.spyOn(logger, "warn").mockImplementation(() => {});
  info = vi.spyOn(logger, "info").mockImplementation(() => {});
  error = vi.spyOn(logger, "error").mockImplementation(() => {});
  consoleError = vi.spyOn(console, "error");
});

afterEach(async () => {
  for (const a of auths) a.dispose();
  auths = [];
  for (const s of servers) s.closeAllConnections();
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
  // Nothing in this file may print: every expected log line is spied above.
  expect(consoleError).not.toHaveBeenCalled();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

/**
 * A fake `sleep`: records each requested delay and the signal it got, and
 * only resolves when the test calls `release()`. It deliberately ignores
 * abort, so a loader that relies on `sleep` rejecting to stop is caught.
 */
function manualSleep() {
  const delays: number[] = [];
  const signals: AbortSignal[] = [];
  const pending: Array<() => void> = [];
  return {
    delays,
    signals,
    sleep: (ms: number, signal: AbortSignal) => {
      delays.push(ms);
      signals.push(signal);
      return new Promise<void>((resolve) => pending.push(resolve));
    },
    async release() {
      pending.shift()?.();
      await flush();
    },
  };
}

/** A fetcher that fails `failures` times, then resolves `value`. */
function flakyFetcher<T>(failures: number, value: T) {
  const signals: AbortSignal[] = [];
  let calls = 0;
  const fetcher = vi.fn(async (signal: AbortSignal) => {
    signals.push(signal);
    calls++;
    if (calls <= failures) throw new Error(`down ${calls}`);
    return value;
  });
  return { fetcher, signals };
}

describe("createRetryLoader", () => {
  it("retries a failing fetcher with doubling delays: pending, pending, ready", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0.5); // no jitter
    const s = manualSleep();
    const { fetcher } = flakyFetcher(2, "metadata");
    const loader = createRetryLoader(fetcher, { sleep: s.sleep });

    const statuses = [];
    await flush();
    statuses.push(loader.status());
    expect(loader.current()).toBeUndefined();
    await s.release();
    statuses.push(loader.status());
    await s.release();
    statuses.push(loader.status());

    expect(statuses).toEqual(["pending", "pending", "ready"]);
    expect(s.delays).toEqual([1000, 2000]);
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(loader.current()).toBe("metadata");
    loader.dispose();
  });

  it("jitters each delay by at most ±20%", async () => {
    for (const [random, expected] of [
      [0, [800, 1600]],
      [0.9999999, [1200, 2400]],
    ] as const) {
      vi.spyOn(Math, "random").mockReturnValue(random);
      const s = manualSleep();
      const loader = createRetryLoader(flakyFetcher(2, 1).fetcher, { sleep: s.sleep });
      await flush();
      await s.release();
      await s.release();
      expect(s.delays[0]).toBeCloseTo(expected[0], 0);
      expect(s.delays[1]).toBeCloseTo(expected[1], 0);
      loader.dispose();
      vi.mocked(Math.random).mockRestore();
    }

    // Unmocked: every delay stays inside its ±20% band.
    const s = manualSleep();
    const loader = createRetryLoader(flakyFetcher(2, 1).fetcher, { sleep: s.sleep });
    await flush();
    await s.release();
    await s.release();
    expect(s.delays[0]).toBeGreaterThanOrEqual(800);
    expect(s.delays[0]).toBeLessThanOrEqual(1200);
    expect(s.delays[1]).toBeGreaterThanOrEqual(1600);
    expect(s.delays[1]).toBeLessThanOrEqual(2400);
    expect(loader.status()).toBe("ready");
    loader.dispose();
  });

  it("caps the doubling at maxDelayMs, and honours initialDelayMs and jitter", async () => {
    const s = manualSleep();
    const loader = createRetryLoader(flakyFetcher(5, 1).fetcher, {
      sleep: s.sleep,
      initialDelayMs: 500,
      maxDelayMs: 3000,
      jitter: 0,
    });
    await flush();
    for (let i = 0; i < 5; i++) await s.release();
    expect(s.delays).toEqual([500, 1000, 2000, 3000, 3000]);
    expect(loader.status()).toBe("ready");
    loader.dispose();
  });

  it("dispose() aborts an in-flight fetch, ignores its late result, and never retries", async () => {
    const s = manualSleep();
    let seen: AbortSignal | undefined;
    let finish: (v: string) => void = () => {};
    const fetcher = vi.fn(
      (signal: AbortSignal) =>
        new Promise<string>((resolve) => {
          seen = signal;
          finish = resolve;
        }),
    );
    const loader = createRetryLoader(fetcher, { sleep: s.sleep });
    await flush();
    expect(seen?.aborted).toBe(false);

    loader.dispose();
    expect(seen?.aborted).toBe(true);

    finish("too late");
    await flush();
    expect(loader.current()).toBeUndefined();
    expect(loader.status()).toBe("pending");
    expect(s.delays).toEqual([]);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("dispose() during a retry delay aborts the sleep and stops the schedule", async () => {
    const s = manualSleep();
    const { fetcher } = flakyFetcher(1, "metadata");
    const loader = createRetryLoader(fetcher, { sleep: s.sleep });
    await flush();
    expect(s.signals).toHaveLength(1);
    expect(s.signals[0].aborted).toBe(false);

    loader.dispose();
    expect(s.signals[0].aborted).toBe(true);
    // The fake sleep ignores abort and resolves anyway: the loader must
    // still not fetch again.
    await s.release();
    await s.release();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(loader.current()).toBeUndefined();
  });

  it("dispose() after a rejection that lands post-dispose schedules nothing", async () => {
    const s = manualSleep();
    let fail: (e: Error) => void = () => {};
    const fetcher = vi.fn(() => new Promise<string>((_resolve, reject) => (fail = reject)));
    const loader = createRetryLoader(fetcher, { sleep: s.sleep });
    await flush();
    loader.dispose();
    fail(new Error("aborted"));
    await flush();
    expect(s.delays).toEqual([]);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
  });

  it("treats a synchronous throw as a retryable failure", async () => {
    const s = manualSleep();
    let calls = 0;
    const loader = createRetryLoader(
      () => {
        if (++calls === 1) throw new Error("sync");
        return Promise.resolve("ok");
      },
      { sleep: s.sleep, jitter: 0 },
    );
    await flush();
    expect(s.delays).toEqual([1000]);
    await s.release();
    expect(loader.current()).toBe("ok");
    loader.dispose();
  });

  it("uses a real timer by default, and dispose() cancels it", async () => {
    vi.useFakeTimers();
    const ok = flakyFetcher(1, "metadata");
    const loader = createRetryLoader(ok.fetcher, { jitter: 0 });
    await vi.advanceTimersByTimeAsync(999);
    expect(ok.fetcher).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(ok.fetcher).toHaveBeenCalledTimes(2);
    expect(loader.status()).toBe("ready");
    loader.dispose();

    const stuck = flakyFetcher(10, "never");
    const stopped = createRetryLoader(stuck.fetcher, { jitter: 0 });
    await vi.advanceTimersByTimeAsync(0);
    stopped.dispose();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(60000);
    expect(stuck.fetcher).toHaveBeenCalledTimes(1);
  });

  it("logs each failure at warn with the attempt and delay, and success at info", async () => {
    const s = manualSleep();
    const loader = createRetryLoader(flakyFetcher(1, 1).fetcher, { sleep: s.sleep, jitter: 0, name: "Google discovery" });
    await flush();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith("Google discovery failed (attempt 1); retrying in 1000ms", "down 1");
    await s.release();
    expect(info).toHaveBeenCalledWith("Google discovery succeeded after 2 attempts");
    loader.dispose();
  });

  it("bounds the logged failure message", async () => {
    const s = manualSleep();
    const loader = createRetryLoader(
      async () => {
        throw new Error(`a\nforged line ${"x".repeat(1000)}`);
      },
      { sleep: s.sleep },
    );
    await flush();
    const logged = String(warn.mock.calls[0][1]);
    expect(logged).not.toContain("\n");
    expect(logged.length).toBeLessThan(300);
    loader.dispose();
  });
});

describe("parseDegradedConfig", () => {
  it("defaults to false", () => {
    expect(parseDegradedConfig({})).toEqual({ allowDegradedStart: false });
    expect(parseDegradedConfig({ STEAMPIPE_MCP_ALLOW_DEGRADED_START: "" })).toEqual({ allowDegradedStart: false });
  });

  it("accepts true and false, case-insensitively", () => {
    expect(parseDegradedConfig({ STEAMPIPE_MCP_ALLOW_DEGRADED_START: "TRUE" })).toEqual({ allowDegradedStart: true });
    expect(parseDegradedConfig({ STEAMPIPE_MCP_ALLOW_DEGRADED_START: " false " })).toEqual({ allowDegradedStart: false });
  });

  it("rejects anything else, naming the variable without echoing the value", () => {
    let thrown: unknown;
    try {
      parseDegradedConfig({ STEAMPIPE_MCP_ALLOW_DEGRADED_START: "yes-secret-ish" });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(ConfigError);
    expect((thrown as Error).message).toContain("STEAMPIPE_MCP_ALLOW_DEGRADED_START");
    expect((thrown as Error).message).not.toContain("yes-secret-ish");
  });

  it("is wired into loadConfig as auth.allowDegradedStart in http mode only", () => {
    expect(googleConfig().auth.allowDegradedStart).toBe(false);
    expect(googleConfig(DEGRADED).auth.allowDegradedStart).toBe(true);
    expect(() => googleConfig({ STEAMPIPE_MCP_ALLOW_DEGRADED_START: "maybe" })).toThrow(ConfigError);
    // stdio never serves auth, so a stray value must not block it.
    expect(() => loadConfig({ STEAMPIPE_MCP_ALLOW_DEGRADED_START: "maybe" }, ["node", "index.js"])).not.toThrow();
  });
});

// --- HTTP: google mode with the flag on ------------------------------------

function newDb(): DatabaseService {
  return new DatabaseService({
    connectionString: testDbUrl() || "postgresql://steampipe@localhost:9193/steampipe",
    maxRows: 10000,
    statementTimeoutMs: 120000,
    poolMax: 1,
    exposeConnectionDetails: false,
  });
}

/** Fake tokeninfo: `good` is a valid token for CLIENT from corp.com. */
async function fakeTokeninfo(): Promise<string> {
  const server = createNodeServer((req: IncomingMessage, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const good = new URLSearchParams(body).get("access_token") === "good";
      res.writeHead(good ? 200 : 400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify(
          good
            ? {
                aud: CLIENT,
                azp: CLIENT,
                sub: "1234",
                email: "a@corp.com",
                email_verified: "true",
                scope: "openid https://www.googleapis.com/auth/userinfo.email",
                exp: String(Math.floor(Date.now() / 1000) + 3600),
              }
            : { error: "invalid_token" },
        ),
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/tokeninfo`;
}

interface Response {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function send(port: number, opts: { method: string; path: string; headers?: Record<string, string>; body?: string }) {
  return new Promise<Response>((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: opts.method, path: opts.path, headers: opts.headers, agent: false },
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

function toolsList(port: number, token: string): Promise<Response> {
  return send(port, {
    method: "POST",
    path: "/mcp",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });
}

/** Wire the app exactly as `startHttp` does, with an uncached readiness. */
async function startApp(auth: AuthMiddleware, cfg: ServerConfig): Promise<number> {
  const db = newDb();
  vi.spyOn(db, "ping").mockResolvedValue(undefined);
  const readiness = buildReadiness(db, auth.readiness, { cacheMs: 0 });
  const app = buildHttpApp(cfg, db, auth.mcpMiddleware, auth.rootRouters, readiness);
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

async function build(cfg: ServerConfig, metadataFetcher: (signal?: AbortSignal) => Promise<OAuthMetadata>, sleep?: ReturnType<typeof manualSleep>) {
  const auth = await authMiddleware(cfg, {
    metadataFetcher,
    tokeninfoUrl: await fakeTokeninfo(),
    discoveryRetry: sleep && { sleep: sleep.sleep },
  });
  auths.push(auth);
  return auth;
}

describe("authMiddleware: google with STEAMPIPE_MCP_ALLOW_DEGRADED_START=true", () => {
  it("builds while discovery fails, serves bearer traffic, and recovers PRM and /readyz", async () => {
    const s = manualSleep();
    let down = true;
    const fetcher = vi.fn(async () => {
      if (down) throw new Error("Google discovery document request failed with HTTP 503");
      return FAKE_GOOGLE_METADATA;
    });
    const cfg = googleConfig(DEGRADED);
    const auth = await build(cfg, fetcher, s);
    const port = await startApp(auth, cfg);
    await flush();

    const prm = await send(port, { method: "GET", path: PRM });
    expect(prm.status).toBe(503);
    expect(prm.headers["retry-after"]).toBe("5");

    // tokeninfo needs no discovery, so the bearer path keeps working.
    expect((await toolsList(port, "good")).status).toBe(200);
    expect((await toolsList(port, "bad")).status).toBe(401);

    const notReady = await send(port, { method: "GET", path: "/readyz" });
    expect(notReady.status).toBe(503);
    expect(JSON.parse(notReady.body)).toEqual({ status: "not_ready", checks: { db: "ready", auth: "pending" } });

    down = false;
    await s.release();

    const recovered = await send(port, { method: "GET", path: PRM });
    expect(recovered.status).toBe(200);
    expect(JSON.parse(recovered.body).authorization_servers).toEqual(["https://accounts.google.com"]);
    const ready = await send(port, { method: "GET", path: "/readyz" });
    expect(ready.status).toBe(200);
    expect(JSON.parse(ready.body)).toEqual({ status: "ready", checks: { db: "ready", auth: "ready" } });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("Google discovery failed (attempt 1)"), expect.any(String));
  });

  it("passes the loader's signal to the fetcher, and dispose() aborts it and stops retrying", async () => {
    const s = manualSleep();
    const signals: (AbortSignal | undefined)[] = [];
    const fetcher = vi.fn((signal?: AbortSignal) => {
      signals.push(signal);
      return new Promise<OAuthMetadata>(() => {});
    });
    const auth = await build(googleConfig(DEGRADED), fetcher, s);
    expect(signals[0]).toBeInstanceOf(AbortSignal);
    expect(signals[0]?.aborted).toBe(false);
    auth.dispose();
    expect(signals[0]?.aborted).toBe(true);
    expect(await auth.readiness[0].check(new AbortController().signal)).toBe("pending");
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("exposes one `auth` readiness check that reports the loader status", async () => {
    const s = manualSleep();
    let down = true;
    const auth = await build(
      googleConfig(DEGRADED),
      async () => {
        if (down) throw new Error("down");
        return FAKE_GOOGLE_METADATA;
      },
      s,
    );
    await flush();
    expect(auth.readiness.map((c) => c.name)).toEqual(["auth"]);
    expect(await auth.readiness[0].check(new AbortController().signal)).toBe("pending");
    down = false;
    await s.release();
    expect(await auth.readiness[0].check(new AbortController().signal)).toBe("ready");
  });

  it("is ignored outside google mode", async () => {
    const cfg = loadConfig(
      {
        STEAMPIPE_MCP_TRANSPORT: "http",
        STEAMPIPE_MCP_AUTH_MODE: "token",
        STEAMPIPE_MCP_AUTH_TOKEN: "s".repeat(40),
        ...DEGRADED,
      },
      ["node", "index.js"],
    );
    const auth = await authMiddleware(cfg);
    expect(auth.readiness).toEqual([]);
    expect(() => auth.dispose()).not.toThrow();
  });
});

describe("authMiddleware: google with the flag off (default)", () => {
  it("rejects when the discovery fetcher rejects, and never retries", async () => {
    const s = manualSleep();
    const fetcher = vi.fn(async () => {
      throw new Error("network down");
    });
    await expect(
      authMiddleware(googleConfig(), { metadataFetcher: fetcher, discoveryRetry: { sleep: s.sleep } }),
    ).rejects.toThrow("network down");
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(s.delays).toEqual([]);
  });

  it("reports the auth check as always ready, and serves the PRM at once", async () => {
    const cfg = googleConfig();
    const auth = await build(cfg, async () => FAKE_GOOGLE_METADATA);
    expect(auth.readiness.map((c) => c.name)).toEqual(["auth"]);
    expect(await auth.readiness[0].check(new AbortController().signal)).toBe("ready");
    const port = await startApp(auth, cfg);
    expect((await send(port, { method: "GET", path: PRM })).status).toBe(200);
    expect(() => auth.dispose()).not.toThrow();
  });

  it("adds no readiness check in none and token mode", async () => {
    const none = await authMiddleware(loadConfig({ STEAMPIPE_MCP_TRANSPORT: "http" }, ["node", "index.js"]));
    expect(none.readiness).toEqual([]);
    expect(() => none.dispose()).not.toThrow();
  });
});

describe("fetchGoogleMetadata: logging", () => {
  it("does not log a guard refusal itself; the cause (scheme and host only) is in the thrown error", async () => {
    let thrown: unknown;
    try {
      await fetchGoogleMetadata("https://evil.example/discovery?secret=1");
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VerifyError);
    expect((thrown as Error).message).toBe(
      "Google discovery document unavailable (policy: https host evil.example is not in the allowed identity-provider hosts)",
    );
    expect(error).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("fetchGoogleMetadata: caller abort", () => {
  it("passes the signal to the guarded fetch and does not log an aborted request as a failure", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      });
    });
    const controller = new AbortController();
    const pending = fetchGoogleMetadata(undefined, controller.signal);
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(VerifyError);
    expect(error).not.toHaveBeenCalled();
  });
});

describe("gracefulShutdown", () => {
  function deps(overrides: { disposeThrows?: boolean; closeRejects?: boolean } = {}) {
    const order: string[] = [];
    return {
      order,
      deps: {
        httpServer: {
          close(cb: (err?: Error) => void) {
            order.push("http");
            cb();
          },
          closeAllConnections() {},
        },
        auth: {
          dispose() {
            order.push("dispose");
            if (overrides.disposeThrows) throw new Error("boom");
          },
        },
        db: {
          async close() {
            order.push("db");
            if (overrides.closeRejects) throw new Error("pool");
          },
        },
      },
    };
  }

  it("disposes auth before closing the database, and exits 0", async () => {
    const { order, deps: d } = deps();
    expect(await gracefulShutdown(d)).toBe(0);
    expect(order).toEqual(["dispose", "http", "db"]);
  });

  it("still closes the HTTP server and database when dispose throws, then exits 1", async () => {
    const { order, deps: d } = deps({ disposeThrows: true });
    expect(await gracefulShutdown(d)).toBe(1);
    expect(order).toEqual(["dispose", "http", "db"]);
  });

  it("exits 1 when the database close fails", async () => {
    const { deps: d } = deps({ closeRejects: true });
    expect(await gracefulShutdown(d)).toBe(1);
  });

  it("works without an HTTP server or auth (stdio)", async () => {
    const { order, deps: d } = deps();
    expect(await gracefulShutdown({ db: d.db })).toBe(0);
    expect(order).toEqual(["db"]);
  });
});

// --- Production composition: what startHttp actually runs ------------------

class FakeProcess extends EventEmitter {
  exit = vi.fn();
}

const REFUSED = () => fetchGoogleMetadata("https://evil.example/discovery");

async function serve(
  cfg: ServerConfig,
  opts: { metadataFetcher: (signal?: AbortSignal) => Promise<OAuthMetadata>; sleep?: ReturnType<typeof manualSleep> },
) {
  const db = newDb();
  vi.spyOn(db, "ping").mockResolvedValue(undefined);
  const close = vi.spyOn(db, "close").mockResolvedValue(undefined);
  const proc = new FakeProcess();
  const served = await serveHttp({ ...cfg, http: { ...cfg.http, port: 0 } }, db, {
    metadataFetcher: opts.metadataFetcher,
    tokeninfoUrl: await fakeTokeninfo(),
    discoveryRetry: opts.sleep && { sleep: opts.sleep.sleep },
    readiness: { cacheMs: 0 },
    proc,
  });
  servers.push(served.server);
  auths.push(served.auth);
  return { ...served, db, close, proc, port: (served.server.address() as AddressInfo).port };
}

describe("serveHttp (the composition startHttp uses)", () => {
  it("registers auth's readiness check: degraded google with a refusing fetcher gives /readyz 503 auth=pending", async () => {
    const s = manualSleep();
    const { port } = await serve(googleConfig(DEGRADED), { metadataFetcher: REFUSED, sleep: s });
    await flush();
    const res = await send(port, { method: "GET", path: "/readyz" });
    expect(res.status).toBe(503);
    expect(JSON.parse(res.body)).toEqual({ status: "not_ready", checks: { db: "ready", auth: "pending" } });
    expect((await send(port, { method: "GET", path: PRM })).status).toBe(503);
    expect((await toolsList(port, "good")).status).toBe(200);
  });

  it("logs each degraded retry once, as a warning from the loader, and never as an error", async () => {
    const s = manualSleep();
    await serve(googleConfig(DEGRADED), { metadataFetcher: REFUSED, sleep: s });
    await flush();
    await s.release();
    expect(warn.mock.calls).toEqual([
      [
        expect.stringMatching(/^Google discovery failed \(attempt 1\); retrying in \d+ms$/),
        "Google discovery document unavailable (policy: https host evil.example is not in the allowed identity-provider hosts)",
      ],
      [expect.stringMatching(/^Google discovery failed \(attempt 2\); retrying in \d+ms$/), expect.any(String)],
    ]);
    expect(error).not.toHaveBeenCalled();
  });

  it("fails fast with the flag off: one clear error, nothing served, no signal handlers", async () => {
    const proc = new FakeProcess();
    const db = newDb();
    await expect(serveHttp(googleConfig(), db, { metadataFetcher: REFUSED, proc })).rejects.toThrow(
      "Google discovery document unavailable",
    );
    expect(error.mock.calls).toEqual([
      [
        "Failed to initialise STEAMPIPE_MCP_AUTH_MODE=google:",
        "Google discovery document unavailable (policy: https host evil.example is not in the allowed identity-provider hosts)",
      ],
    ]);
    expect(warn).not.toHaveBeenCalled();
    expect(proc.listenerCount("SIGTERM")).toBe(0);
  });

  it("on SIGTERM disposes auth before closing the database, then exits 0", async () => {
    const s = manualSleep();
    const served = await serve(googleConfig(DEGRADED), { metadataFetcher: REFUSED, sleep: s });
    const dispose = vi.spyOn(served.auth, "dispose");
    expect(served.proc.listenerCount("SIGINT")).toBe(1);
    served.proc.emit("SIGTERM");
    await vi.waitFor(() => expect(served.proc.exit).toHaveBeenCalled());
    expect(served.proc.exit).toHaveBeenCalledWith(0);
    expect(dispose).toHaveBeenCalledTimes(1);
    expect(served.close).toHaveBeenCalledTimes(1);
    expect(dispose.mock.invocationCallOrder[0]).toBeLessThan(served.close.mock.invocationCallOrder[0]);
    expect(served.server.listening).toBe(false);
  });
});
