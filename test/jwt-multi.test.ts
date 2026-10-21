import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { authMiddleware } from "../src/auth/index.js";
import type { RejectEvent } from "../src/auth/bearer.js";
import type { Reason } from "../src/auth/errors.js";
import { peekIssuer } from "../src/auth/issuer-peek.js";
import { FetchRefused } from "../src/auth/fetch-guard.js";
import { ConfigError, loadConfig, type ServerConfig } from "../src/config.js";
import type { DatabaseService } from "../src/services/database.js";
import { buildHttpApp } from "../src/http/app.js";
import { logger, LogLevel } from "../src/services/logger.js";
import { startTestIssuer, type TestIssuer, type TestIssuerOptions } from "./helpers/issuer.js";

// Two (or more) in-test issuers on 127.0.0.1 behind one Authorization
// header, configured with STEAMPIPE_MCP_JWT_ISSUERS. Token time is the
// verifier's injected `now`.

const NOW_S = 1_800_000_000;
const NOW_MS = NOW_S * 1000;
const PUBLIC_URL = "http://127.0.0.1/mcp";
const AUD = new URL(PUBLIC_URL).href;
const PRM_PATH = "/.well-known/oauth-protected-resource/mcp";

function fakeDb(): DatabaseService {
  return { executeUserQuery: async () => ({ rows: [], truncated: false }) } as unknown as DatabaseService;
}

let servers: HttpServer[] = [];
let issuers: TestIssuer[] = [];

beforeEach(() => {
  logger.configure({ isTestEnvironment: true, level: LogLevel.INFO });
  logger.clearLogs();
});

afterEach(async () => {
  for (const s of servers) s.closeAllConnections();
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  await Promise.all(issuers.map((i) => i.close()));
  servers = [];
  issuers = [];
});

async function issuerFor(opts?: TestIssuerOptions): Promise<TestIssuer> {
  const iss = await startTestIssuer(opts);
  issuers.push(iss);
  return iss;
}

function multiEnv(entries: unknown[], env: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    STEAMPIPE_MCP_TRANSPORT: "http",
    STEAMPIPE_MCP_AUTH_MODE: "jwt",
    STEAMPIPE_MCP_PUBLIC_URL: PUBLIC_URL,
    STEAMPIPE_MCP_JWT_ISSUERS: JSON.stringify(entries),
    STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1000",
    ...env,
  };
}

interface App {
  port: number;
  rejects: RejectEvent[];
}

/** `audit: true` keeps the default onReject (auditAuthReject) so reject lines reach the log. */
async function startMulti(
  entries: unknown[],
  env: Record<string, string> = {},
  o: { audit?: boolean; now?: () => number } = {},
): Promise<App> {
  const rejects: RejectEvent[] = [];
  const cfg = loadConfig(multiEnv(entries, env), ["node", "index.js"]);
  const { rootRouters, mcpMiddleware } = await authMiddleware(cfg, {
    now: o.now ?? (() => NOW_MS),
    ...(o.audit ? {} : { onReject: (e: RejectEvent) => rejects.push(e) }),
  });
  const app = buildHttpApp(cfg, fakeDb(), mcpMiddleware, rootRouters);
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return { port: (server.address() as AddressInfo).port, rejects };
}

interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function send(
  port: number,
  opts: { method?: string; path?: string; headers?: Record<string, string>; body?: string },
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: opts.method ?? "POST", path: opts.path ?? "/mcp", headers: opts.headers },
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

const TOOLS_LIST = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });

function toolsList(port: number, token: string): Promise<Reply> {
  return send(port, {
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${token}`,
    },
    body: TOOLS_LIST,
  });
}

function claims(iss: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss, aud: AUD, sub: "svc-1", exp: NOW_S + 300, iat: NOW_S, ...overrides };
}

async function expectRejected(app: App, token: string, reason: Reason, status = 401): Promise<void> {
  const before = app.rejects.length;
  const res = await toolsList(app.port, token);
  expect(res.status).toBe(status);
  expect(app.rejects.slice(before).map((e) => e.reason)).toEqual([reason]);
}

async function expectAccepted(app: App, token: string): Promise<void> {
  const before = app.rejects.length;
  const res = await toolsList(app.port, token);
  expect(app.rejects.slice(before).map((e) => e.reason)).toEqual([]);
  expect(res.status).toBe(200);
}

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/** An unsigned compact token with the given payload (the peek never looks at the rest). */
function unsigned(payload: unknown): string {
  return `${b64url({ alg: "RS256", typ: "at+jwt" })}.${b64url(payload)}.c2ln`;
}

/** Network activity seen by an issuer: every request path plus JWKS hits. */
function traffic(iss: TestIssuer): { paths: number; jwks: number } {
  return { paths: iss.requests().length, jwks: iss.jwksRequests() };
}

async function prmServers(app: App): Promise<string[]> {
  const res = await send(app.port, { method: "GET", path: PRM_PATH });
  expect(res.status).toBe(200);
  return JSON.parse(res.body).authorization_servers;
}

describe("peekIssuer", () => {
  it("returns the unverified iss of a compact JWS", () => {
    expect(peekIssuer(unsigned({ iss: "https://a.example", sub: "x" }))).toBe("https://a.example");
  });

  it("returns an iss of exactly 2048 characters and refuses 2049", () => {
    const at = `https://a.example/${"x".repeat(2048 - "https://a.example/".length)}`;
    expect(at.length).toBe(2048);
    expect(peekIssuer(unsigned({ iss: at }))).toBe(at);
    expect(peekIssuer(unsigned({ iss: `${at}y` }))).toBeUndefined();
  });

  it("returns undefined for a missing, empty or non-string iss", () => {
    for (const payload of [{}, { iss: "" }, { iss: 1 }, { iss: null }, { iss: ["https://a.example"] }, { iss: { a: 1 } }, { iss: true }]) {
      expect(peekIssuer(unsigned(payload))).toBeUndefined();
    }
  });

  it("returns undefined when the payload is not a JSON object", () => {
    for (const payload of [null, ["https://a.example"], "https://a.example", 42]) {
      expect(peekIssuer(unsigned(payload))).toBeUndefined();
    }
  });

  it("returns undefined, never throwing, for anything that is not a three-segment compact JWS", () => {
    const good = unsigned({ iss: "https://a.example" });
    const [h, p, s] = good.split(".");
    for (const token of [
      "",
      "opaque-token",
      "a.b",
      `${h}.${p}`,
      `${h}.${p}.${s}.x`,
      `${h}..${s}`,
      `${h}.!!!.${s}`,
      `${h}.${b64url({ iss: "https://a.example" }).slice(0, -3)}.${s}`,
      `{"payload":"${p}","x":"a.b"}`,
      `{.${p}.${s}`,
      `${h}.${Buffer.from("not json").toString("base64url")}.${s}`,
    ]) {
      expect(() => peekIssuer(token)).not.toThrow();
      expect(peekIssuer(token)).toBeUndefined();
    }
  });
});

describe("jwt multi-issuer: routing by iss", () => {
  it("accepts tokens from both configured issuers", async () => {
    const a = await issuerFor();
    const b = await issuerFor({ alg: "ES256" });
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }]);
    await expectAccepted(app, await a.sign(claims(a.issuer)));
    await expectAccepted(app, await b.sign(claims(b.issuer)));
    // Each issuer's keys were fetched from that issuer only.
    expect(a.jwksRequests()).toBe(1);
    expect(b.jwksRequests()).toBe(1);
  });

  it("rejects iss=B signed with A's key as signature, never consulting A's keys", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }]);
    // A's kid: B's key set has no such key.
    await expectRejected(app, await a.sign(claims(b.issuer)), "signature");
    // B's kid with A's private key: the key is found, the signature fails.
    await expectRejected(app, await a.sign(claims(b.issuer), { kid: b.kid() }), "signature");
    expect(a.jwksRequests()).toBe(0);
  });

  it("rejects an unknown iss as unknown_issuer with no network I/O to any issuer", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }]);
    const beforeA = traffic(a);
    const beforeB = traffic(b);
    // Signed by A with A's kid, on a cold cache: any fallback to a configured
    // issuer would fetch A's JWKS.
    await expectRejected(app, await a.sign(claims("https://unknown.example")), "unknown_issuer");
    await expectRejected(app, await a.sign(claims(`${a.issuer}/`)), "unknown_issuer");
    expect(traffic(a)).toEqual(beforeA);
    expect(traffic(b)).toEqual(beforeB);
    expect(a.jwksRequests()).toBe(0);
    expect(b.jwksRequests()).toBe(0);
  });

  it("routes an iss of 2048 characters (unknown_issuer) and refuses 2049 as malformed", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }]);
    const at = `https://a.example/${"x".repeat(2048 - "https://a.example/".length)}`;
    await expectRejected(app, await a.sign(claims(at)), "unknown_issuer");
    await expectRejected(app, await a.sign(claims(`${at}y`)), "malformed");
    expect(a.jwksRequests() + b.jwksRequests()).toBe(0);
  });

  it("rejects a non-JWT and a token without a string iss as malformed", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }]);
    await expectRejected(app, "not-a-jwt", "malformed");
    await expectRejected(app, await a.sign(claims(a.issuer, { iss: undefined })), "malformed");
    await expectRejected(app, await a.sign(claims(a.issuer, { iss: 7 })), "malformed");
    expect(a.jwksRequests() + b.jwksRequests()).toBe(0);
  });

  it("applies only the routed issuer's claims settings", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([
      { issuer: a.issuer },
      { issuer: b.issuer, audiences: ["api://b"], acceptedTyp: ["JWT"] },
    ]);
    await expectAccepted(app, await b.sign(claims(b.issuer, { aud: "api://b" }), { typ: "JWT" }));
    // B's audience and typ do not leak into A's settings, nor A's into B's.
    await expectRejected(app, await a.sign(claims(a.issuer, { aud: "api://b" })), "audience");
    await expectRejected(app, await a.sign(claims(a.issuer), { typ: "JWT" }), "malformed");
    await expectRejected(app, await b.sign(claims(b.issuer)), "malformed");
    await expectAccepted(app, await a.sign(claims(a.issuer)));
  });

  it("refuses startup when any issuer's discovery fails", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    b.setDiscoveryFailing(true);
    await expect(startMulti([{ issuer: a.issuer }, { issuer: b.issuer }])).rejects.toThrow(/discovery/);
  });
});

describe("jwt multi-issuer: per-issuer fetch policy", () => {
  // Two distinct https hosts. The fetch guard admits loopback http whatever
  // the allowlist, so the 127.0.0.1 test issuers cannot show this; here the
  // global fetch behind guardedFetch is stubbed, so the real per-issuer
  // policy is applied to https URLs with no TLS or DNS.
  const A = "https://a.example";
  const B = "https://b.example";
  let fetched: string[] = [];

  beforeEach(() => {
    fetched = [];
    vi.stubGlobal("fetch", async (input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : input);
      fetched.push(url.href);
      const issuer = url.origin;
      const json = (body: unknown) =>
        new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
      if (url.pathname === "/.well-known/openid-configuration") {
        // A's discovery points its keys at B's host; B's points at its own.
        return json({ issuer, jwks_uri: issuer === A ? `${B}/keys` : `${B}/keys-b` });
      }
      return json({ keys: [] });
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function start(env: Record<string, string> = {}): Promise<void> {
    const cfg = loadConfig(multiEnv([{ issuer: A }, { issuer: B }], env), ["node", "index.js"]);
    await authMiddleware(cfg, { now: () => NOW_MS, onReject: () => {} });
  }

  it("refuses an issuer's jwks_uri on another configured issuer's host, with zero requests to it", async () => {
    await expect(start()).rejects.toThrow(FetchRefused);
    await expect(start()).rejects.toThrow(/b\.example/);
    expect(fetched).toContain(`${A}/.well-known/openid-configuration`);
    expect(fetched.filter((u) => u.startsWith(`${B}/keys`))).toEqual([]);
  });

  it("allows it once JWT_ALLOWED_HOSTS lists that host", async () => {
    await expect(start({ STEAMPIPE_MCP_JWT_ALLOWED_HOSTS: "b.example" })).resolves.toBeUndefined();
    // Startup validates jwks_uri without fetching keys (they load on first use).
    expect(fetched.filter((u) => u.startsWith(`${B}/keys`))).toEqual([]);
  });
});

describe("jwt multi-issuer: per-issuer JWKS backoff (R16)", () => {
  it("backs off only the failing issuer: B is served and fetched inside A's window, A recovers on its own", async () => {
    let clock = NOW_MS;
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }], {}, { now: () => clock });
    a.setJwksFailing(true);

    // A's cold-cache fetch fails and opens A's 1 s window.
    await expectRejected(app, await a.sign(claims(a.issuer)), "issuer_unavailable", 503);
    expect([a.jwksRequests(), b.jwksRequests()]).toEqual([1, 0]);

    // Inside A's window: B's cold cache is fetched exactly once and B is served.
    clock += 500;
    await expectAccepted(app, await b.sign(claims(b.issuer)));
    expect([a.jwksRequests(), b.jwksRequests()]).toEqual([1, 1]);
    // A still fails fast, with no extra A fetch.
    await expectRejected(app, await a.sign(claims(a.issuer)), "issuer_unavailable", 503);
    expect([a.jwksRequests(), b.jwksRequests()]).toEqual([1, 1]);

    // A's window ends: A recovers with one fetch; B is untouched.
    a.setJwksFailing(false);
    clock += 500;
    await expectAccepted(app, await a.sign(claims(a.issuer)));
    await expectAccepted(app, await b.sign(claims(b.issuer)));
    expect([a.jwksRequests(), b.jwksRequests()]).toEqual([2, 1]);
  });

  it("keeps B's own window when A recovers", async () => {
    let clock = NOW_MS;
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }], {}, { now: () => clock });
    a.setJwksFailing(true);
    await expectRejected(app, await a.sign(claims(a.issuer)), "issuer_unavailable", 503);

    // B fails 500 ms later, so its window ends at +1500 ms, after A's.
    clock += 500;
    b.setJwksFailing(true);
    await expectRejected(app, await b.sign(claims(b.issuer)), "issuer_unavailable", 503);
    expect([a.jwksRequests(), b.jwksRequests()]).toEqual([1, 1]);

    // At +1000 ms A recovers; B, still inside its own window, is not fetched.
    a.setJwksFailing(false);
    b.setJwksFailing(false);
    clock += 500;
    await expectAccepted(app, await a.sign(claims(a.issuer)));
    await expectRejected(app, await b.sign(claims(b.issuer)), "issuer_unavailable", 503);
    expect([a.jwksRequests(), b.jwksRequests()]).toEqual([2, 1]);

    clock += 500;
    await expectAccepted(app, await b.sign(claims(b.issuer)));
    expect([a.jwksRequests(), b.jwksRequests()]).toEqual([2, 2]);
  });
});

describe("jwt multi-issuer: PRM advertise", () => {
  it("lists only advertised issuers, while a non-advertised issuer's tokens are still accepted", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer, advertise: false }]);
    expect(await prmServers(app)).toEqual([a.issuer]);
    await expectAccepted(app, await b.sign(claims(b.issuer)));
  });

  it("lists every advertised issuer in config order", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: b.issuer }, { issuer: a.issuer, advertise: true }]);
    expect(await prmServers(app)).toEqual([b.issuer, a.issuer]);
  });

  it("refuses a config where no issuer is advertised", () => {
    expect(() =>
      loadConfig(
        multiEnv([
          { issuer: "https://a.example", advertise: false },
          { issuer: "https://b.example", advertise: false },
        ]),
        ["node", "index.js"],
      ),
    ).toThrow(/STEAMPIPE_MCP_JWT_ISSUERS.*advertise/);
  });
});

describe("jwt multi-issuer: identity is iss|sub", () => {
  it("gives the same sub from two issuers separate rate-limit buckets", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }], {
      STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1",
    });
    expect((await toolsList(app.port, await a.sign(claims(a.issuer, { sub: "same" })))).status).toBe(200);
    expect((await toolsList(app.port, await b.sign(claims(b.issuer, { sub: "same" })))).status).toBe(200);
    // The limit is live: A's principal has used its one request.
    expect((await toolsList(app.port, await a.sign(claims(a.issuer, { sub: "same" })))).status).toBe(429);
  });

  it("writes each accepted request's iss into its audit line, and never a peeked iss", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }], {}, { audit: true });
    expect((await toolsList(app.port, await a.sign(claims(a.issuer, { sub: "same" })))).status).toBe(200);
    expect((await toolsList(app.port, await b.sign(claims(b.issuer, { sub: "same" })))).status).toBe(200);
    const marker = "https://marker-7f3a.example";
    expect((await toolsList(app.port, await a.sign(claims(marker)))).status).toBe(401);

    const logs = logger.getCollectedLogs();
    const audit = logs.filter((l) => l.includes('"method":"tools/list"'));
    expect(audit).toHaveLength(2);
    expect(audit[0]).toContain(`"iss":${JSON.stringify(a.issuer)}`);
    expect(audit[1]).toContain(`"iss":${JSON.stringify(b.issuer)}`);
    expect(audit.every((l) => l.includes('"sub":"same"'))).toBe(true);
    expect(logs.some((l) => l.includes('"event":"auth_reject"') && l.includes('"reason":"unknown_issuer"'))).toBe(true);
    expect(logs.join("\n")).not.toContain("marker-7f3a");
  });
});

describe("jwt multi-issuer config", () => {
  function load(env: Record<string, string>): ServerConfig {
    return loadConfig(
      { STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_AUTH_MODE: "jwt", STEAMPIPE_MCP_PUBLIC_URL: PUBLIC_URL, ...env },
      ["node", "index.js"],
    );
  }

  function issuersEnv(value: unknown): Record<string, string> {
    return { STEAMPIPE_MCP_JWT_ISSUERS: typeof value === "string" ? value : JSON.stringify(value) };
  }

  function expectConfigError(env: Record<string, string>, pattern: RegExp = /STEAMPIPE_MCP_JWT_ISSUERS/): ConfigError {
    let caught: unknown;
    try {
      load(env);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ConfigError);
    expect((caught as Error).message).toMatch(pattern);
    return caught as ConfigError;
  }

  it("parses per-issuer settings, defaulting missing fields to the single-issuer env values", () => {
    const cfg = load({
      ...issuersEnv([
        { issuer: "https://a.example" },
        {
          issuer: "https://b.example/tenant",
          audiences: ["api://b"],
          algorithms: ["PS256"],
          acceptedTyp: ["JWT"],
          clockSkewS: 5,
          maxTokenAgeS: 60,
          advertise: false,
        },
      ]),
      STEAMPIPE_MCP_JWT_AUDIENCES: "api://default",
      STEAMPIPE_MCP_JWT_ALGORITHMS: "ES256",
      STEAMPIPE_MCP_JWT_ACCEPTED_TYP: "at+jwt",
      STEAMPIPE_MCP_JWT_CLOCK_SKEW_S: "10",
      STEAMPIPE_MCP_JWT_MAX_TOKEN_AGE_S: "3600",
    });
    expect(cfg.auth.jwt?.issuers).toEqual([
      {
        issuer: "https://a.example",
        audiences: ["api://default"],
        algorithms: ["ES256"],
        acceptedTyp: ["at+jwt"],
        clockSkewS: 10,
        maxTokenAgeS: 3600,
        advertise: true,
      },
      {
        issuer: "https://b.example/tenant",
        audiences: ["api://b"],
        algorithms: ["PS256"],
        acceptedTyp: ["jwt"],
        clockSkewS: 5,
        maxTokenAgeS: 60,
        advertise: false,
      },
    ]);
  });

  it("maps a single JWT_ISSUER to one advertised issuer", () => {
    const cfg = load({ STEAMPIPE_MCP_JWT_ISSUER: "https://a.example" });
    expect(cfg.auth.jwt?.issuers).toEqual([
      {
        issuer: "https://a.example",
        audiences: [AUD],
        algorithms: ["RS256", "ES256"],
        acceptedTyp: ["at+jwt", "application/at+jwt"],
        clockSkewS: 0,
        maxTokenAgeS: 0,
        advertise: true,
      },
    ]);
  });

  it("refuses JWT_ISSUER and JWT_ISSUERS together", () => {
    const err = expectConfigError({
      STEAMPIPE_MCP_JWT_ISSUER: "https://a.example",
      ...issuersEnv([{ issuer: "https://b.example" }]),
    });
    expect(err.message).toMatch(/STEAMPIPE_MCP_JWT_ISSUER\b(?!S)/);
  });

  it("requires JWT_ISSUER or JWT_ISSUERS", () => {
    expectConfigError({}, /STEAMPIPE_MCP_JWT_ISSUERS?\b/);
  });

  it("refuses a duplicate issuer without echoing it", () => {
    const err = expectConfigError(
      issuersEnv([{ issuer: "https://dup-1c9e.example" }, { issuer: "https://b.example" }, { issuer: "https://dup-1c9e.example" }]),
    );
    expect(err.message).not.toContain("dup-1c9e");
  });

  it("refuses a config where no issuer is advertised", () => {
    expectConfigError(issuersEnv([{ issuer: "https://a.example", advertise: false }]), /advertise/);
  });

  it("refuses invalid JSON without echoing it", () => {
    // Node's SyntaxError quotes the input around an unexpected token.
    for (const value of ['[{"issuer":"https://hunter2.example"', '[{"issuer": hunter2}]']) {
      const err = expectConfigError(issuersEnv(value));
      expect(err.message).not.toContain("hunter2");
    }
  });

  it("refuses anything but a non-empty array of objects", () => {
    for (const value of ["{}", "[]", '"https://a.example"', "null", '["https://a.example"]', "[null]", "[[]]"]) {
      expectConfigError(issuersEnv(value));
    }
  });

  it("refuses unknown fields, so a typo cannot silently fall back to a default", () => {
    expectConfigError(issuersEnv([{ issuer: "https://a.example", advertize: false }]), /advertize/);
    expectConfigError(issuersEnv([{ issuer: "https://a.example", audience: ["x"] }]), /audience/);
  });

  it("validates each entry's issuer like JWT_ISSUER, without echoing it", () => {
    for (const issuer of [undefined, 7, "", "http://idp.example.com", "not a url", "https://idp.example.com/t?x=1", "https://idp.example.com/t#f"]) {
      expectConfigError(issuersEnv([{ issuer: "https://a.example" }, { issuer }]), /STEAMPIPE_MCP_JWT_ISSUERS\[1\]\.issuer/);
    }
    const err = expectConfigError(issuersEnv([{ issuer: "https://user:hunter2@idp.example.com" }]));
    expect(err.message).not.toContain("hunter2");
  });

  it("caps each entry's clockSkewS at 300 seconds (M-6)", () => {
    const cfg = load(issuersEnv([{ issuer: "https://a.example", clockSkewS: 300 }]));
    expect(cfg.auth.jwt?.issuers[0].clockSkewS).toBe(300);
    expectConfigError(
      issuersEnv([{ issuer: "https://a.example" }, { issuer: "https://b.example", clockSkewS: 301 }]),
      /^STEAMPIPE_MCP_JWT_ISSUERS\[1\]\.clockSkewS must be an integer between 0 and 300$/,
    );
    // maxTokenAgeS is not capped.
    expect(load(issuersEnv([{ issuer: "https://a.example", maxTokenAgeS: 86400 }])).auth.jwt?.issuers[0].maxTokenAgeS).toBe(86400);
  });

  it("refuses an entry's issuer containing '|', without echoing it (M-3)", () => {
    const err = expectConfigError(
      issuersEnv([{ issuer: "https://a.example" }, { issuer: "https://b.example/t|x" }]),
      /^STEAMPIPE_MCP_JWT_ISSUERS\[1\]\.issuer must not contain "\|"$/,
    );
    expect(err.message).not.toContain("b.example");
  });

  it("validates each entry's settings", () => {
    const bad: Record<string, unknown>[] = [
      { audiences: [] },
      { audiences: "api://b" },
      { audiences: [""] },
      { audiences: [1] },
      { algorithms: ["HS256"] },
      { algorithms: ["none"] },
      { algorithms: [] },
      { acceptedTyp: [] },
      { acceptedTyp: [""] },
      { clockSkewS: -1 },
      { clockSkewS: 1.5 },
      { clockSkewS: "5" },
      { maxTokenAgeS: -1 },
      { maxTokenAgeS: null },
      { advertise: "false" },
      { advertise: 0 },
    ];
    for (const fields of bad) {
      const [field] = Object.keys(fields);
      expectConfigError(
        issuersEnv([{ issuer: "https://a.example", ...fields }]),
        new RegExp(`STEAMPIPE_MCP_JWT_ISSUERS\\[0\\]\\.${field}`),
      );
    }
  });
});

describe("jwt identity policy", () => {
  const GH_SUB = "repo:RafPe/steampipe-mcp:ref:refs/heads/main";

  async function expectDenied(app: App, token: string, secrets: string[] = []): Promise<void> {
    const before = app.rejects.length;
    const res = await toolsList(app.port, token);
    expect(app.rejects.slice(before).map((e) => e.reason)).toEqual(["not_allowed"]);
    expect(res.status).toBe(403);
    expect(JSON.parse(res.body).error).toBe("access_denied");
    // A policy denial is not a scope problem: no challenge to step up.
    expect(res.headers["www-authenticate"]).toBeUndefined();
    for (const secret of secrets) {
      expect(res.body).not.toContain(secret);
      expect(JSON.stringify(res.headers)).not.toContain(secret);
    }
  }

  it("applies the global REQUIRED_CLAIMS to every issuer", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }, { issuer: b.issuer }], {
      STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"groups":["platform"]}',
    });
    for (const iss of [a, b]) {
      await expectAccepted(app, await iss.sign(claims(iss.issuer, { groups: ["platform", "x"] })));
      await expectDenied(app, await iss.sign(claims(iss.issuer, { groups: ["x"] })));
      await expectDenied(app, await iss.sign(claims(iss.issuer)));
    }
  });

  it("applies the global subject rules to the verified sub", async () => {
    const a = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer }], { STEAMPIPE_MCP_ALLOWED_SUBJECTS: '["svc-1"]' });
    await expectAccepted(app, await a.sign(claims(a.issuer, { sub: "svc-1" })));
    await expectDenied(app, await a.sign(claims(a.issuer, { sub: "svc-2" })));
  });

  it("lets issuer B's override replace the global policy for B only", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti(
      [{ issuer: a.issuer }, { issuer: b.issuer, requiredClaims: { repository_owner: ["RafPe"] } }],
      { STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"groups":["platform"]}', STEAMPIPE_MCP_SUBJECT_PREFIXES: '["svc-"]' },
    );
    // B: the override alone decides. No groups claim and a sub outside the
    // global prefixes still pass, so nothing of the global policy is merged in.
    await expectAccepted(app, await b.sign(claims(b.issuer, { sub: GH_SUB, repository_owner: "RafPe" })));
    await expectDenied(app, await b.sign(claims(b.issuer, { sub: "svc-1", groups: ["platform"] })));
    await expectDenied(app, await b.sign(claims(b.issuer, { sub: GH_SUB, repository_owner: "Other" })));
    // A: still the global policy; B's override does not leak into it.
    await expectAccepted(app, await a.sign(claims(a.issuer, { sub: "svc-1", groups: ["platform"] })));
    await expectDenied(app, await a.sign(claims(a.issuer, { sub: "svc-1", repository_owner: "RafPe" })));
    await expectDenied(app, await a.sign(claims(a.issuer, { sub: GH_SUB, groups: ["platform"] })));
  });

  it("matches a subject prefix against a GitHub Actions sub", async () => {
    const a = await issuerFor();
    const gh = await issuerFor();
    const app = await startMulti([
      { issuer: a.issuer },
      { issuer: gh.issuer, requiredClaims: { repository_owner: ["RafPe"] }, subjectPrefixes: ["repo:RafPe/"] },
    ]);
    await expectAccepted(app, await gh.sign(claims(gh.issuer, { sub: GH_SUB, repository_owner: "RafPe" })));
    await expectAccepted(
      app,
      await gh.sign(claims(gh.issuer, { sub: "repo:RafPe/other:environment:prod", repository_owner: "RafPe" })),
    );
    // The trailing slash keeps a lookalike owner out.
    await expectDenied(app, await gh.sign(claims(gh.issuer, { sub: "repo:RafPeEvil/x:ref:refs/heads/main", repository_owner: "RafPe" })));
    await expectDenied(app, await gh.sign(claims(gh.issuer, { sub: "repo:Other/x:ref:refs/heads/main", repository_owner: "RafPe" })));
    // No global policy: A is unrestricted.
    await expectAccepted(app, await a.sign(claims(a.issuer, { sub: "anything" })));
  });

  it("never echoes a claim value in the denial or the logs", async () => {
    const a = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer, requiredClaims: { groups: ["platform"] } }], {}, { audit: true });
    const secret = "claim-secret-5d1e";
    const res = await toolsList(app.port, await a.sign(claims(a.issuer, { groups: [secret] })));
    expect(res.status).toBe(403);
    expect(res.body).not.toContain(secret);
    expect(JSON.stringify(res.headers)).not.toContain(secret);
    const logs = logger.getCollectedLogs();
    expect(logs.some((l) => l.includes('"event":"auth_reject"') && l.includes('"reason":"not_allowed"'))).toBe(true);
    expect(logs.join("\n")).not.toContain(secret);
  });

  it("checks the policy only after the token itself is valid", async () => {
    const a = await issuerFor();
    const app = await startMulti([{ issuer: a.issuer, requiredClaims: { groups: ["platform"] } }]);
    await expectRejected(app, await a.sign(claims(a.issuer, { exp: NOW_S - 10 })), "expired");
  });
});

describe("jwt identity policy config", () => {
  const SENTINEL = "sentinel-do-not-echo";

  function load(entry: Record<string, unknown>, env: Record<string, string> = {}): ServerConfig {
    return loadConfig(multiEnv([{ issuer: "https://a.example", ...entry }], env), ["node", "index.js"]);
  }

  function configError(entry: Record<string, unknown>): ConfigError {
    try {
      load(entry);
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      return error as ConfigError;
    }
    throw new Error("expected loadConfig to throw");
  }

  it("parses a per-issuer policy, leaving fields it does not set empty", () => {
    const cfg = load(
      { requiredClaims: { repository_owner: ["RafPe"] }, subjectPrefixes: ["repo:RafPe/"] },
      { STEAMPIPE_MCP_ALLOWED_SUBJECTS: '["alice"]' },
    );
    const policy = cfg.auth.jwt?.issuers[0].policy;
    expect(policy?.requiredClaims).toEqual({ repository_owner: ["RafPe"] });
    expect(policy?.subjectPrefixes).toEqual(["repo:RafPe/"]);
    // Not inherited from the global ALLOWED_SUBJECTS.
    expect(policy?.allowedSubjects).toEqual(new Set());
    expect(load({ allowedSubjects: ["bob"] }).auth.jwt?.issuers[0].policy?.allowedSubjects).toEqual(new Set(["bob"]));
  });

  it("leaves an issuer without policy fields on the global policy", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti(
      [{ issuer: a.issuer }, { issuer: b.issuer, requiredClaims: { repository_owner: ["RafPe"] } }],
      { STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"groups":["platform"]}' },
    );
    // A has no override, so the global policy decides for it, even though
    // another issuer carries its own.
    await expectAccepted(app, await a.sign(claims(a.issuer, { groups: ["platform"] })));
    const before = app.rejects.length;
    const res = await toolsList(app.port, await a.sign(claims(a.issuer, { groups: ["x"] })));
    expect(app.rejects.slice(before).map((e) => e.reason)).toEqual(["not_allowed"]);
    expect(res.status).toBe(403);
    expect(JSON.parse(res.body).error).toBe("access_denied");
    expect(load({}).auth.jwt?.issuers[0].policy).toBeUndefined();
  });

  it("loads a global policy in jwt mode", () => {
    const cfg = load({}, { STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"groups":["platform"]}' });
    expect(cfg.policy?.requiredClaims).toEqual({ groups: ["platform"] });
  });

  const long = `${SENTINEL}${"a".repeat(257 - SENTINEL.length)}`;
  const many = (n: number) => Array.from({ length: n }, (_, i) => `${SENTINEL}${i}`);

  it.each<[string, Record<string, unknown>]>([
    ["requiredClaims as an array", { requiredClaims: [SENTINEL] }],
    ["requiredClaims as null", { requiredClaims: null }],
    ["requiredClaims value not an array", { requiredClaims: { [SENTINEL]: "x" } }],
    ["requiredClaims value as an empty array", { requiredClaims: { [SENTINEL]: [] } }],
    ["requiredClaims value with an empty string", { requiredClaims: { [SENTINEL]: [""] } }],
    ["requiredClaims value with a non-string", { requiredClaims: { [SENTINEL]: ["a", 1] } }],
    ["requiredClaims empty key", { requiredClaims: { "": [SENTINEL] } }],
    ["requiredClaims 257-character value", { requiredClaims: { k: [long] } }],
    ["requiredClaims 257-character key", { requiredClaims: { [long]: ["x"] } }],
    ["allowedSubjects as a string", { allowedSubjects: SENTINEL }],
    ["allowedSubjects as null", { allowedSubjects: null }],
    ["allowedSubjects with an empty string", { allowedSubjects: [SENTINEL, ""] }],
    ["allowedSubjects 257-character entry", { allowedSubjects: [long] }],
    ["allowedSubjects with 1025 entries", { allowedSubjects: many(1025) }],
    ["subjectPrefixes as an object", { subjectPrefixes: { [SENTINEL]: 1 } }],
    ["subjectPrefixes with an empty string (would match every subject)", { subjectPrefixes: [SENTINEL, ""] }],
    ["subjectPrefixes 257-character entry", { subjectPrefixes: [long] }],
    ["subjectPrefixes with 65 entries", { subjectPrefixes: many(65) }],
  ])("refuses %s with the global parser's limits, naming the field without echoing it", (_name, entry) => {
    const [field] = Object.keys(entry);
    const err = configError(entry);
    expect(err.message).toMatch(new RegExp(`STEAMPIPE_MCP_JWT_ISSUERS\\[0\\]\\.${field}\\b`));
    expect(err.message).not.toContain(SENTINEL);
  });

  it("accepts entries at the global parser's limits", () => {
    const at = "a".repeat(256);
    const policy = load({
      requiredClaims: { [at]: [at] },
      allowedSubjects: Array.from({ length: 1024 }, (_, i) => `s${i}`),
      subjectPrefixes: Array.from({ length: 64 }, (_, i) => `p${i}`),
    }).auth.jwt?.issuers[0].policy;
    expect(policy?.allowedSubjects.size).toBe(1024);
    expect(policy?.subjectPrefixes).toHaveLength(64);
  });

  it("refuses an override with no rules, which would silently drop the global policy", () => {
    for (const entry of [{ requiredClaims: {} }, { allowedSubjects: [] }, { subjectPrefixes: [], allowedSubjects: [] }]) {
      expect(configError(entry).message).toMatch(/STEAMPIPE_MCP_JWT_ISSUERS\[0\]/);
    }
  });

  it("still refuses a misspelt policy field", () => {
    expect(configError({ subjectPrefix: ["repo:RafPe/"] }).message).toMatch(/subjectPrefix/);
  });
});

describe("jwt multi-issuer: lenient profile (R27)", () => {
  /** GitHub Actions / Entra v2 shaped: no client_id (and no jti for Entra). */
  function lenientShaped(iss: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return claims(iss, { sub: "repo:acme/app:ref:refs/heads/main", azp: "azp-1", uti: "u-1", client_id: undefined, jti: undefined, ...overrides });
  }

  it("applies the lenient profile to its own issuer only", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([
      // A's typ allowlist includes JWT, so only the claim set can refuse a B-shaped token.
      { issuer: a.issuer, acceptedTyp: ["at+jwt", "JWT"] },
      { issuer: b.issuer, profile: "lenient", subjectPrefixes: ["repo:acme/"] },
    ]);
    await expectAccepted(app, await b.sign(lenientShaped(b.issuer), { typ: "JWT" }));
    // The same shape signed by A for A: A stays rfc9068.
    await expectRejected(app, await a.sign(lenientShaped(a.issuer), { typ: "JWT" }), "malformed");
    await expectRejected(app, await a.sign(lenientShaped(a.issuer)), "malformed");
    // A still accepts its own RFC 9068 tokens.
    await expectAccepted(app, await a.sign(claims(a.issuer)));
  });

  it("does not let a lenient issuer's key sign for an rfc9068 issuer", async () => {
    const a = await issuerFor();
    const b = await issuerFor();
    const app = await startMulti([
      { issuer: a.issuer },
      { issuer: b.issuer, profile: "lenient", subjectPrefixes: ["repo:acme/"] },
    ]);
    await expectRejected(app, await b.sign(lenientShaped(a.issuer), { typ: "JWT" }), "malformed");
    await expectRejected(app, await b.sign(claims(a.issuer)), "signature");
  });

  it("answers 503 for a lenient issuer's unusable key material, backs off, and recovers after the window (Codex I-1)", async () => {
    let clock = NOW_MS;
    const b = await issuerFor();
    b.setJwksKeys([{ kty: "RSA", kid: b.kid(), alg: "RS256", use: "sig" }]);
    const app = await startMulti(
      [{ issuer: b.issuer, profile: "lenient", subjectPrefixes: ["repo:acme/"] }],
      {},
      { now: () => clock },
    );
    const token = await b.sign(lenientShaped(b.issuer), { typ: "JWT" });
    await expectRejected(app, token, "issuer_unavailable", 503);
    expect(b.jwksRequests()).toBe(1);

    b.setJwksKeys(undefined);
    clock += 999;
    await expectRejected(app, token, "issuer_unavailable", 503);
    expect(b.jwksRequests()).toBe(1);
    clock += 1;
    await expectAccepted(app, token);
    expect(b.jwksRequests()).toBe(2);
  });

  it("writes the azp fallback as clientId in the audit line", async () => {
    const b = await issuerFor();
    const app = await startMulti(
      [{ issuer: b.issuer, profile: "lenient", requiredClaims: { tid: ["tenant-1"] } }],
      {},
      { audit: true },
    );
    const token = await b.sign(lenientShaped(b.issuer, { azp: "azp-entra-7", tid: "tenant-1" }), { typ: "JWT" });
    expect((await toolsList(app.port, token)).status).toBe(200);
    const audit = logger.getCollectedLogs().filter((l) => l.includes('"method":"tools/list"'));
    expect(audit).toHaveLength(1);
    expect(audit[0]).toContain('"clientId":"azp-entra-7"');
  });
});

describe("jwt multi-issuer lenient profile config (R27)", () => {
  function load(entries: unknown[], env: Record<string, string> = {}): ServerConfig {
    return loadConfig(multiEnv(entries, env), ["node", "index.js"]);
  }

  function configError(entries: unknown[], env: Record<string, string> = {}): ConfigError {
    try {
      load(entries, env);
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      return error as ConfigError;
    }
    throw new Error("expected loadConfig to throw");
  }

  it("refuses a lenient entry with no override and an empty global policy", () => {
    const err = configError([{ issuer: "https://a.example" }, { issuer: "https://b.example", profile: "lenient" }]);
    expect(err.message).toMatch(/STEAMPIPE_MCP_JWT_ISSUERS\[1\]\.profile/);
    expect(err.message).toMatch(/identity policy/);
  });

  it("loads a lenient entry covered by the global policy only", () => {
    const cfg = load([{ issuer: "https://a.example", profile: "lenient" }], {
      STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"repository_owner":["acme"]}',
    });
    expect(cfg.auth.jwt?.issuers[0].profile).toBe("lenient");
    expect(cfg.auth.jwt?.issuers[0].policy).toBeUndefined();
  });

  it("loads a lenient entry with its own override only", () => {
    const cfg = load([{ issuer: "https://a.example", profile: "lenient", subjectPrefixes: ["repo:acme/"] }]);
    expect(cfg.auth.jwt?.issuers[0].profile).toBe("lenient");
    expect(cfg.auth.jwt?.issuers[0].acceptedTyp).toEqual(["at+jwt", "application/at+jwt", "jwt"]);
  });

  it("keeps an entry's explicit acceptedTyp, or an explicit JWT_ACCEPTED_TYP, under lenient", () => {
    const own = load([{ issuer: "https://a.example", profile: "lenient", acceptedTyp: ["at+jwt"], subjectPrefixes: ["x"] }]);
    expect(own.auth.jwt?.issuers[0].acceptedTyp).toEqual(["at+jwt"]);
    const env = load([{ issuer: "https://a.example", profile: "lenient", subjectPrefixes: ["x"] }], {
      STEAMPIPE_MCP_JWT_ACCEPTED_TYP: "at+jwt",
    });
    expect(env.auth.jwt?.issuers[0].acceptedTyp).toEqual(["at+jwt"]);
  });

  it("leaves rfc9068 entries (explicit or default) without a profile field", () => {
    const cfg = load([{ issuer: "https://a.example", profile: "rfc9068" }, { issuer: "https://b.example" }]);
    expect(cfg.auth.jwt?.issuers.map((i) => i.profile)).toEqual([undefined, undefined]);
    expect(cfg.auth.jwt?.issuers[0].acceptedTyp).toEqual(["at+jwt", "application/at+jwt"]);
  });

  it("refuses an unknown or non-string profile without echoing it", () => {
    for (const profile of ["loose", "LENIENT", 1, null, ["lenient"]]) {
      const err = configError([{ issuer: "https://a.example", profile, subjectPrefixes: ["x"] }]);
      expect(err.message).toMatch(/^STEAMPIPE_MCP_JWT_ISSUERS\[0\]\.profile must be/);
      expect(err.message).not.toContain("loose");
      expect(err.message).not.toContain("LENIENT");
    }
  });

  it("refuses JWT_PROFILE together with JWT_ISSUERS, so lenient is set per entry", () => {
    const err = configError([{ issuer: "https://a.example", subjectPrefixes: ["x"] }], {
      STEAMPIPE_MCP_JWT_PROFILE: "lenient",
    });
    expect(err.message).toMatch(/STEAMPIPE_MCP_JWT_PROFILE/);
    expect(err.message).toMatch(/profile/);
  });
});
