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
  o: { audit?: boolean } = {},
): Promise<App> {
  const rejects: RejectEvent[] = [];
  const cfg = loadConfig(multiEnv(entries, env), ["node", "index.js"]);
  const { rootRouters, mcpMiddleware } = await authMiddleware(cfg, {
    now: () => NOW_MS,
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
