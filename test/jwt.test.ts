import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import { createServer as createNetServer, type AddressInfo } from "node:net";
import { createLocalJWKSet, createRemoteJWKSet, errors, generateKeyPair, type JWTVerifyGetKey } from "jose";
import { authMiddleware } from "../src/auth/index.js";
import type { RejectEvent } from "../src/auth/bearer.js";
import { VerifyError, type Reason } from "../src/auth/errors.js";
import { createJwtVerifier, jwksBackoff, type IssuerConfig } from "../src/auth/jwt.js";
import { discoverJwks } from "../src/auth/discovery.js";
import { DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_MS, FetchRefused, type FetchPolicy } from "../src/auth/fetch-guard.js";
import { ConfigError, loadConfig, type ServerConfig } from "../src/config.js";
import type { DatabaseService } from "../src/services/database.js";
import { buildHttpApp } from "../src/http/app.js";
import { logger, LogLevel } from "../src/services/logger.js";
import { startTestIssuer, type TestIssuer, type TestIssuerOptions } from "./helpers/issuer.js";

// Every issuer here is an in-test HTTP server on 127.0.0.1 (test/helpers/
// issuer.ts). Token time is driven by the verifier's injected `now`; only
// the key-rotation tests also fake `Date`, because jose's JWKS cache and
// cooldown read the real `Date.now()`.

const NOW_S = 1_800_000_000;
const NOW_MS = NOW_S * 1000;
const PUBLIC_URL = "http://127.0.0.1/mcp";
// The default audience is PUBLIC_URL's canonical href (R12).
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
  vi.useRealTimers();
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

function jwtEnv(issuer: string, env: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    STEAMPIPE_MCP_TRANSPORT: "http",
    STEAMPIPE_MCP_AUTH_MODE: "jwt",
    STEAMPIPE_MCP_PUBLIC_URL: PUBLIC_URL,
    STEAMPIPE_MCP_JWT_ISSUER: issuer,
    STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1000",
    ...env,
  };
}

function jwtConfig(issuer: string, env: Record<string, string> = {}): ServerConfig {
  return loadConfig(jwtEnv(issuer, env), ["node", "index.js"]);
}

async function startJwt(
  iss: TestIssuer,
  env: Record<string, string> = {},
  now: () => number = () => NOW_MS,
): Promise<{ port: number; rejects: RejectEvent[] }> {
  const rejects: RejectEvent[] = [];
  const cfg = jwtConfig(iss.issuer, env);
  const { rootRouters, mcpMiddleware } = await authMiddleware(cfg, { now, onReject: (e) => rejects.push(e) });
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

/** RFC 9068 access-token claims valid at NOW_S, with overrides. */
function claims(iss: TestIssuer, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss: iss.issuer, aud: AUD, sub: "svc-1", exp: NOW_S + 300, iat: NOW_S, ...overrides };
}

/** Sends `token` and asserts the status and the single onReject reason. */
async function expectRejected(
  app: { port: number; rejects: RejectEvent[] },
  token: string,
  reason: Reason,
  status = 401,
): Promise<Reply> {
  const before = app.rejects.length;
  const res = await toolsList(app.port, token);
  expect(res.status).toBe(status);
  expect(app.rejects.slice(before).map((e) => e.reason)).toEqual([reason]);
  return res;
}

async function expectAccepted(app: { port: number; rejects: RejectEvent[] }, token: string): Promise<void> {
  const before = app.rejects.length;
  const res = await toolsList(app.port, token);
  expect(app.rejects.slice(before).map((e) => e.reason)).toEqual([]);
  expect(res.status).toBe(200);
  expect(JSON.parse(res.body).result.tools.length).toBeGreaterThan(0);
}

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

describe("jwt: acceptance and audience", () => {
  it("accepts a valid RFC 9068 access token on tools/list", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectAccepted(app, await iss.sign(claims(iss)));
  });

  it("accepts an ES256 issuer", async () => {
    const iss = await issuerFor({ alg: "ES256" });
    const app = await startJwt(iss);
    await expectAccepted(app, await iss.sign(claims(iss)));
  });

  it("rejects a token for another audience as audience", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    const res = await expectRejected(app, await iss.sign(claims(iss, { aud: "https://other.example/mcp" })), "audience");
    expect(res.headers["www-authenticate"]).toContain('error="invalid_token"');
  });

  it("accepts an audience array containing a configured audience, compared as exact strings", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_AUDIENCES: "api://steampipe" });
    await expectAccepted(app, await iss.sign(claims(iss, { aud: ["x", "api://steampipe"] })));
    // The default (PUBLIC_URL) no longer applies once JWT_AUDIENCES is set.
    await expectRejected(app, await iss.sign(claims(iss)), "audience");
    // No normalisation: a trailing slash is a different audience.
    await expectRejected(app, await iss.sign(claims(iss, { aud: "api://steampipe/" })), "audience");
  });
});

describe("jwt: readiness and dispose", () => {
  it("reports an always-ready auth check and a no-op dispose once discovery has succeeded", async () => {
    const iss = await issuerFor();
    const mw = await authMiddleware(jwtConfig(iss.issuer), { now: () => NOW_MS });
    expect(mw.readiness.map((c) => c.name)).toEqual(["auth"]);
    await expect(mw.readiness[0].check(new AbortController().signal)).resolves.toBe("ready");
    expect(() => mw.dispose()).not.toThrow();
  });
});

describe("jwt: auth_reject audit", () => {
  it("writes an auth_reject line for a refused token by default", async () => {
    const iss = await issuerFor();
    const cfg = jwtConfig(iss.issuer);
    const { rootRouters, mcpMiddleware } = await authMiddleware(cfg, { now: () => NOW_MS });
    const app = buildHttpApp(cfg, fakeDb(), mcpMiddleware, rootRouters);
    const server = await new Promise<HttpServer>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    servers.push(server);
    const token = await iss.sign(claims(iss, { exp: NOW_S }));
    const res = await toolsList((server.address() as AddressInfo).port, token);
    expect(res.status).toBe(401);
    const logs = logger.getCollectedLogs();
    expect(logs.some((l) => l.includes('"event":"auth_reject"') && l.includes('"reason":"expired"'))).toBe(true);
    expect(logs.join("\n")).not.toContain(token);
  });

  async function startAudited(iss: TestIssuer): Promise<number> {
    const cfg = jwtConfig(iss.issuer);
    const { rootRouters, mcpMiddleware } = await authMiddleware(cfg, { now: () => NOW_MS });
    const app = buildHttpApp(cfg, fakeDb(), mcpMiddleware, rootRouters);
    const server = await new Promise<HttpServer>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    servers.push(server);
    return (server.address() as AddressInfo).port;
  }

  /** Every auth_reject line written so far, parsed. */
  function rejectLines(): Array<Record<string, unknown>> {
    return logger
      .getCollectedLogs()
      .filter((l) => l.includes('"event":"auth_reject"'))
      .map((l) => JSON.parse(l.slice(l.indexOf("{"))) as Record<string, unknown>);
  }

  it("carries the configured issuer on a rejection once the token is routed to it (I-3)", async () => {
    const iss = await issuerFor({ path: "/t1" });
    const port = await startAudited(iss);
    const token = await iss.sign(claims(iss, { exp: NOW_S }));
    expect((await toolsList(port, token)).status).toBe(401);
    expect(rejectLines()).toEqual([expect.objectContaining({ reason: "expired", iss: iss.issuer })]);
    expect(logger.getCollectedLogs().join("\n")).not.toContain(token);
  });

  it("carries the configured issuer on a 503 during a JWKS outage, and the backoff warning names its origin only (I-3)", async () => {
    const iss = await issuerFor({ path: "/t1" });
    const port = await startAudited(iss);
    iss.setJwksFailing(true);
    const token = await iss.sign(claims(iss));
    expect((await toolsList(port, token)).status).toBe(503);
    expect(rejectLines()).toEqual([expect.objectContaining({ reason: "issuer_unavailable", iss: iss.issuer })]);
    const warnings = logger.getCollectedLogs().filter((l) => l.includes("[WARN]"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`JWKS fetch for ${new URL(iss.issuer).origin} failed (1 consecutive failure, cause: network)`);
    expect(warnings[0]).not.toContain("/t1");
    expect(warnings[0]).not.toContain(token);
  });

  it("writes no iss for a token whose iss matches no configured issuer, or that has none (I-3)", async () => {
    const iss = await issuerFor();
    const port = await startAudited(iss);
    const foreign = await iss.sign(claims(iss, { iss: "https://evil.example" }));
    expect((await toolsList(port, foreign)).status).toBe(401);
    const noIss = await iss.sign(claims(iss, { iss: undefined }));
    expect((await toolsList(port, noIss)).status).toBe(401);
    const lines = rejectLines();
    expect(lines.map((l) => l.reason)).toEqual(["unknown_issuer", "malformed"]);
    for (const line of lines) expect(line).not.toHaveProperty("iss");
    expect(logger.getCollectedLogs().join("\n")).not.toContain("evil.example");
  });
});

describe("jwt: typ and ID-token substitution (Review Focus 2)", () => {
  it("rejects a token with no typ as malformed", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss), { typ: null }), "malformed");
  });

  it("rejects typ JWT as malformed by default", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss), { typ: "JWT" }), "malformed");
  });

  it("accepts typ JWT when JWT_ACCEPTED_TYP lists it", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_ACCEPTED_TYP: "at+jwt,JWT" });
    await expectAccepted(app, await iss.sign(claims(iss), { typ: "JWT" }));
  });

  it("compares typ case-insensitively and accepts the application/ form", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectAccepted(app, await iss.sign(claims(iss), { typ: "AT+JWT" }));
    await expectAccepted(app, await iss.sign(claims(iss), { typ: "application/at+jwt" }));
  });

  it("rejects an ID-token-shaped token (aud = client id, no client_id) even with an accepted typ", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    const idToken = await iss.sign(claims(iss, { aud: "rp-client", client_id: undefined, nonce: "n" }));
    const res = await toolsList(app.port, idToken);
    expect(res.status).toBe(401);
    expect(["audience", "malformed"]).toContain(app.rejects[0]?.reason);
  });

  it("still rejects an ID-token-shaped typ JWT token when JWT is an accepted typ (Entra case)", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_ACCEPTED_TYP: "at+jwt,JWT" });
    const idToken = await iss.sign(claims(iss, { aud: "rp-client", client_id: undefined }), { typ: "JWT" });
    const res = await toolsList(app.port, idToken);
    expect(res.status).toBe(401);
    expect(["audience", "malformed"]).toContain(app.rejects[0]?.reason);
  });

  it("rejects a token for the client id as audience even when client_id is present", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss, { aud: "rp-client" })), "audience");
  });
});

describe("jwt: time boundaries (injected now)", () => {
  it("treats exp == now as expired at skew 0, and exp == now + 1 as valid", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss, { exp: NOW_S })), "expired");
    await expectAccepted(app, await iss.sign(claims(iss, { exp: NOW_S + 1 })));
  });

  it("treats nbf == now + 1 as not yet valid at skew 0, and nbf == now as valid", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss, { nbf: NOW_S + 1 })), "not_yet_valid");
    await expectAccepted(app, await iss.sign(claims(iss, { nbf: NOW_S })));
  });

  it("applies CLOCK_SKEW_S=30 to exp and nbf equally", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_CLOCK_SKEW_S: "30" });
    await expectAccepted(app, await iss.sign(claims(iss, { exp: NOW_S - 29 })));
    await expectRejected(app, await iss.sign(claims(iss, { exp: NOW_S - 31 })), "expired");
    await expectAccepted(app, await iss.sign(claims(iss, { nbf: NOW_S + 29 })));
    await expectRejected(app, await iss.sign(claims(iss, { nbf: NOW_S + 31 })), "not_yet_valid");
  });

  it("rejects iat older than MAX_TOKEN_AGE_S=60 as too_old", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_MAX_TOKEN_AGE_S: "60" });
    await expectRejected(app, await iss.sign(claims(iss, { iat: NOW_S - 61 })), "too_old");
    await expectAccepted(app, await iss.sign(claims(iss, { iat: NOW_S - 60 })));
  });

  it("does not limit token age by default", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectAccepted(app, await iss.sign(claims(iss, { iat: NOW_S - 86400 * 365 })));
  });
});

describe("jwt: algorithm confusion (Review Focus 1)", () => {
  // Cold cache throughout: a token refused by the algorithm allowlist never
  // reaches the key lookup, so the JWKS is never fetched.
  it("rejects alg none (empty signature) as malformed without fetching keys", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    const token = `${b64url({ alg: "none", typ: "at+jwt" })}.${b64url(claims(iss, { jti: "j", client_id: "c" }))}.`;
    await expectRejected(app, token, "malformed");
    expect(iss.jwksRequests()).toBe(0);
  });

  it("rejects alg none with a non-empty signature segment as malformed without fetching keys", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    const payload = claims(iss, { jti: "j", client_id: "c" });
    const token = `${b64url({ alg: "none", typ: "at+jwt", kid: iss.kid() })}.${b64url(payload)}.c2ln`;
    await expectRejected(app, token, "malformed");
    expect(iss.jwksRequests()).toBe(0);
  });

  it("rejects HS256 keyed with the issuer's public key PEM as malformed without fetching keys", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    const pem = new TextEncoder().encode(await iss.publicKeyPem());
    await expectRejected(app, await iss.sign(claims(iss), { alg: "HS256", key: pem }), "malformed");
    expect(iss.jwksRequests()).toBe(0);
  });

  it("rejects an algorithm outside JWT_ALGORITHMS even when the signature is good", async () => {
    const iss = await issuerFor({ alg: "ES256" });
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_ALGORITHMS: "RS256" });
    await expectRejected(app, await iss.sign(claims(iss)), "malformed");
    expect(iss.jwksRequests()).toBe(0);
  });
});

describe("jwt: key rotation with a warm cache (Review Focus 3)", () => {
  async function warm(
    env: Record<string, string> = {},
  ): Promise<{ iss: TestIssuer; app: { port: number; rejects: RejectEvent[] } }> {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW_MS);
    const iss = await issuerFor();
    const app = await startJwt(iss, env, () => Date.now());
    await expectAccepted(app, await iss.sign(claims(iss)));
    expect(iss.jwksRequests()).toBe(1);
    return { iss, app };
  }

  it("refuses a new kid inside the cooldown as signature (401, no refetch), and accepts it after", async () => {
    const { iss, app } = await warm();
    await iss.rotate();

    vi.setSystemTime(NOW_MS + 5_000);
    const early = await iss.sign(claims(iss, { iat: NOW_S + 5 }));
    await expectRejected(app, early, "signature", 401);
    expect(iss.jwksRequests()).toBe(1);

    vi.setSystemTime(NOW_MS + 31_000);
    await expectAccepted(app, await iss.sign(claims(iss, { iat: NOW_S + 31 })));
    expect(iss.jwksRequests()).toBe(2);
  });

  it("honours JWT_JWKS_COOLDOWN_S=5: a new kid is refused at +3 s and accepted at +6 s", async () => {
    const { iss, app } = await warm({ STEAMPIPE_MCP_JWT_JWKS_COOLDOWN_S: "5" });
    await iss.rotate();

    vi.setSystemTime(NOW_MS + 3_000);
    await expectRejected(app, await iss.sign(claims(iss, { iat: NOW_S + 3 })), "signature", 401);
    expect(iss.jwksRequests()).toBe(1);

    vi.setSystemTime(NOW_MS + 6_000);
    await expectAccepted(app, await iss.sign(claims(iss, { iat: NOW_S + 6 })));
    expect(iss.jwksRequests()).toBe(2);
  });

  it("refetches at most once for 10 concurrent new-kid requests after the cooldown", async () => {
    const { iss, app } = await warm();
    await iss.rotate();
    vi.setSystemTime(NOW_MS + 31_000);
    const tokens = await Promise.all(
      Array.from({ length: 10 }, () => iss.sign(claims(iss, { iat: NOW_S + 31 }))),
    );
    const replies = await Promise.all(tokens.map((t) => toolsList(app.port, t)));
    expect(replies.map((r) => r.status)).toEqual(Array(10).fill(200));
    expect(iss.jwksRequests()).toBe(2);
  });

  it("rejects a token signed by an unrelated key that reuses a known kid as signature", async () => {
    const { iss, app } = await warm();
    const { privateKey } = await generateKeyPair("RS256");
    await expectRejected(app, await iss.sign(claims(iss), { kid: iss.kid(), key: privateKey }), "signature");
    expect(iss.jwksRequests()).toBe(1);
  });
});

describe("jwt: claims", () => {
  it("rejects an iss mismatch as unknown_issuer", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss, { iss: `${iss.issuer}/other` })), "unknown_issuer");
  });

  it("rejects a missing, null, empty or over-long sub as subject_missing", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss, { sub: null })), "subject_missing");
    await expectRejected(app, await iss.sign(claims(iss, { sub: undefined })), "subject_missing");
    await expectRejected(app, await iss.sign(claims(iss, { sub: "" })), "subject_missing");
    await expectRejected(app, await iss.sign(claims(iss, { sub: 42 })), "subject_missing");
    await expectRejected(app, await iss.sign(claims(iss, { sub: "s".repeat(257) })), "subject_missing");
    await expectAccepted(app, await iss.sign(claims(iss, { sub: "s".repeat(256) })));
  });

  it("rejects a token missing any RFC 9068 mandatory claim (exp, iat, jti, client_id) as malformed", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    for (const name of ["exp", "iat", "jti", "client_id"]) {
      await expectRejected(app, await iss.sign(claims(iss, { [name]: undefined })), "malformed");
    }
  });

  it("rejects a non-string or empty jti, a non-string iss, and a non-string aud or aud member as malformed", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    for (const bad of [
      { jti: null },
      { jti: 42 },
      { jti: "" },
      { aud: [AUD, 42] },
      { aud: 42 },
      { iss: 42 },
    ]) {
      await expectRejected(app, await iss.sign(claims(iss, bad)), "malformed");
    }
  });

  it("rejects a non-string client_id or scope as malformed", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss, { client_id: 42 })), "malformed");
    await expectRejected(app, await iss.sign(claims(iss, { client_id: "" })), "malformed");
    await expectRejected(app, await iss.sign(claims(iss, { scope: ["read"] })), "malformed");
  });

  it("rejects out-of-range or non-numeric time claims as malformed", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    await expectRejected(app, await iss.sign(claims(iss, { exp: 1e300 })), "malformed");
    await expectRejected(app, await iss.sign(claims(iss, { exp: 2 ** 40 + 1 })), "malformed");
    await expectRejected(app, await iss.sign(claims(iss, { nbf: -1e300 })), "malformed");
    await expectRejected(app, await iss.sign(claims(iss, { iat: "1800000000" })), "malformed");
  });

  it("rejects tokens that are not three base64url segments as malformed", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    const good = await iss.sign(claims(iss));
    const [h, p, s] = good.split(".");
    for (const bad of ["abc", `${h}.${p}`, `${h}.${p}.${s}.x`, `${h}+.${p}.${s}`, `${b64url("x").slice(0, -1)}!.${p}.${s}`]) {
      await expectRejected(app, bad, "malformed");
    }
    // A header that is not a JSON object.
    await expectRejected(app, `${Buffer.from("not json").toString("base64url")}.${p}.${s}`, "malformed");
    expect(iss.jwksRequests()).toBe(0);
  });
});

describe("jwt: issuer reachability", () => {
  it("answers 503 issuer_unavailable when the JWKS connection fails on a cold cache", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss);
    iss.setJwksFailing(true);
    const res = await expectRejected(app, await iss.sign(claims(iss)), "issuer_unavailable", 503);
    expect(res.headers["retry-after"]).toBe("5");
  });

  it("answers 503 issuer_unavailable when the JWKS answers 503, and recovers once the backoff has passed", async () => {
    let clock = NOW_MS;
    const iss = await issuerFor();
    const app = await startJwt(iss, {}, () => clock);
    iss.setJwksFailing(503);
    await expectRejected(app, await iss.sign(claims(iss)), "issuer_unavailable", 503);
    iss.setJwksFailing(false);
    clock += 1000;
    await expectAccepted(app, await iss.sign(claims(iss)));
  });
});

describe("jwt: JWKS backoff during an outage (R16)", () => {
  it("sends one probe for 10 concurrent requests at the window boundary, and answers them all alike", async () => {
    let clock = NOW_MS;
    const iss = await issuerFor();
    const app = await startJwt(iss, {}, () => clock);
    const token = await iss.sign(claims(iss));
    iss.setJwksFailing(true);
    await expectRejected(app, token, "issuer_unavailable", 503);
    expect(iss.jwksRequests()).toBe(1);

    // Window over, JWKS still down: one probe, ten 503s, and the window doubles.
    clock += 1000;
    let replies = await Promise.all(Array.from({ length: 10 }, () => toolsList(app.port, token)));
    expect(replies.map((r) => r.status)).toEqual(Array(10).fill(503));
    expect(iss.jwksRequests()).toBe(2);
    clock += 1999;
    await expectRejected(app, token, "issuer_unavailable", 503);
    expect(iss.jwksRequests()).toBe(2);

    // Window over again, JWKS back: one probe, ten 200s.
    iss.setJwksFailing(false);
    clock += 1;
    replies = await Promise.all(Array.from({ length: 10 }, () => toolsList(app.port, token)));
    expect(replies.map((r) => r.status)).toEqual(Array(10).fill(200));
    expect(iss.jwksRequests()).toBe(3);
  });

  it("fails fast inside the window, doubles it, and serves again after recovery", async () => {
    let clock = NOW_MS;
    const iss = await issuerFor();
    const app = await startJwt(iss, {}, () => clock);
    const token = await iss.sign(claims(iss));
    iss.setJwksFailing(true);

    // First failure opens a 1 s window: 3 requests, 1 fetch, 3 × 503.
    for (let i = 0; i < 3; i++) await expectRejected(app, token, "issuer_unavailable", 503);
    expect(iss.jwksRequests()).toBe(1);

    clock += 999;
    await expectRejected(app, token, "issuer_unavailable", 503);
    expect(iss.jwksRequests()).toBe(1);

    // Window over: one more fetch, which fails and opens a 2 s window.
    clock += 1;
    await expectRejected(app, token, "issuer_unavailable", 503);
    expect(iss.jwksRequests()).toBe(2);
    clock += 1000;
    await expectRejected(app, token, "issuer_unavailable", 503);
    expect(iss.jwksRequests()).toBe(2);

    iss.setJwksFailing(false);
    clock += 1000;
    await expectAccepted(app, token);
    expect(iss.jwksRequests()).toBe(3);
    await expectAccepted(app, await iss.sign(claims(iss)));
    expect(iss.jwksRequests()).toBe(3);
  });

  it("does not let an unknown-kid refetch failure block tokens served from the warm cache", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW_MS);
    const iss = await issuerFor();
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_JWKS_COOLDOWN_S: "1" }, () => Date.now());
    await expectAccepted(app, await iss.sign(claims(iss)));
    expect(iss.jwksRequests()).toBe(1);

    iss.setJwksFailing(true);
    vi.setSystemTime(NOW_MS + 2_000);
    await expectRejected(app, await iss.sign(claims(iss), { kid: "unknown-kid" }), "issuer_unavailable", 503);
    expect(iss.jwksRequests()).toBe(2);
    // Inside the backoff window, but the key is cached: no fetch needed.
    await expectAccepted(app, await iss.sign(claims(iss)));
    expect(iss.jwksRequests()).toBe(2);
  });
});

describe("jwksBackoff", () => {
  const ORIGIN = "https://idp.example";

  function fakeFetch(outcomes: Array<number | "throw" | { body: string }>) {
    let calls = 0;
    const impl = vi.fn(async () => {
      const next = outcomes[calls++] ?? 200;
      // A message with a path: the backoff must log the cause, never this.
      if (next === "throw") throw new FetchRefused("network", "request to https://idp.example/tenant-x/jwks failed");
      if (typeof next === "object") return new Response(next.body, { status: 200 });
      return new Response('{"keys":[]}', { status: next });
    });
    return { impl: impl as unknown as typeof fetch, calls: () => impl.mock.calls.length };
  }

  async function outcome(f: typeof fetch): Promise<unknown> {
    try {
      return (await f(new URL("https://idp.example/tenant-x/jwks"))).status;
    } catch (error) {
      return error;
    }
  }

  /** Every argument of every call, joined, so nothing a call passes escapes the check. */
  function logged(spy: ReturnType<typeof vi.spyOn>): string {
    return spy.mock.calls.flat().map(String).join(" ");
  }

  it("warns once per window opened, with the origin, failure count, next delay and a bounded cause", async () => {
    const warn = vi.spyOn(logger, "warn");
    let clock = 0;
    const f = fakeFetch(["throw", 503, { body: "{}" }]);
    const gated = jwksBackoff(f.impl, ORIGIN, () => clock);

    await outcome(gated);
    await outcome(gated); // inside the window: refused, no new warning
    await outcome(gated);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toBe(
      "JWKS fetch for https://idp.example failed (1 consecutive failure, cause: network); backing off 1000ms",
    );

    clock = 1000;
    await outcome(gated);
    expect(warn).toHaveBeenCalledTimes(2);
    expect(warn.mock.calls[1][0]).toBe(
      "JWKS fetch for https://idp.example failed (2 consecutive failures, cause: HTTP 503); backing off 2000ms",
    );

    clock = 3000;
    await outcome(gated);
    expect(warn).toHaveBeenCalledTimes(3);
    expect(warn.mock.calls[2][0]).toBe(
      "JWKS fetch for https://idp.example failed (3 consecutive failures, cause: invalid key set); backing off 4000ms",
    );

    // Origin only: never the JWKS path or the error message.
    expect(logged(warn)).not.toContain("tenant-x");
    expect(logged(warn)).not.toContain("/jwks");
    warn.mockRestore();
  });

  it("logs info on the first usable 200 after failures, and never on a 200 with no failures before it", async () => {
    const info = vi.spyOn(logger, "info");
    let clock = 0;
    const f = fakeFetch([200, 503, "throw", 200, 200]);
    const gated = jwksBackoff(f.impl, ORIGIN, () => clock);
    expect(await outcome(gated)).toBe(200);
    expect(info).not.toHaveBeenCalled();

    await outcome(gated); // 503: window 1 s
    clock = 1000;
    await outcome(gated); // throw: window 2 s
    clock = 3000;
    expect(await outcome(gated)).toBe(200);
    expect(info).toHaveBeenCalledTimes(1);
    expect(info.mock.calls[0][0]).toBe("JWKS fetch for https://idp.example recovered after 2 consecutive failures");

    expect(await outcome(gated)).toBe(200);
    expect(info).toHaveBeenCalledTimes(1);
    expect(logged(info)).not.toContain("tenant-x");
    info.mockRestore();
  });

  it("refuses with issuer_unavailable inside the window, without calling fetch", async () => {
    let clock = 0;
    const f = fakeFetch(["throw"]);
    const gated = jwksBackoff(f.impl, ORIGIN, () => clock);
    expect(await outcome(gated)).toBeInstanceOf(FetchRefused);
    clock = 999;
    const refused = await outcome(gated);
    expect(refused).toBeInstanceOf(VerifyError);
    expect((refused as VerifyError).reason).toBe("issuer_unavailable");
    expect(f.calls()).toBe(1);
  });

  it("treats a non-200 answer as a failure, and a 200 resets the schedule", async () => {
    let clock = 0;
    const f = fakeFetch([503, "throw", 200, 500]);
    const gated = jwksBackoff(f.impl, ORIGIN, () => clock);
    expect(await outcome(gated)).toBe(503); // window 1 s
    clock = 1000;
    expect(await outcome(gated)).toBeInstanceOf(FetchRefused); // window 2 s
    clock = 2999;
    expect(await outcome(gated)).toBeInstanceOf(VerifyError);
    clock = 3000;
    expect(await outcome(gated)).toBe(200);
    expect(f.calls()).toBe(3);

    // After the reset the next failure opens a 1 s window again, not 4 s.
    expect(await outcome(gated)).toBe(500);
    clock = 3999;
    expect(await outcome(gated)).toBeInstanceOf(VerifyError);
    clock = 4000;
    expect(await outcome(gated)).toBe(200);
    expect(f.calls()).toBe(5);
  });

  it("treats a 200 that is not a JSON key set as a failure", async () => {
    // `keys` must be an array of objects (M-1): jose rejects any other entry.
    for (const body of ["not json", "{}", '{"keys":{}}', "[]", '{"keys":[1]}', '{"keys":[null]}', '{"keys":[[]]}', '{"keys":["k"]}']) {
      let clock = 0;
      const f = fakeFetch([{ body }, 200]);
      const gated = jwksBackoff(f.impl, ORIGIN, () => clock);
      expect(await outcome(gated)).toBe(200); // handed to jose, which rejects it
      clock = 999;
      expect(await outcome(gated)).toBeInstanceOf(VerifyError);
      expect(f.calls()).toBe(1);
      clock = 1000;
      expect(await outcome(gated)).toBe(200);
      expect(f.calls()).toBe(2);
    }
  });

  it("doubles from 1 s and caps the window at 60 s", async () => {
    let clock = 0;
    const f = fakeFetch(Array(9).fill(503));
    const gated = jwksBackoff(f.impl, ORIGIN, () => clock);
    expect(await outcome(gated)).toBe(503);
    for (const window of [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000]) {
      const before = f.calls();
      clock += window - 1;
      expect(await outcome(gated)).toBeInstanceOf(VerifyError);
      expect(f.calls()).toBe(before);
      clock += 1;
      expect(await outcome(gated)).toBe(503);
      expect(f.calls()).toBe(before + 1);
    }
  });
});

describe("jwt: startup discovery", () => {
  it("rejects startup when the discovery document names another issuer", async () => {
    const iss = await issuerFor({ discoveryIssuer: "https://evil.example" });
    await expect(startJwt(iss)).rejects.toThrow(/issuer/);
    // Both conventions were tried; neither could rescue the mismatch.
    expect(iss.requests()).toEqual(["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]);
  });

  it("rejects startup when jwks_uri points at a host that is not allowed, with zero requests to it", async () => {
    let connections = 0;
    const trap = createNetServer((socket) => {
      connections++;
      socket.destroy();
    });
    await new Promise<void>((resolve) => trap.listen(0, "127.0.0.1", () => resolve()));
    const trapPort = (trap.address() as AddressInfo).port;
    try {
      const iss = await issuerFor({ jwksUri: `https://localhost:${trapPort}/jwks` });
      await expect(startJwt(iss)).rejects.toThrow(FetchRefused);
      // Allowing the host via JWT_ALLOWED_HOSTS gets past the policy check.
      const allowed = await issuerFor({ jwksUri: `https://localhost:${trapPort}/jwks` });
      await expect(
        startJwt(allowed, { STEAMPIPE_MCP_JWT_ALLOWED_HOSTS: "localhost" }),
      ).resolves.toBeDefined();
      expect(connections).toBe(0);
    } finally {
      await new Promise((resolve) => trap.close(resolve));
    }
  });

  it("rejects startup when discovery fails", async () => {
    const iss = await issuerFor();
    iss.setDiscoveryFailing(true);
    await expect(startJwt(iss)).rejects.toThrow(/discovery/);
    expect(iss.requests()).toEqual(["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]);
    expect(iss.jwksRequests()).toBe(0);
  });

  it("serves PRM with authorization_servers equal to [issuer] byte-exact", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_SCOPES_SUPPORTED: "mcp.read,mcp.write" });
    const res = await send(app.port, { method: "GET", path: PRM_PATH });
    expect(res.status).toBe(200);
    expect(res.body).toBe(
      `{"resource":${JSON.stringify(AUD)},` +
        `"authorization_servers":[${JSON.stringify(iss.issuer)}],` +
        `"scopes_supported":["mcp.read","mcp.write"],` +
        `"bearer_methods_supported":["header"],` +
        `"resource_name":"Steampipe MCP"}`,
    );
    // The issuer is a bare origin: a URL round trip would have added "/".
    expect(iss.issuer.endsWith("/")).toBe(false);
  });

  it("points 401 challenges at the PRM and advertises JWT_CHALLENGE_SCOPE", async () => {
    const iss = await issuerFor();
    const app = await startJwt(iss, { STEAMPIPE_MCP_JWT_CHALLENGE_SCOPE: "mcp.read" });
    const res = await send(app.port, {
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
      body: TOOLS_LIST,
    });
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe(
      `Bearer resource_metadata="http://127.0.0.1${PRM_PATH}", scope="mcp.read"`,
    );
  });
});

describe("discoverJwks", () => {
  function policyFor(issuer: string, extraHosts: string[] = []): FetchPolicy {
    return {
      allowedHosts: [new URL(issuer).hostname, ...extraHosts],
      insecureAuthorities: [],
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxBytes: DEFAULT_MAX_BYTES,
    };
  }

  it("discovers a tenant-path issuer via the OIDC appended path", async () => {
    const iss = await issuerFor({ path: "/t1", discovery: "oidc" });
    const d = await discoverJwks(iss.issuer, fetch, policyFor(iss.issuer));
    expect(d.issuer).toBe(iss.issuer);
    expect(d.jwksUri.href).toBe(`${new URL(iss.issuer).origin}/jwks`);
    expect(iss.requests()).toEqual(["/t1/.well-known/openid-configuration"]);
  });

  it("falls back to RFC 8414 path insertion for a tenant-path issuer", async () => {
    const iss = await issuerFor({ path: "/t1", discovery: "oauth" });
    const d = await discoverJwks(iss.issuer, fetch, policyFor(iss.issuer));
    expect(d.jwksUri.href).toBe(`${new URL(iss.issuer).origin}/jwks`);
    expect(iss.requests()).toEqual([
      "/t1/.well-known/openid-configuration",
      "/.well-known/oauth-authorization-server/t1",
    ]);
  });

  it("strips one trailing slash before appending the OIDC suffix, but compares the issuer exactly", async () => {
    const iss = await issuerFor({ path: "/t1", discovery: "oidc", discoveryIssuer: (i) => `${i}/` });
    const configured = `${iss.issuer}/`;
    const d = await discoverJwks(configured, fetch, policyFor(configured));
    expect(d.issuer).toBe(configured);
    expect(iss.requests()).toEqual(["/t1/.well-known/openid-configuration"]);
  });

  it("serves the full flow for a tenant-path issuer", async () => {
    const iss = await issuerFor({ path: "/t1", discovery: "oauth" });
    const app = await startJwt(iss);
    await expectAccepted(app, await iss.sign(claims(iss)));
  });

  it("rejects a jwks_uri that does not parse", async () => {
    const iss = await issuerFor({ jwksUri: "not a url" });
    await expect(discoverJwks(iss.issuer, fetch, policyFor(iss.issuer))).rejects.toThrow(/jwks_uri/);
  });

  it("rejects a jwks_uri refused by the fetch policy", async () => {
    const iss = await issuerFor({ jwksUri: "ftp://127.0.0.1/jwks" });
    await expect(discoverJwks(iss.issuer, fetch, policyFor(iss.issuer))).rejects.toThrow(FetchRefused);
  });

  it("rejects an https issuer whose jwks_uri is loopback http (R15), with zero requests to it", async () => {
    let connections = 0;
    const trap = createNetServer((socket) => {
      connections++;
      socket.destroy();
    });
    await new Promise<void>((resolve) => trap.listen(0, "127.0.0.1", () => resolve()));
    const trapPort = (trap.address() as AddressInfo).port;
    const issuer = "https://idp.example.com/t1";
    // Stands in for the https issuer: answers its OIDC document only.
    const fakeFetch = (async (input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : input);
      if (url.href === `${issuer}/.well-known/openid-configuration`) {
        return Response.json({ issuer, jwks_uri: `http://127.0.0.1:${trapPort}/jwks` });
      }
      return new Response(null, { status: 404 });
    }) as typeof fetch;
    try {
      await expect(discoverJwks(issuer, fakeFetch, policyFor(issuer))).rejects.toThrow(/https/);
      // The same document is fine once its jwks_uri is https on an allowed host.
      const ok = (async () => Response.json({ issuer, jwks_uri: "https://idp.example.com/jwks" })) as typeof fetch;
      await expect(discoverJwks(issuer, ok, policyFor(issuer))).resolves.toMatchObject({ issuer });
      expect(connections).toBe(0);
    } finally {
      await new Promise((resolve) => trap.close(resolve));
    }
  });

  it("requires the discovery document's issuer to equal the configured issuer byte for byte", async () => {
    const configured = "https://issuer.example/t1";
    const docFor = (docIssuer: string) =>
      (async () => Response.json({ issuer: docIssuer, jwks_uri: "https://issuer.example/jwks" })) as typeof fetch;
    await expect(discoverJwks(configured, docFor(configured), policyFor(configured))).resolves.toMatchObject({
      issuer: configured,
    });
    for (const variant of [
      "https://issuer.example/t1/",
      "HTTPS://ISSUER.EXAMPLE/t1",
      "https://issuer.example:443/t1",
    ]) {
      await expect(discoverJwks(configured, docFor(variant), policyFor(configured))).rejects.toThrow(
        /different issuer/,
      );
    }
  });

  it("rejects startup when the discovery issuer differs only by a trailing slash or case", async () => {
    for (const variant of [(i: string) => `${i}/`, (i: string) => i.replace("http://", "HTTP://")]) {
      const iss = await issuerFor({ discoveryIssuer: variant });
      await expect(startJwt(iss)).rejects.toThrow(/different issuer/);
    }
  });

  it("still accepts a loopback-http jwks_uri for a loopback-http issuer", async () => {
    const iss = await issuerFor();
    const d = await discoverJwks(iss.issuer, fetch, policyFor(iss.issuer));
    expect(d.jwksUri.protocol).toBe("http:");
    expect(d.jwksUri.hostname).toBe("127.0.0.1");
  });

  it("requires only issuer and jwks_uri", async () => {
    const iss = await issuerFor();
    const d = await discoverJwks(iss.issuer, fetch, policyFor(iss.issuer));
    expect(Object.keys(d).sort()).toEqual(["issuer", "jwksUri"]);
  });

  it("rejects when neither discovery document is served", async () => {
    const iss = await issuerFor();
    iss.setDiscoveryFailing(true);
    await expect(discoverJwks(iss.issuer, fetch, policyFor(iss.issuer))).rejects.toThrow(/discovery/);
    expect(iss.requests()).toHaveLength(2);
  });
});

describe("createJwtVerifier", () => {
  async function verifierFor(
    iss: TestIssuer,
    getKey?: JWTVerifyGetKey,
  ): Promise<ReturnType<typeof createJwtVerifier>> {
    const cfg: IssuerConfig = {
      issuer: iss.issuer,
      audiences: [AUD],
      algorithms: ["RS256", "ES256"],
      acceptedTyp: ["at+jwt", "application/at+jwt"],
      clockSkewS: 0,
      maxTokenAgeS: 0,
    };
    const keys = new Map([[iss.issuer, getKey ?? createRemoteJWKSet(new URL(`${new URL(iss.issuer).origin}/jwks`))]]);
    return createJwtVerifier({ issuers: [cfg], publicUrl: new URL(PUBLIC_URL), keys, now: () => NOW_MS });
  }

  async function reasonOf(p: Promise<unknown>): Promise<Reason | unknown> {
    try {
      await p;
    } catch (error) {
      return error instanceof VerifyError ? error.reason : error;
    }
    throw new Error("expected a rejection");
  }

  it("returns AuthInfo with client_id, split scopes, exp, resource and an issuer-qualified principal", async () => {
    const iss = await issuerFor();
    const verifier = await verifierFor(iss);
    const token = await iss.sign(claims(iss, { scope: "mcp.read  mcp.write", client_id: "c-1", jti: "j-1" }));
    const info = await verifier.verify(token);
    expect(info).toEqual({
      token,
      clientId: "c-1",
      scopes: ["mcp.read", "mcp.write"],
      expiresAt: NOW_S + 300,
      resource: new URL(PUBLIC_URL),
      extra: {
        iss: iss.issuer,
        sub: "svc-1",
        principal: `${iss.issuer}|svc-1`,
        claims: claims(iss, { scope: "mcp.read  mcp.write", client_id: "c-1", jti: "j-1" }),
      },
    });
  });

  it("matches the token iss to the configured issuer as an exact string", async () => {
    const configured = "https://issuer.example/t1";
    const iss = await issuerFor();
    const keys = createLocalJWKSet(await (await fetch(`${iss.issuer}/jwks`)).json());
    const verifier = createJwtVerifier({
      issuers: [
        {
          issuer: configured,
          audiences: [AUD],
          algorithms: ["RS256"],
          acceptedTyp: ["at+jwt"],
          clockSkewS: 0,
          maxTokenAgeS: 0,
        },
      ],
      publicUrl: new URL(PUBLIC_URL),
      keys: new Map([[configured, keys]]),
      now: () => NOW_MS,
    });
    // The exact string is accepted...
    await expect(verifier.verify(await iss.sign(claims(iss, { iss: configured })))).resolves.toBeDefined();
    // ...and URL-equivalent but byte-different spellings are not.
    for (const variant of [
      "https://issuer.example/t1/",
      "HTTPS://ISSUER.EXAMPLE/t1",
      "https://issuer.example:443/t1",
    ]) {
      expect(await reasonOf(verifier.verify(await iss.sign(claims(iss, { iss: variant }))))).toBe("unknown_issuer");
    }
  });

  it("returns no scopes when scope is absent", async () => {
    const iss = await issuerFor();
    const info = await (await verifierFor(iss)).verify(await iss.sign(claims(iss)));
    expect(info.scopes).toEqual([]);
  });

  it("maps key-fetch failures to issuer_unavailable", async () => {
    const iss = await issuerFor();
    const token = await iss.sign(claims(iss));
    const failures = [
      new FetchRefused("network", "down"),
      new errors.JWKSTimeout(),
      new errors.JOSEError("Expected 200 OK from the JSON Web Key Set HTTP response"),
      new errors.JWKSInvalid("JSON Web Key Set malformed"),
    ];
    for (const failure of failures) {
      const verifier = await verifierFor(iss, async () => {
        throw failure;
      });
      expect(await reasonOf(verifier.verify(token))).toBe("issuer_unavailable");
    }
  });

  it("rethrows anything unexpected so it becomes a 500", async () => {
    const iss = await issuerFor();
    const bug = new TypeError("bug");
    const verifier = await verifierFor(iss, async () => {
      throw bug;
    });
    expect(await reasonOf(verifier.verify(await iss.sign(claims(iss))))).toBe(bug);
  });

  it("uses fixed error messages that never quote claim values", async () => {
    const iss = await issuerFor();
    const verifier = await verifierFor(iss);
    const marker = "secret-marker-123";
    const tokens = [
      await iss.sign(claims(iss, { aud: marker })),
      await iss.sign(claims(iss, { iss: marker })),
      await iss.sign(claims(iss, { sub: marker.repeat(30) })),
    ];
    for (const t of tokens) {
      await expect(verifier.verify(t)).rejects.toSatisfy(
        (e: unknown) => e instanceof VerifyError && !e.message.includes(marker),
      );
    }
  });
});

describe("jwt config", () => {
  function load(env: Record<string, string>): ServerConfig {
    return loadConfig(
      { STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_AUTH_MODE: "jwt", STEAMPIPE_MCP_PUBLIC_URL: PUBLIC_URL, ...env },
      ["node", "index.js"],
    );
  }
  const ISSUER = "https://idp.example.com/tenant";

  function expectConfigError(env: Record<string, string>, variable: RegExp): ConfigError {
    let caught: unknown;
    try {
      load(env);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ConfigError);
    expect((caught as Error).message).toMatch(variable);
    return caught as ConfigError;
  }

  it("parses defaults, with the audience defaulting to PUBLIC_URL's href", () => {
    const cfg = load({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_PUBLIC_URL: "https://mcp.example.com" });
    expect(cfg.auth.mode).toBe("jwt");
    expect(cfg.auth.jwt).toEqual({
      issuers: [
        {
          issuer: ISSUER,
          audiences: ["https://mcp.example.com/"],
          algorithms: ["RS256", "ES256"],
          acceptedTyp: ["at+jwt", "application/at+jwt"],
          clockSkewS: 0,
          maxTokenAgeS: 0,
          advertise: true,
        },
      ],
      jwksCooldownS: 30,
      scopesSupported: [],
      challengeScope: [],
      allowedHosts: [],
    });
  });

  it("parses every setting", () => {
    const cfg = load({
      STEAMPIPE_MCP_JWT_ISSUER: "http://127.0.0.1:8080",
      STEAMPIPE_MCP_JWT_AUDIENCES: "a, b",
      STEAMPIPE_MCP_JWT_ALGORITHMS: "PS256,EdDSA",
      STEAMPIPE_MCP_JWT_ACCEPTED_TYP: "at+jwt,JWT",
      STEAMPIPE_MCP_JWT_CLOCK_SKEW_S: "15",
      STEAMPIPE_MCP_JWT_MAX_TOKEN_AGE_S: "3600",
      STEAMPIPE_MCP_JWT_JWKS_COOLDOWN_S: "3600",
      STEAMPIPE_MCP_JWT_SCOPES_SUPPORTED: "mcp.read,mcp.write",
      STEAMPIPE_MCP_JWT_CHALLENGE_SCOPE: "mcp.read",
      STEAMPIPE_MCP_JWT_ALLOWED_HOSTS: "keys.example.com",
    });
    expect(cfg.auth.jwt).toEqual({
      issuers: [
        {
          issuer: "http://127.0.0.1:8080",
          audiences: ["a", "b"],
          algorithms: ["PS256", "EdDSA"],
          acceptedTyp: ["at+jwt", "jwt"],
          clockSkewS: 15,
          maxTokenAgeS: 3600,
          advertise: true,
        },
      ],
      jwksCooldownS: 3600,
      scopesSupported: ["mcp.read", "mcp.write"],
      challengeScope: ["mcp.read"],
      allowedHosts: ["keys.example.com"],
    });
  });

  it("refuses HS* and none algorithms", () => {
    for (const algs of ["HS256", "RS256,HS512", "none", "RS256,None", "FOO256"]) {
      expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_ALGORITHMS: algs }, /STEAMPIPE_MCP_JWT_ALGORITHMS/);
    }
  });

  it("requires JWT_ISSUER", () => {
    expectConfigError({}, /STEAMPIPE_MCP_JWT_ISSUER/);
  });

  it("requires an https issuer, or http only on loopback, without echoing it", () => {
    for (const issuer of [
      "http://idp.example.com",
      "ftp://idp.example.com",
      "not a url",
      "https://idp.example.com/t?x=1",
      "https://idp.example.com/t#f",
    ]) {
      expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: issuer }, /STEAMPIPE_MCP_JWT_ISSUER/);
    }
    const err = expectConfigError(
      { STEAMPIPE_MCP_JWT_ISSUER: "http://user:hunter2@idp.example.com" },
      /STEAMPIPE_MCP_JWT_ISSUER/,
    );
    expect(err.message).not.toContain("hunter2");
  });

  it("requires PUBLIC_URL", () => {
    expect(() =>
      loadConfig(
        { STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_AUTH_MODE: "jwt", STEAMPIPE_MCP_JWT_ISSUER: ISSUER },
        ["node", "index.js"],
      ),
    ).toThrow(/STEAMPIPE_MCP_PUBLIC_URL/);
  });

  it("refuses an empty audience or typ list", () => {
    expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_AUDIENCES: " , " }, /STEAMPIPE_MCP_JWT_AUDIENCES/);
    expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_ACCEPTED_TYP: "," }, /STEAMPIPE_MCP_JWT_ACCEPTED_TYP/);
  });

  it("validates the integer settings", () => {
    for (const [name, value] of [
      ["CLOCK_SKEW_S", "-1"],
      ["CLOCK_SKEW_S", "1.5"],
      ["MAX_TOKEN_AGE_S", "abc"],
      ["JWKS_COOLDOWN_S", "0"],
      ["JWKS_COOLDOWN_S", "3601"],
    ]) {
      expectConfigError(
        { STEAMPIPE_MCP_JWT_ISSUER: ISSUER, [`STEAMPIPE_MCP_JWT_${name}`]: value },
        new RegExp(`STEAMPIPE_MCP_JWT_${name}`),
      );
    }
  });

  it("caps JWT_CLOCK_SKEW_S at 300 seconds (M-6)", () => {
    expect(load({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_CLOCK_SKEW_S: "300" }).auth.jwt?.issuers[0].clockSkewS).toBe(300);
    const err = expectConfigError(
      { STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_CLOCK_SKEW_S: "301" },
      /^STEAMPIPE_MCP_JWT_CLOCK_SKEW_S must be an integer between 0 and 300$/,
    );
    expect(err.message).not.toContain("301");
  });

  it("refuses an issuer containing '|', the principal separator, without echoing it (M-3)", () => {
    for (const issuer of ["https://idp.example.com/t|x", "https://idp.example.com/|", "https://idp.example.com/t%7C|"]) {
      const err = expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: issuer }, /^STEAMPIPE_MCP_JWT_ISSUER must not contain "\|"$/);
      expect(err.message).not.toContain("idp.example.com");
    }
    // A host position '|' too, which would otherwise read as "not a valid URL".
    expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: "https://idp|example.com" }, /^STEAMPIPE_MCP_JWT_ISSUER must not contain "\|"$/);
  });

  it("refuses scopes that are not RFC 6750 scope tokens", () => {
    expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_SCOPES_SUPPORTED: 'a"b' }, /STEAMPIPE_MCP_JWT_SCOPES_SUPPORTED/);
    expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_CHALLENGE_SCOPE: "a\\b" }, /STEAMPIPE_MCP_JWT_CHALLENGE_SCOPE/);
  });

  it("refuses allowed hosts that carry a scheme or path", () => {
    expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_ALLOWED_HOSTS: "https://keys.example.com" }, /STEAMPIPE_MCP_JWT_ALLOWED_HOSTS/);
    expectConfigError({ STEAMPIPE_MCP_JWT_ISSUER: ISSUER, STEAMPIPE_MCP_JWT_ALLOWED_HOSTS: "keys.example.com/x" }, /STEAMPIPE_MCP_JWT_ALLOWED_HOSTS/);
  });

  it("does not read JWT settings in other auth modes", () => {
    const cfg = loadConfig(
      { STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_JWT_ALGORITHMS: "HS256" },
      ["node", "index.js"],
    );
    expect(cfg.auth.jwt).toBeUndefined();
  });
});
