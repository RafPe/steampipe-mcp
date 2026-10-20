import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createServer as createNodeServer,
  request as httpRequest,
  type IncomingMessage,
  type Server as HttpServer,
} from "node:http";
import type { AddressInfo } from "node:net";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { InsufficientScopeError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { loadConfig, type ServerConfig } from "../src/config.js";
import { DatabaseService } from "../src/services/database.js";
import { buildHttpApp } from "../src/http/app.js";
import { authMiddleware } from "../src/auth/index.js";
import { createStaticTokenVerifier } from "../src/auth/verifiers.js";
import { createGoogleVerifier, fetchGoogleMetadata } from "../src/auth/google.js";
import { testDbUrl } from "./helpers/db.js";

// No test here talks to Google: tokeninfo and the discovery document are
// served by an in-test HTTP server, and the metadata fetcher is injected.

const STATIC_TOKEN = "s".repeat(40);
const CLIENT = "our-client.apps.googleusercontent.com";
const OTHER_CLIENT = "someone-else.apps.googleusercontent.com";
const PUBLIC_URL = "http://127.0.0.1/mcp";

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

function tokenConfig(): ServerConfig {
  return httpConfig({ STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_AUTH_TOKEN: STATIC_TOKEN });
}

function googleConfig(env: Record<string, string> = {}): ServerConfig {
  return httpConfig({
    STEAMPIPE_MCP_AUTH_MODE: "google",
    STEAMPIPE_MCP_PUBLIC_URL: PUBLIC_URL,
    STEAMPIPE_MCP_GOOGLE_CLIENT_ID: CLIENT,
    STEAMPIPE_MCP_ALLOWED_DOMAINS: "corp.com",
    ...env,
  });
}

const FAKE_GOOGLE_METADATA: OAuthMetadata = {
  issuer: "https://accounts.google.com",
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint: "https://oauth2.googleapis.com/token",
  response_types_supported: ["code"],
};

let servers: HttpServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
  vi.restoreAllMocks();
});

async function listen(server: HttpServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

interface FakeRequest {
  method: string;
  url: string;
  contentType?: string;
  body: string;
}

/**
 * Fake Google: POST /tokeninfo answers from `tokens` (keyed by the
 * form-encoded access_token), GET /discovery serves `discovery`. Every
 * request is recorded so tests can assert on what Google would have seen.
 */
async function fakeGoogle(opts: {
  tokens?: Record<string, { status: number; body: unknown }>;
  discovery?: unknown;
}): Promise<{ base: string; requests: FakeRequest[] }> {
  const requests: FakeRequest[] = [];
  const server = createNodeServer((req: IncomingMessage, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      requests.push({ method: req.method ?? "", url: req.url ?? "", contentType: req.headers["content-type"], body });
      let status = 404;
      let payload: unknown = { error: "not_found" };
      if (req.url === "/tokeninfo" && req.method === "POST") {
        const token = new URLSearchParams(body).get("access_token") ?? "";
        const entry = opts.tokens?.[token];
        status = entry?.status ?? 400;
        payload = entry?.body ?? { error: "invalid_token", error_description: "Invalid Value" };
      } else if (req.url === "/discovery" && opts.discovery !== undefined) {
        status = 200;
        payload = opts.discovery;
      }
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(typeof payload === "string" ? payload : JSON.stringify(payload));
    });
  });
  const port = await listen(server);
  return { base: `http://127.0.0.1:${port}`, requests };
}

async function startApp(cfg: ServerConfig, tokeninfoUrl?: string): Promise<number> {
  const { rootRouters, mcpMiddleware } = await authMiddleware(cfg, {
    metadataFetcher: async () => FAKE_GOOGLE_METADATA,
    tokeninfoUrl,
  });
  const app = buildHttpApp(cfg, newDb(), mcpMiddleware, rootRouters);
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

interface Response {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function send(
  port: number,
  opts: { method?: string; path?: string; headers?: Record<string, string>; body?: string },
): Promise<Response> {
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
const MCP_HEADERS = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };

function toolsList(port: number, token?: string, path = "/mcp"): Promise<Response> {
  const headers: Record<string, string> = { ...MCP_HEADERS };
  if (token !== undefined) headers.Authorization = `Bearer ${token}`;
  return send(port, { path, headers, body: TOOLS_LIST });
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
      scope: "openid https://www.googleapis.com/auth/userinfo.email",
      exp: String(nowSec() + 3600),
      ...overrides,
    },
  };
}

describe("authMiddleware: none", () => {
  it("returns no routers and no MCP middleware", async () => {
    expect(await authMiddleware(httpConfig())).toEqual({ rootRouters: [], mcpMiddleware: [] });
  });
});

describe("authMiddleware: static token", () => {
  it("rejects a request with no Authorization header with 401 and a Bearer challenge", async () => {
    const port = await startApp(tokenConfig());
    const res = await toolsList(port);
    expect(res.status).toBe(401);
    expect(String(res.headers["www-authenticate"])).toMatch(/^Bearer error="invalid_token"/);
  });

  it("rejects a wrong token with 401", async () => {
    const port = await startApp(tokenConfig());
    expect((await toolsList(port, "w".repeat(40))).status).toBe(401);
    expect((await toolsList(port, "short")).status).toBe(401);
  });

  it("accepts the right token", async () => {
    const port = await startApp(tokenConfig());
    const res = await toolsList(port, STATIC_TOKEN);
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).result.tools.length).toBeGreaterThan(0);
  });

  it("ignores ?access_token= in the query string", async () => {
    const port = await startApp(tokenConfig());
    const res = await toolsList(port, undefined, `/mcp?access_token=${STATIC_TOKEN}`);
    expect(res.status).toBe(401);
  });

  it("leaves GET/DELETE on the MCP path as unauthenticated 405s", async () => {
    const port = await startApp(tokenConfig());
    for (const method of ["GET", "DELETE"]) {
      expect((await send(port, { method })).status).toBe(405);
    }
  });

  it("returns static AuthInfo with an expiry the SDK will accept", async () => {
    const info = await createStaticTokenVerifier(STATIC_TOKEN).verifyAccessToken(STATIC_TOKEN);
    expect(info).toMatchObject({ token: STATIC_TOKEN, clientId: "static", scopes: [], extra: { sub: "static" } });
    expect(info.expiresAt).toBeGreaterThan(nowSec());
    await expect(createStaticTokenVerifier(STATIC_TOKEN).verifyAccessToken("x")).rejects.toBeInstanceOf(
      InvalidTokenError,
    );
  });
});

describe("authMiddleware: google", () => {
  it("answers no token with 401 and a resource_metadata pointer to the PRM", async () => {
    const google = await fakeGoogle({});
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    const res = await toolsList(port);
    expect(res.status).toBe(401);
    expect(String(res.headers["www-authenticate"])).toContain(
      'resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource/mcp"',
    );
  });

  it("serves Protected Resource Metadata pointing at accounts.google.com, without auth", async () => {
    const google = await fakeGoogle({});
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    const res = await send(port, { method: "GET", path: "/.well-known/oauth-protected-resource/mcp" });
    expect(res.status).toBe(200);
    const prm = JSON.parse(res.body);
    expect(prm.resource).toBe(PUBLIC_URL);
    expect(prm.authorization_servers).toEqual(["https://accounts.google.com"]);
    expect(prm.scopes_supported).toEqual(["openid", "email"]);
  });

  it("still applies Origin validation to the well-known routes", async () => {
    const google = await fakeGoogle({});
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    const res = await send(port, {
      method: "GET",
      path: "/.well-known/oauth-protected-resource/mcp",
      headers: { Origin: "https://evil.example" },
    });
    expect(res.status).toBe(403);
  });

  it("accepts a valid token for our client from an allowlisted domain", async () => {
    const google = await fakeGoogle({ tokens: { good: tokeninfo() } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    const res = await toolsList(port, "good");
    expect(res.status).toBe(200);
  });

  it("accepts an allowlisted email outside the allowlisted domains, case-insensitively", async () => {
    const google = await fakeGoogle({ tokens: { good: tokeninfo({ email: "Bob@Partner.example" }) } });
    const port = await startApp(
      googleConfig({ STEAMPIPE_MCP_ALLOWED_EMAILS: "bob@partner.example" }),
      `${google.base}/tokeninfo`,
    );
    expect((await toolsList(port, "good")).status).toBe(200);
  });

  it("rejects a token issued to a different OAuth client with 401 invalid_token (Review Focus 3)", async () => {
    const google = await fakeGoogle({ tokens: { other: tokeninfo({ aud: OTHER_CLIENT, azp: OTHER_CLIENT }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    const res = await toolsList(port, "other");
    expect(res.status).toBe(401);
    expect(String(res.headers["www-authenticate"])).toContain('error="invalid_token"');
  });

  it("rejects an expired token with 401", async () => {
    const google = await fakeGoogle({ tokens: { old: tokeninfo({ exp: String(nowSec() - 10) }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "old")).status).toBe(401);
  });

  it("rejects a token tokeninfo answers with 400 as 401", async () => {
    const google = await fakeGoogle({});
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "garbage")).status).toBe(401);
  });

  it("rejects a non-allowlisted email with 403 insufficient_scope (Review Focus 4)", async () => {
    const google = await fakeGoogle({ tokens: { evil: tokeninfo({ email: "x@evil.com" }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    const res = await toolsList(port, "evil");
    expect(res.status).toBe(403);
    expect(String(res.headers["www-authenticate"])).toContain('error="insufficient_scope"');
    expect(res.body).not.toContain("result");
  });

  it("rejects an unverified email with 403 (Review Focus 4)", async () => {
    const google = await fakeGoogle({ tokens: { unverified: tokeninfo({ email_verified: "false" }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "unverified")).status).toBe(403);
  });

  it("does not treat a domain lookalike as allowlisted", async () => {
    const google = await fakeGoogle({ tokens: { look: tokeninfo({ email: "a@evilcorp.com" }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "look")).status).toBe(403);
  });

  it("rejects a token with aud=foreign and azp=ours with 401 (R17)", async () => {
    const google = await fakeGoogle({ tokens: { mixed: tokeninfo({ aud: OTHER_CLIENT, azp: CLIENT }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "mixed")).status).toBe(401);
  });

  for (const email of ["a@corp.com.evil.com", '"a@corp.com"@evil.com']) {
    it(`rejects ${email} with 403 when only ALLOWED_DOMAINS=corp.com is set`, async () => {
      const google = await fakeGoogle({ tokens: { t: tokeninfo({ email }) } });
      const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
      expect((await toolsList(port, "t")).status).toBe(403);
    });
  }

  it("rejects a domain-admitted principal whose hd differs from the email domain with 403", async () => {
    const google = await fakeGoogle({ tokens: { t: tokeninfo({ email: "a@corp.com", hd: "other.com" }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "t")).status).toBe(403);
  });

  it("accepts a domain-admitted principal whose hd matches the email domain, case-insensitively", async () => {
    const google = await fakeGoogle({ tokens: { t: tokeninfo({ email: "a@corp.com", hd: "Corp.COM" }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "t")).status).toBe(200);
  });

  it("accepts a domain-admitted principal when tokeninfo omits hd", async () => {
    const google = await fakeGoogle({ tokens: { t: tokeninfo({ email: "a@corp.com", hd: undefined }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "t")).status).toBe(200);
  });

  it("does not apply the hd check to an explicitly allowlisted email", async () => {
    const google = await fakeGoogle({ tokens: { t: tokeninfo({ email: "bob@partner.example", hd: "other.com" }) } });
    const port = await startApp(
      googleConfig({ STEAMPIPE_MCP_ALLOWED_EMAILS: "bob@partner.example" }),
      `${google.base}/tokeninfo`,
    );
    expect((await toolsList(port, "t")).status).toBe(200);
  });

  it("caches a positive result: two calls with the same token hit tokeninfo once", async () => {
    const google = await fakeGoogle({ tokens: { good: tokeninfo() } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "good")).status).toBe(200);
    expect((await toolsList(port, "good")).status).toBe(200);
    expect(google.requests.filter((r) => r.url === "/tokeninfo")).toHaveLength(1);
  });

  it("never caches a negative result", async () => {
    const google = await fakeGoogle({ tokens: { evil: tokeninfo({ email: "x@evil.com" }) } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "evil")).status).toBe(403);
    expect((await toolsList(port, "evil")).status).toBe(403);
    expect(google.requests.filter((r) => r.url === "/tokeninfo")).toHaveLength(2);
  });

  it("sends the token as a form body, never in the tokeninfo URL", async () => {
    const google = await fakeGoogle({ tokens: { "secret-token-value": tokeninfo() } });
    const port = await startApp(googleConfig(), `${google.base}/tokeninfo`);
    expect((await toolsList(port, "secret-token-value")).status).toBe(200);
    const calls = google.requests.filter((r) => r.url.startsWith("/tokeninfo"));
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).not.toContain("secret-token-value");
    expect(calls[0].contentType).toMatch(/^application\/x-www-form-urlencoded/);
    expect(calls[0].body).toBe("access_token=secret-token-value");
  });

  it("fails closed with 500 when tokeninfo is unreachable", async () => {
    const closed = createNodeServer();
    const closedPort = await listen(closed);
    await new Promise((resolve) => closed.close(resolve));
    servers = servers.filter((s) => s !== closed);
    const port = await startApp(googleConfig(), `http://127.0.0.1:${closedPort}/tokeninfo`);
    expect((await toolsList(port, "good")).status).toBe(500);
  });

  it("fails startup when the Google metadata cannot be fetched", async () => {
    await expect(
      authMiddleware(googleConfig(), {
        metadataFetcher: async () => {
          throw new Error("network down");
        },
      }),
    ).rejects.toThrow();
  });
});

describe("createGoogleVerifier: malformed tokeninfo", () => {
  async function verifierFor(body: unknown, status = 200) {
    const google = await fakeGoogle({ tokens: { t: { status, body } } });
    return createGoogleVerifier({
      clientId: CLIENT,
      allowedEmails: [],
      allowedDomains: ["corp.com"],
      publicUrl: new URL(PUBLIC_URL),
      tokeninfoUrl: `${google.base}/tokeninfo`,
    });
  }

  it("rejects a missing exp as invalid_token", async () => {
    const v = await verifierFor({ ...(tokeninfo().body as object), exp: undefined });
    await expect(v.verifyAccessToken("t")).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("rejects a non-numeric exp as invalid_token", async () => {
    const v = await verifierFor({ ...(tokeninfo().body as object), exp: "soon" });
    await expect(v.verifyAccessToken("t")).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("rejects a missing email as insufficient_scope", async () => {
    const v = await verifierFor({ ...(tokeninfo().body as object), email: undefined });
    await expect(v.verifyAccessToken("t")).rejects.toBeInstanceOf(InsufficientScopeError);
  });

  it("rejects a non-JSON 200 body as invalid_token", async () => {
    const v = await verifierFor("not json at all");
    await expect(v.verifyAccessToken("t")).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("rejects aud=foreign with azp=ours as invalid_token (R17: aud must be our client)", async () => {
    const v = await verifierFor({ ...(tokeninfo().body as object), aud: OTHER_CLIENT, azp: CLIENT });
    await expect(v.verifyAccessToken("t")).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("accepts aud=ours and reports AuthInfo with clientId = aud", async () => {
    const exp = nowSec() + 3600;
    const v = await verifierFor({ ...(tokeninfo().body as object), azp: OTHER_CLIENT, exp: String(exp) });
    const info = await v.verifyAccessToken("t");
    expect(info).toEqual({
      token: "t",
      clientId: CLIENT,
      scopes: ["openid", "https://www.googleapis.com/auth/userinfo.email"],
      expiresAt: exp,
      resource: new URL(PUBLIC_URL),
      extra: { sub: "1234", email: "a@corp.com" },
    });
  });

  it("never hands out the shared cached AuthInfo: mutating a result does not affect the next call", async () => {
    const v = await verifierFor(tokeninfo().body);
    const first = await v.verifyAccessToken("t");
    try {
      first.scopes.push("admin");
      first.clientId = "tampered";
      (first.extra as Record<string, unknown>).email = "x@evil.com";
    } catch {
      // A frozen result throwing on mutation is equally acceptable.
    }
    const second = await v.verifyAccessToken("t");
    expect(second.clientId).toBe(CLIENT);
    expect(second.scopes).toEqual(["openid", "https://www.googleapis.com/auth/userinfo.email"]);
    expect(second.extra).toEqual({ sub: "1234", email: "a@corp.com" });
  });

  it("stops serving a cached result once the injected clock passes the TTL", async () => {
    const google = await fakeGoogle({ tokens: { t: tokeninfo() } });
    let clock = Date.now();
    const v = createGoogleVerifier({
      clientId: CLIENT,
      allowedEmails: [],
      allowedDomains: ["corp.com"],
      publicUrl: new URL(PUBLIC_URL),
      tokeninfoUrl: `${google.base}/tokeninfo`,
      now: () => clock,
    });
    await v.verifyAccessToken("t");
    clock += 59_000;
    await v.verifyAccessToken("t");
    expect(google.requests).toHaveLength(1);
    clock += 2_000;
    await v.verifyAccessToken("t");
    expect(google.requests).toHaveLength(2);
  });
});

describe("fetchGoogleMetadata", () => {
  it("returns validated metadata for the Google issuer", async () => {
    const google = await fakeGoogle({ discovery: { ...FAKE_GOOGLE_METADATA, extra_field: 1 } });
    const metadata = await fetchGoogleMetadata(`${google.base}/discovery`);
    expect(metadata.issuer).toBe("https://accounts.google.com");
    expect(metadata.authorization_endpoint).toBe(FAKE_GOOGLE_METADATA.authorization_endpoint);
  });

  it("rejects a document from any other issuer", async () => {
    const google = await fakeGoogle({ discovery: { ...FAKE_GOOGLE_METADATA, issuer: "https://evil.example" } });
    await expect(fetchGoogleMetadata(`${google.base}/discovery`)).rejects.toThrow(/issuer/);
  });

  it("rejects a non-200 discovery response", async () => {
    const google = await fakeGoogle({});
    await expect(fetchGoogleMetadata(`${google.base}/discovery`)).rejects.toThrow();
  });
});
