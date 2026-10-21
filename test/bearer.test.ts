import { afterEach, describe, expect, it, vi } from "vitest";
import express from "express";
import type { Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { bearerAuth, challenge, type BearerOptions, type RejectEvent, type TokenVerifier } from "../src/auth/bearer.js";
import { reasonOf, statusFor, VerifyError, type Reason } from "../src/auth/errors.js";
import { logger } from "../src/services/logger.js";

const PRM_URL = "http://127.0.0.1/.well-known/oauth-protected-resource/mcp";
const RESOURCE = "http://127.0.0.1/mcp";

let servers: HttpServer[] = [];

afterEach(async () => {
  for (const s of servers) s.closeAllConnections();
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
  vi.restoreAllMocks();
});

function okInfo(token: string, overrides: Partial<AuthInfo> = {}): AuthInfo {
  return { token, clientId: "c", scopes: [], extra: { sub: "u1" }, ...overrides };
}

/** A verifier that accepts "good" and otherwise throws whatever `fail` says. */
function stubVerifier(fail: () => never = () => {
  throw new VerifyError("invalid", "Invalid token");
}): TokenVerifier & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async verify(token) {
      calls.push(token);
      if (token === "good") return okInfo(token, { resource: new URL(RESOURCE) });
      fail();
    },
  };
}

function rejecting(reason: Reason, message = "nope"): TokenVerifier & { calls: string[] } {
  return stubVerifier(() => {
    throw new VerifyError(reason, message);
  });
}

async function start(
  opts: Partial<BearerOptions> & { verifier: TokenVerifier },
): Promise<{ base: string; events: RejectEvent[] }> {
  const events: RejectEvent[] = [];
  const app = express();
  app.post(
    "/mcp",
    bearerAuth({ resourceMetadataUrl: PRM_URL, onReject: (e) => events.push(e), ...opts }),
    (req, res) => {
      res.json({ ok: true, sub: req.auth?.extra?.sub, clientId: req.auth?.clientId });
    },
  );
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, events };
}

function post(base: string, authorization?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (authorization !== undefined) headers.Authorization = authorization;
  return fetch(`${base}/mcp`, { method: "POST", headers });
}

describe("bearerAuth: no credentials (RFC 6750 §3.1)", () => {
  it("answers a missing header with 401 and a bare resource_metadata challenge", async () => {
    const { base, events } = await start({ verifier: stubVerifier() });
    const res = await post(base);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(`Bearer resource_metadata="${PRM_URL}"`);
    expect(await res.json()).toEqual({ error: "invalid_token", error_description: "Missing Authorization header" });
    expect(events).toHaveLength(1);
    expect(events[0].reason).toBe("missing");
    expect(events[0].status).toBe(401);
    expect(typeof events[0].durationMs).toBe("number");
  });

  it("treats a non-Bearer scheme exactly like a missing header, with no error=", async () => {
    const { base, events } = await start({ verifier: stubVerifier() });
    const res = await post(base, "Basic x");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(`Bearer resource_metadata="${PRM_URL}"`);
    expect(res.headers.get("www-authenticate")).not.toContain("error=");
    expect(events[0].reason).toBe("missing");
  });

  it("sends a bare Bearer challenge when no resourceMetadataUrl is configured", async () => {
    const { base } = await start({ verifier: stubVerifier(), resourceMetadataUrl: undefined });
    const res = await post(base);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
  });
});

describe("bearerAuth: presented token", () => {
  it("accepts a good token, sets req.auth, and calls next", async () => {
    const { base, events } = await start({ verifier: stubVerifier() });
    const res = await post(base, "Bearer good");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, sub: "u1", clientId: "c" });
    expect(events).toHaveLength(0);
  });

  it("matches the Bearer scheme case-insensitively", async () => {
    const { base } = await start({ verifier: stubVerifier() });
    expect((await post(base, "bearer good")).status).toBe(200);
    expect((await post(base, "BEARER good")).status).toBe(200);
  });

  for (const header of ["Bearer", "Bearer ", "Bearer a b"]) {
    it(`rejects ${JSON.stringify(header)} as malformed without calling the verifier`, async () => {
      const verifier = stubVerifier();
      const { base, events } = await start({ verifier });
      const res = await post(base, header);
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toContain('error="invalid_token"');
      expect(events[0].reason).toBe("malformed");
      expect(verifier.calls).toHaveLength(0);
    });
  }

  const unauthorizedReasons: Reason[] = [
    "malformed",
    "unknown_issuer",
    "invalid",
    "signature",
    "expired",
    "not_yet_valid",
    "too_old",
    "audience",
    "subject_missing",
  ];
  for (const reason of unauthorizedReasons) {
    it(`answers ${reason} with 401 error="invalid_token" and resource_metadata`, async () => {
      const { base, events } = await start({ verifier: rejecting(reason, "Token rejected") });
      const res = await post(base, "Bearer bad");
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe(
        `Bearer error="invalid_token", error_description="Token rejected", resource_metadata="${PRM_URL}"`,
      );
      expect(await res.json()).toEqual({ error: "invalid_token", error_description: "Token rejected" });
      expect(events[0]).toMatchObject({ reason, status: 401 });
    });
  }

  it("answers not_allowed with 403 access_denied and no WWW-Authenticate", async () => {
    const { base, events } = await start({
      verifier: rejecting("not_allowed", "Principal not allowed"),
      challengeScope: ["openid", "email"],
    });
    const res = await post(base, "Bearer bad");
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toBeNull();
    expect(await res.json()).toEqual({ error: "access_denied", error_description: "Principal not allowed" });
    expect(events[0]).toMatchObject({ reason: "not_allowed", status: 403 });
  });

  it("answers issuer_unavailable with 503, Retry-After: 5, and a fixed body", async () => {
    const { base, events } = await start({
      verifier: rejecting("issuer_unavailable", "tokeninfo said 502 at 10.0.0.1"),
      challengeScope: ["openid", "email"],
    });
    const res = await post(base, "Bearer bad");
    expect(res.status).toBe(503);
    expect(res.headers.get("retry-after")).toBe("5");
    expect(res.headers.get("www-authenticate")).toBeNull();
    expect(await res.json()).toEqual({
      error: "temporarily_unavailable",
      error_description: "Token validation unavailable",
    });
    expect(events[0]).toMatchObject({ reason: "issuer_unavailable", status: 503 });
  });

  it("answers a non-VerifyError throw with 500 server_error, logged without the token or message", async () => {
    const errorSpy = vi.spyOn(logger, "error").mockImplementation(() => {});
    const secret = "leaky-token-value";
    const verifier: TokenVerifier = {
      async verify(token) {
        throw new TypeError(`boom, saw ${token}`);
      },
    };
    const { base, events } = await start({ verifier });
    const res = await post(base, `Bearer ${secret}`);
    expect(res.status).toBe(500);
    expect(res.headers.get("www-authenticate")).toBeNull();
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ error: "server_error", error_description: "Internal Server Error" });
    expect(text).not.toContain(secret);
    expect(events).toHaveLength(0);
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(errorSpy.mock.calls)).toContain("TypeError");
    expect(JSON.stringify(errorSpy.mock.calls)).not.toContain(secret);
  });

  it("strips quotes, backslashes, CR/LF and non-ASCII from error_description (Review Focus 4)", async () => {
    const { base } = await start({ verifier: rejecting("invalid", 'a"b\\c\r\nX: y é') });
    const res = await post(base, "Bearer bad");
    expect(res.status).toBe(401);
    const header = res.headers.get("www-authenticate") ?? "";
    expect(header).toContain('error_description="abcX: y "');
    expect(header).not.toMatch(/[\r\n]/);
    expect(res.headers.get("x")).toBeNull();
  });

  it("rejects a token whose AuthInfo.resource differs from expectedResource as audience", async () => {
    const { base, events } = await start({
      verifier: stubVerifier(),
      expectedResource: "https://other.example/mcp",
    });
    const res = await post(base, "Bearer good");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain('error="invalid_token"');
    expect(events[0].reason).toBe("audience");
  });

  it("rejects a token with no AuthInfo.resource when expectedResource is set", async () => {
    const verifier: TokenVerifier = { verify: async (t) => okInfo(t) };
    const { base, events } = await start({ verifier, expectedResource: RESOURCE });
    expect((await post(base, "Bearer good")).status).toBe(401);
    expect(events[0].reason).toBe("audience");
  });

  it("accepts a matching expectedResource, ignoring a fragment", async () => {
    const verifier: TokenVerifier = { verify: async (t) => okInfo(t, { resource: new URL(`${RESOURCE}#frag`) }) };
    const { base } = await start({ verifier, expectedResource: RESOURCE });
    expect((await post(base, "Bearer good")).status).toBe(200);
  });

  it("does not treat a trailing slash as the same resource (exact compare)", async () => {
    const verifier: TokenVerifier = { verify: async (t) => okInfo(t, { resource: new URL(`${RESOURCE}/`) }) };
    const { base } = await start({ verifier, expectedResource: RESOURCE });
    expect((await post(base, "Bearer good")).status).toBe(401);
  });

  it("rejects a 9000-byte token as malformed without calling the verifier", async () => {
    const verifier = stubVerifier();
    const { base, events } = await start({ verifier });
    const res = await post(base, `Bearer ${"a".repeat(9000)}`);
    expect(res.status).toBe(401);
    expect(events[0].reason).toBe("malformed");
    expect(verifier.calls).toHaveLength(0);
  });

  it("honours a custom maxTokenBytes, counting bytes rather than characters", async () => {
    const verifier = stubVerifier();
    const { base, events } = await start({ verifier, maxTokenBytes: 4 });
    expect((await post(base, "Bearer good")).status).toBe(200);
    expect((await post(base, "Bearer goods")).status).toBe(401);
    expect(events[0].reason).toBe("malformed");
    expect(verifier.calls).toEqual(["good"]);
  });

  it("never puts the token into a RejectEvent", async () => {
    const secret = "super-secret-token-value";
    const events: RejectEvent[] = [];
    for (const reason of ["invalid", "not_allowed", "issuer_unavailable", "audience"] as Reason[]) {
      const started = await start({ verifier: rejecting(reason, "rejected") });
      await post(started.base, `Bearer ${secret}`);
      events.push(...started.events);
    }
    const tooLong = await start({ verifier: stubVerifier(), maxTokenBytes: 8 });
    await post(tooLong.base, `Bearer ${secret}`);
    events.push(...tooLong.events);
    expect(events).toHaveLength(5);
    expect(JSON.stringify(events)).not.toContain(secret);
  });

  it("still answers when onReject throws", async () => {
    const { base } = await start({
      verifier: stubVerifier(),
      onReject: () => {
        throw new Error("hook failed");
      },
    });
    expect((await post(base, "Bearer bad")).status).toBe(401);
  });
});

describe("bearerAuth: challengeScope", () => {
  it("throws at construction for a scope that is not an RFC 6750 scope-token", () => {
    expect(() => bearerAuth({ verifier: stubVerifier(), challengeScope: ["bad scope"] })).toThrow();
    expect(() => bearerAuth({ verifier: stubVerifier(), challengeScope: ['a"b'] })).toThrow();
    expect(() => bearerAuth({ verifier: stubVerifier(), challengeScope: ["a\\b"] })).toThrow();
    expect(() => bearerAuth({ verifier: stubVerifier(), challengeScope: [""] })).toThrow();
    expect(() => bearerAuth({ verifier: stubVerifier(), challengeScope: ["é"] })).toThrow();
  });

  it("adds scope to every 401, with or without an error", async () => {
    const { base } = await start({ verifier: stubVerifier(), challengeScope: ["openid", "email"] });
    const missing = await post(base);
    expect(missing.headers.get("www-authenticate")).toBe(
      `Bearer resource_metadata="${PRM_URL}", scope="openid email"`,
    );
    const rejected = await post(base, "Bearer bad");
    expect(rejected.status).toBe(401);
    expect(rejected.headers.get("www-authenticate")).toContain('scope="openid email"');
  });
});

describe("challenge", () => {
  it("builds a Bearer challenge from ordered params", () => {
    expect(challenge([])).toBe("Bearer");
    expect(
      challenge([
        ["error", "invalid_token"],
        ["resource_metadata", PRM_URL],
      ]),
    ).toBe(`Bearer error="invalid_token", resource_metadata="${PRM_URL}"`);
  });

  it("truncates error_description to 200 characters after sanitising", () => {
    const header = challenge([["error_description", `${"é".repeat(50)}${"x".repeat(300)}`]]);
    expect(header).toBe(`Bearer error_description="${"x".repeat(200)}"`);
  });
});

describe("errors", () => {
  it("maps reasons to statuses", () => {
    expect(statusFor("not_allowed")).toBe(403);
    expect(statusFor("issuer_unavailable")).toBe(503);
    for (const r of ["missing", "malformed", "invalid", "expired", "audience", "signature"] as Reason[]) {
      expect(statusFor(r)).toBe(401);
    }
  });

  it("reports the reason of a VerifyError and nothing else", () => {
    const err = new VerifyError("expired", "Token has expired");
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe("Token has expired");
    expect(reasonOf(err)).toBe("expired");
    expect(reasonOf(new Error("x"))).toBeUndefined();
    expect(reasonOf("expired")).toBeUndefined();
  });
});
