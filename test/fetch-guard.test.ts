import { afterEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  assertAllowedUrl,
  DEFAULT_MAX_BYTES,
  DEFAULT_TIMEOUT_MS,
  FetchRefused,
  GOOGLE_FETCH_POLICY,
  guardedFetch,
  type FetchPolicy,
  type FetchRefusedCause,
} from "../src/auth/fetch-guard.js";

// Every request here goes to an in-test node:http server on 127.0.0.1.
// Nothing reaches the real network.

const POLICY: FetchPolicy = {
  allowedHosts: [],
  insecureAuthorities: [],
  timeoutMs: DEFAULT_TIMEOUT_MS,
  maxBytes: DEFAULT_MAX_BYTES,
};

interface Fake {
  base: string;
  port: number;
  requests: string[];
  connections: () => number;
}

const servers: Server[] = [];

afterEach(async () => {
  for (const s of servers.splice(0)) {
    s.closeAllConnections();
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
});

async function fake(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<Fake> {
  const requests: string[] = [];
  let connections = 0;
  const server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    handler(req, res);
  });
  server.on("connection", () => connections++);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { base: `http://127.0.0.1:${port}`, port, requests, connections: () => connections };
}

async function expectRefused(p: Promise<unknown>, cause: FetchRefusedCause): Promise<void> {
  const err = await p.then(
    () => {
      throw new Error("expected the fetch to be refused");
    },
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(FetchRefused);
  expect((err as FetchRefused).cause_).toBe(cause);
}

function refusedSync(fn: () => void, cause: FetchRefusedCause): void {
  let err: unknown;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  expect(err).toBeInstanceOf(FetchRefused);
  expect((err as FetchRefused).cause_).toBe(cause);
}

describe("assertAllowedUrl", () => {
  const policy: FetchPolicy = {
    ...POLICY,
    allowedHosts: ["Idp.Example.com"],
    insecureAuthorities: ["Keycloak:8080", "plain-idp"],
  };
  const allowed = (u: string) => expect(() => assertAllowedUrl(new URL(u), policy)).not.toThrow();
  const refused = (u: string) => refusedSync(() => assertAllowedUrl(new URL(u), policy), "policy");

  it("allows https hosts on the allowlist, case-insensitively, on any path or port", () => {
    allowed("https://idp.example.com/.well-known/openid-configuration");
    allowed("https://IDP.EXAMPLE.COM/jwks");
    allowed("https://idp.example.com:8443/jwks");
  });

  it("refuses https hosts not on the allowlist, including look-alikes", () => {
    refused("https://evil.example.com/");
    refused("https://idp.example.com.evil.com/");
    refused("https://sub.idp.example.com/");
    refused("https://idp.example.com./");
  });

  it("allows http to loopback literals and localhost", () => {
    allowed("http://127.0.0.1:9000/x");
    allowed("http://127.10.20.30/x");
    allowed("http://[::1]:9000/x");
    allowed("http://localhost:9000/x");
    allowed("http://LOCALHOST/x");
  });

  it("refuses http to hosts that only look like loopback", () => {
    refused("http://127.0.0.1.evil.com/");
    refused("http://127.evil.com/");
    refused("http://localhost.evil.com/");
    refused("http://128.0.0.1/");
    refused("http://[::2]/");
  });

  it("does not extend the loopback exemption to https", () => {
    refused("https://127.0.0.1/");
    refused("https://localhost/");
  });

  it("allows http only for host:port pairs listed in insecureAuthorities", () => {
    allowed("http://keycloak:8080/realms/x");
    allowed("http://KEYCLOAK:8080/realms/x");
    refused("http://keycloak:8081/realms/x");
    refused("http://keycloak/realms/x");
    // An entry without a port means the http default, 80, on both sides.
    allowed("http://plain-idp/x");
    allowed("http://plain-idp:80/x");
    refused("http://plain-idp:8080/x");
  });

  it("does not let insecureAuthorities admit https or the allowlist admit http", () => {
    refused("https://keycloak:8080/");
    refused("http://idp.example.com/");
  });

  it("refuses every other scheme", () => {
    for (const u of ["ftp://idp.example.com/", "data:text/plain,hi", "blob:https://idp.example.com/x", "file:///etc/passwd", "ws://127.0.0.1/", "wss://idp.example.com/"]) {
      refused(u);
    }
  });

  it("never echoes the path or query of a refused URL", () => {
    let err: unknown;
    try {
      assertAllowedUrl(new URL("https://evil.example.com/p?access_token=secret-value"), policy);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(FetchRefused);
    expect((err as Error).message).toContain("evil.example.com");
    expect((err as Error).message).not.toContain("secret-value");
    expect((err as Error).message).not.toContain("access_token");
  });
});

describe("GOOGLE_FETCH_POLICY", () => {
  it("admits exactly the Google tokeninfo and discovery hosts with the default bounds", () => {
    expect(GOOGLE_FETCH_POLICY.allowedHosts).toEqual(["oauth2.googleapis.com", "accounts.google.com"]);
    expect(GOOGLE_FETCH_POLICY.insecureAuthorities).toEqual([]);
    expect(GOOGLE_FETCH_POLICY.timeoutMs).toBe(5000);
    expect(GOOGLE_FETCH_POLICY.maxBytes).toBe(65536);
    expect(() => assertAllowedUrl(new URL("https://oauth2.googleapis.com/tokeninfo"), GOOGLE_FETCH_POLICY)).not.toThrow();
    expect(() =>
      assertAllowedUrl(new URL("https://accounts.google.com/.well-known/openid-configuration"), GOOGLE_FETCH_POLICY),
    ).not.toThrow();
    refusedSync(() => assertAllowedUrl(new URL("https://www.googleapis.com/oauth2/v3/certs"), GOOGLE_FETCH_POLICY), "policy");
  });
});

describe("guardedFetch", () => {
  it("passes a loopback http request through and returns status, headers and body", async () => {
    const srv = await fake((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.writeHead(201, { "content-type": "application/json", "x-echo": req.method ?? "" });
        res.end(JSON.stringify({ got: body }));
      });
    });
    const res = await guardedFetch(POLICY)(`${srv.base}/tokeninfo`, {
      method: "POST",
      body: new URLSearchParams({ access_token: "t" }),
    });
    expect(res.status).toBe(201);
    expect(res.headers.get("x-echo")).toBe("POST");
    expect(await res.json()).toEqual({ got: "access_token=t" });
    expect(srv.requests).toEqual(["POST /tokeninfo"]);
  });

  it("accepts URL and Request inputs", async () => {
    const srv = await fake((_req, res) => res.end("ok"));
    const f = guardedFetch(POLICY);
    expect(await (await f(new URL(`${srv.base}/a`))).text()).toBe("ok");
    expect(await (await f(new Request(`${srv.base}/b`))).text()).toBe("ok");
    expect(srv.requests).toEqual(["GET /a", "GET /b"]);
  });

  it("refuses an https host not on the allowlist before opening any connection", async () => {
    const srv = await fake((_req, res) => res.end("should not be reached"));
    await expectRefused(guardedFetch(POLICY)(`https://127.0.0.1:${srv.port}/`), "policy");
    // Give a stray connection attempt time to land before counting.
    await new Promise((r) => setTimeout(r, 50));
    expect(srv.connections()).toBe(0);
    expect(srv.requests).toEqual([]);
  });

  it("refuses an http host that is neither loopback nor an insecure authority", async () => {
    await expectRefused(guardedFetch(POLICY)("http://idp.invalid/"), "policy");
  });

  it("refuses ftp:, data: and blob: before any I/O", async () => {
    const f = guardedFetch(POLICY);
    await expectRefused(f("ftp://127.0.0.1/file"), "policy");
    await expectRefused(f("data:application/json,{}"), "policy");
    const blobUrl = URL.createObjectURL(new Blob(["{}"]));
    try {
      await expectRefused(f(blobUrl), "policy");
    } finally {
      URL.revokeObjectURL(blobUrl);
    }
  });

  it("refuses a 302 and never follows it, even when the caller asks to follow", async () => {
    const target = await fake((_req, res) => res.end("{}"));
    const srv = await fake((_req, res) => {
      res.writeHead(302, { location: `${target.base}/elsewhere` });
      res.end();
    });
    await expectRefused(guardedFetch(POLICY)(`${srv.base}/`), "redirect");
    await expectRefused(guardedFetch(POLICY)(`${srv.base}/`, { redirect: "follow" }), "redirect");
    await expectRefused(guardedFetch(POLICY)(new Request(`${srv.base}/`, { redirect: "follow" })), "redirect");
    expect(target.requests).toEqual([]);
  });

  it("refuses every 3xx status, not only 302", async () => {
    const srv = await fake((req, res) => {
      res.writeHead(Number(req.url?.slice(1)), { location: "/x" });
      res.end();
    });
    for (const code of [300, 301, 303, 304, 307, 308]) {
      await expectRefused(guardedFetch(POLICY)(`${srv.base}/${code}`), "redirect");
    }
  });

  it("refuses a 70 000-byte body declared by Content-Length", async () => {
    const srv = await fake((_req, res) => {
      res.writeHead(200, { "content-length": "70000" });
      res.end("a".repeat(70_000));
    });
    await expectRefused(guardedFetch(POLICY)(`${srv.base}/`), "too_large");
  });

  it("refuses a 70 000-byte chunked body with no Content-Length", async () => {
    const srv = await fake((_req, res) => {
      res.writeHead(200);
      for (let i = 0; i < 7; i++) res.write("a".repeat(10_000));
      res.end();
    });
    await expectRefused(guardedFetch(POLICY)(`${srv.base}/`), "too_large");
  });

  it("accepts a body of exactly maxBytes and refuses one byte more", async () => {
    const srv = await fake((req, res) => {
      res.writeHead(200);
      res.end("a".repeat(Number(req.url?.slice(1))));
    });
    const res = await guardedFetch(POLICY)(`${srv.base}/65536`);
    expect((await res.text()).length).toBe(65536);
    await expectRefused(guardedFetch(POLICY)(`${srv.base}/65537`), "too_large");
  });

  it("refuses a body that is still trickling in after timeoutMs", async () => {
    const srv = await fake((_req, res) => {
      res.writeHead(200);
      res.write("{");
      // Never finishes; afterEach closes the socket.
    });
    const started = Date.now();
    await expectRefused(guardedFetch({ ...POLICY, timeoutMs: 200 })(`${srv.base}/`), "timeout");
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("refuses a server that never sends headers within timeoutMs", async () => {
    const srv = await fake(() => {
      // Never responds.
    });
    await expectRefused(guardedFetch({ ...POLICY, timeoutMs: 200 })(`${srv.base}/`), "timeout");
  });

  it("still honours a caller-supplied abort signal", async () => {
    const srv = await fake(() => {});
    const ctl = new AbortController();
    const p = guardedFetch(POLICY)(`${srv.base}/`, { signal: ctl.signal });
    setTimeout(() => ctl.abort(), 50);
    await expectRefused(p, "network");
  });

  it("maps a connection failure to network", async () => {
    const srv = await fake(() => {});
    const port = srv.port;
    const s = servers.pop()!;
    await new Promise<void>((resolve) => s.close(() => resolve()));
    await expectRefused(guardedFetch(POLICY)(`http://127.0.0.1:${port}/`), "network");
  });

  it("returns an empty body for 204 without throwing", async () => {
    const srv = await fake((_req, res) => {
      res.writeHead(204);
      res.end();
    });
    const res = await guardedFetch(POLICY)(`${srv.base}/`);
    expect(res.status).toBe(204);
    expect(await res.text()).toBe("");
  });
});
