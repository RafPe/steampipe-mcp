import { afterEach, describe, expect, it } from "vitest";
import express, { type RequestHandler } from "express";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { prmPath, prmRouter, type PrmOptions } from "../src/auth/prm.js";

let servers: HttpServer[] = [];

afterEach(async () => {
  for (const s of servers) s.closeAllConnections();
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  servers = [];
});

async function start(router: RequestHandler): Promise<number> {
  const app = express();
  app.use(router);
  const server = await new Promise<HttpServer>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function send(port: number, method: string, path: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method, path }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

const GOOGLE: PrmOptions = {
  resource: "https://mcp.example.com/mcp",
  authorizationServers: ["https://accounts.google.com"],
  scopesSupported: ["openid", "email"],
  resourceName: "Steampipe MCP",
};
const PATH = "/.well-known/oauth-protected-resource/mcp";

describe("prmPath", () => {
  it("inserts the well-known segment between host and path (RFC 9728 §3.1)", () => {
    expect(prmPath("https://h/mcp")).toBe("/.well-known/oauth-protected-resource/mcp");
  });

  it("uses the bare well-known path for a resource with no path", () => {
    expect(prmPath("https://h")).toBe("/.well-known/oauth-protected-resource");
    expect(prmPath("https://h/")).toBe("/.well-known/oauth-protected-resource");
  });

  it("keeps a multi-segment path", () => {
    expect(prmPath("https://h:8443/tenant/a/mcp")).toBe("/.well-known/oauth-protected-resource/tenant/a/mcp");
  });
});

describe("prmRouter", () => {
  it("serves the document byte-exact, with header bearer method and a 5-minute cache", async () => {
    const port = await start(prmRouter(GOOGLE));
    const res = await send(port, "GET", PATH);
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^application\/json/);
    expect(res.headers["cache-control"]).toBe("max-age=300");
    expect(res.headers["access-control-allow-origin"]).toBe("*");
    expect(res.body).toBe(
      '{"resource":"https://mcp.example.com/mcp",' +
        '"authorization_servers":["https://accounts.google.com"],' +
        '"scopes_supported":["openid","email"],' +
        '"bearer_methods_supported":["header"],' +
        '"resource_name":"Steampipe MCP"}',
    );
  });

  it("keeps resource and authorization servers as exact strings, never normalised through URL", async () => {
    // URL would append "/" to both and lowercase the host.
    const port = await start(prmRouter({ resource: "https://MCP.example.com", authorizationServers: ["https://Issuer.example"] }));
    const res = await send(port, "GET", "/.well-known/oauth-protected-resource");
    expect(res.status).toBe(200);
    expect(res.body).toBe(
      '{"resource":"https://MCP.example.com",' +
        '"authorization_servers":["https://Issuer.example"],' +
        '"bearer_methods_supported":["header"]}',
    );
  });

  it("lists two authorization servers in the given order", async () => {
    const port = await start(prmRouter({ ...GOOGLE, authorizationServers: ["https://b.example", "https://a.example"] }));
    const res = await send(port, "GET", PATH);
    expect(JSON.parse(res.body).authorization_servers).toEqual(["https://b.example", "https://a.example"]);
  });

  it("omits scopes_supported and resource_name when not given", async () => {
    const port = await start(prmRouter({ resource: GOOGLE.resource, authorizationServers: GOOGLE.authorizationServers }));
    const doc = JSON.parse((await send(port, "GET", PATH)).body);
    expect(Object.keys(doc)).toEqual(["resource", "authorization_servers", "bearer_methods_supported"]);
  });

  it("refuses an empty authorization server list at construction", () => {
    expect(() => prmRouter({ ...GOOGLE, authorizationServers: [] })).toThrow(/authorization server/);
  });

  it("answers HEAD with 200, the same headers and no body", async () => {
    const port = await start(prmRouter(GOOGLE));
    const res = await send(port, "HEAD", PATH);
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("max-age=300");
    expect(res.headers["content-type"]).toMatch(/^application\/json/);
    expect(res.body).toBe("");
  });

  for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
    it(`answers ${method} with 405 and Allow: GET, HEAD`, async () => {
      const port = await start(prmRouter(GOOGLE));
      const res = await send(port, method, PATH);
      expect(res.status).toBe(405);
      expect(res.headers.allow).toBe("GET, HEAD");
    });
  }

  it("passes other paths through, including the dropped authorization-server mirror", async () => {
    const port = await start(prmRouter(GOOGLE));
    expect((await send(port, "GET", "/.well-known/oauth-authorization-server")).status).toBe(404);
    expect((await send(port, "GET", "/.well-known/oauth-protected-resource")).status).toBe(404);
    expect((await send(port, "GET", `${PATH}/extra`)).status).toBe(404);
  });

  it("evaluates a thunk on every request: 503 with Retry-After while undefined, then 200", async () => {
    let current: PrmOptions | undefined;
    const port = await start(prmRouter(() => current));
    const pending = await send(port, "GET", PATH);
    expect(pending.status).toBe(503);
    expect(pending.headers["retry-after"]).toBe("5");
    expect(pending.headers["cache-control"]).toBe("no-store");
    expect(JSON.parse(pending.body)).toEqual({ error: "temporarily_unavailable" });

    current = GOOGLE;
    const ready = await send(port, "GET", PATH);
    expect(ready.status).toBe(200);
    expect(JSON.parse(ready.body).authorization_servers).toEqual(["https://accounts.google.com"]);
  });

  describe("while a thunk is pending, the method restriction still comes first", () => {
    for (const [name, thunk] of [
      ["undefined", () => undefined],
      ["no authorization server", () => ({ ...GOOGLE, authorizationServers: [] })],
    ] as Array<[string, () => PrmOptions | undefined]>) {
      for (const method of ["OPTIONS", "POST"]) {
        it(`answers ${method} with 405 and Allow: GET, HEAD (${name})`, async () => {
          const port = await start(prmRouter(thunk));
          const res = await send(port, method, PATH);
          expect(res.status).toBe(405);
          expect(res.headers.allow).toBe("GET, HEAD");
          expect(res.headers["retry-after"]).toBeUndefined();
        });
      }

      it(`answers GET with 503 and Retry-After (${name})`, async () => {
        const port = await start(prmRouter(thunk));
        const res = await send(port, "GET", PATH);
        expect(res.status).toBe(503);
        expect(res.headers["retry-after"]).toBe("5");
        expect(res.headers.allow).toBeUndefined();
      });

      it(`answers HEAD with 503 and Retry-After (${name})`, async () => {
        const port = await start(prmRouter(thunk));
        const res = await send(port, "HEAD", PATH);
        expect(res.status).toBe(503);
        expect(res.headers["retry-after"]).toBe("5");
        expect(res.body).toBe("");
      });
    }
  });

  it("answers 503 when a thunk returns options with no authorization server", async () => {
    const port = await start(prmRouter(() => ({ ...GOOGLE, authorizationServers: [] })));
    const res = await send(port, "GET", PATH);
    expect(res.status).toBe(503);
  });
});
