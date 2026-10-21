import type { RequestHandler } from "express";

export interface PrmOptions {
  resource: string;
  authorizationServers: string[];
  scopesSupported?: string[];
  resourceName?: string;
}

const WELL_KNOWN = "/.well-known/oauth-protected-resource";
const ALLOW = "GET, HEAD";
const RETRY_AFTER_SECONDS = "5";

/**
 * RFC 9728 §3.1 path insertion: the well-known segment goes between the
 * host and the resource's path, so `https://h/mcp` is served at
 * `/.well-known/oauth-protected-resource/mcp` and `https://h` at
 * `/.well-known/oauth-protected-resource`.
 */
export function prmPath(resource: string): string {
  const path = new URL(resource).pathname;
  return path === "/" ? WELL_KNOWN : `${WELL_KNOWN}${path}`;
}

function assertHasAuthorizationServer(o: PrmOptions): void {
  if (o.authorizationServers.length === 0) {
    throw new Error("Protected Resource Metadata needs at least one authorization server");
  }
}

// Field order is the wire order. `resource` and the authorization servers
// are emitted exactly as given: a round trip through URL would append "/"
// to https://accounts.google.com, which is then no longer Google's issuer.
function document(o: PrmOptions): Record<string, unknown> {
  return {
    resource: o.resource,
    authorization_servers: [...o.authorizationServers],
    ...(o.scopesSupported && { scopes_supported: [...o.scopesSupported] }),
    bearer_methods_supported: ["header"],
    ...(o.resourceName !== undefined && { resource_name: o.resourceName }),
  };
}

function isUnderWellKnown(path: string): boolean {
  return path === WELL_KNOWN || path.startsWith(`${WELL_KNOWN}/`);
}

/**
 * Serve RFC 9728 Protected Resource Metadata at `prmPath(resource)`
 * (replaces the SDK's `mcpAuthMetadataRouter`, which also mirrored the
 * authorization server's own metadata; clients fetch that from the server
 * named in `authorization_servers`). GET and HEAD only, everything else on
 * the path is 405; any other path is passed on.
 *
 * Given options, an empty `authorizationServers` throws here. Given a
 * thunk, it is called on every request; while it returns `undefined` (or
 * options with no authorization server), GET and HEAD on any path under
 * `/.well-known/oauth-protected-resource` answer 503 with `Retry-After`,
 * since the resource path is not known yet; other methods there still get
 * 405.
 */
export function prmRouter(o: PrmOptions | (() => PrmOptions | undefined)): RequestHandler {
  if (typeof o !== "function") {
    assertHasAuthorizationServer(o);
  }
  const fixed = typeof o === "function" ? undefined : { path: prmPath(o.resource), body: document(o) };

  return (req, res, next) => {
    let target = fixed;
    if (typeof o === "function") {
      const current = o();
      if (current && current.authorizationServers.length > 0) {
        target = { path: prmPath(current.resource), body: document(current) };
      }
    }
    // While a thunk is pending the exact path is unknown, so the whole
    // well-known prefix stands in for it.
    if (target ? req.path !== target.path : !isUnderWellKnown(req.path)) {
      next();
      return;
    }
    // The method restriction holds whether or not metadata is pending.
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.status(405).set("Allow", ALLOW).json({ error: "method_not_allowed" });
      return;
    }
    if (!target) {
      res.status(503).set({ "Retry-After": RETRY_AFTER_SECONDS, "Cache-Control": "no-store" });
      res.json({ error: "temporarily_unavailable" });
      return;
    }
    // Readable cross-origin by web-based MCP clients, as the SDK router was.
    res.status(200).set({ "Cache-Control": "max-age=300", "Access-Control-Allow-Origin": "*" });
    res.json(target.body);
  };
}
