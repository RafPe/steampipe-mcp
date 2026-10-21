import type { RequestHandler } from "express";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { createRemoteJWKSet, customFetch } from "jose";
import type { ServerConfig } from "../config.js";
import { auditAuthReject } from "../http/audit.js";
import type { ReadinessCheck } from "../http/ready.js";
import { bearerAuth, type RejectEvent } from "./bearer.js";
import { discoverJwks } from "./discovery.js";
import { DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_MS, guardedFetch, type FetchPolicy } from "./fetch-guard.js";
import { createGoogleVerifier, fetchGoogleMetadata, GOOGLE_ISSUER } from "./google.js";
import { createJwtVerifier } from "./jwt.js";
import { prmPath, prmRouter, type PrmOptions } from "./prm.js";
import { createRetryLoader, type RetryLoaderOptions } from "./retry-loader.js";
import { createStaticTokenVerifier } from "./verifiers.js";

export interface AuthMiddleware {
  /** Public routes mounted at the app root (after Host/Origin checks). */
  rootRouters: RequestHandler[];
  /** Guards mounted on `POST {path}` only. */
  mcpMiddleware: RequestHandler[];
  /** Checks for `GET /readyz` (google mode: one named `auth`). */
  readiness: ReadinessCheck[];
  /** Stop background work (the degraded-start discovery retry). */
  dispose(): void;
}

/** Test seams: tests never talk to Google. */
export interface AuthMiddlewareOptions {
  metadataFetcher?: (signal?: AbortSignal) => Promise<OAuthMetadata>;
  /** Retry schedule for degraded start (`sleep` above all). */
  discoveryRetry?: Omit<RetryLoaderOptions, "name">;
  tokeninfoUrl?: string;
  tokeninfoTimeoutMs?: number;
  /** Clock for JWT time checks (ms). Default `Date.now`. */
  now?: () => number;
  onReject?: (e: RejectEvent) => void;
}

const JWKS_TIMEOUT_MS = 5000;

/**
 * Build the auth layer for `cfg.auth.mode` (R15). In google mode this
 * fetches Google's discovery document up front and rejects if that fails,
 * so the server refuses to start when Google is unreachable or answers as
 * another issuer. jwt mode does the same with the configured issuer's
 * discovery document, which must name a `jwks_uri` the fetch policy allows.
 *
 * With `cfg.auth.allowDegradedStart` in google mode, discovery instead runs
 * in the background through a retry loader: the PRM answers 503 with
 * `Retry-After` and the `auth` readiness check reports `pending` until it
 * succeeds. Bearer verification works throughout, since tokeninfo does not
 * depend on discovery.
 */
export async function authMiddleware(
  cfg: ServerConfig,
  opts: AuthMiddlewareOptions = {},
): Promise<AuthMiddleware> {
  const { auth } = cfg;

  if (auth.mode === "token") {
    if (!auth.token) {
      throw new Error("STEAMPIPE_MCP_AUTH_TOKEN is required when STEAMPIPE_MCP_AUTH_MODE=token");
    }
    return {
      rootRouters: [],
      mcpMiddleware: [
        bearerAuth({ verifier: createStaticTokenVerifier(auth.token), onReject: opts.onReject ?? auditAuthReject }),
      ],
      readiness: [],
      dispose: () => {},
    };
  }

  if (auth.mode === "google") {
    const publicUrl = cfg.http.publicUrl;
    if (!publicUrl || !auth.googleClientId) {
      throw new Error(
        "STEAMPIPE_MCP_PUBLIC_URL and STEAMPIPE_MCP_GOOGLE_CLIENT_ID are required when STEAMPIPE_MCP_AUTH_MODE=google",
      );
    }
    const fetchMetadata = opts.metadataFetcher ?? ((signal?: AbortSignal) => fetchGoogleMetadata(undefined, signal));
    // The PRM resource, the expected token resource and AuthInfo.resource
    // all use the same canonical href.
    const resource = publicUrl.href;
    const prm: PrmOptions = {
      resource,
      authorizationServers: [GOOGLE_ISSUER],
      scopesSupported: ["openid", "email"],
      resourceName: "Steampipe MCP",
    };
    const verifier = createGoogleVerifier({
      clientId: auth.googleClientId,
      allowedEmails: auth.allowedEmails,
      allowedDomains: auth.allowedDomains,
      publicUrl,
      policy: cfg.policy,
      tokeninfoUrl: opts.tokeninfoUrl,
      timeoutMs: opts.tokeninfoTimeoutMs,
    });
    let prmHandler: RequestHandler;
    let check: ReadinessCheck;
    let dispose = () => {};
    if (auth.allowDegradedStart) {
      const loader = createRetryLoader(fetchMetadata, { ...opts.discoveryRetry, name: "Google discovery" });
      prmHandler = prmRouter(() => (loader.current() ? prm : undefined));
      check = { name: "auth", check: async () => loader.status() };
      dispose = loader.dispose;
    } else {
      await fetchMetadata();
      prmHandler = prmRouter(prm);
      check = { name: "auth", check: async () => "ready" };
    }
    return {
      rootRouters: [prmHandler],
      mcpMiddleware: [
        bearerAuth({
          verifier,
          expectedResource: resource,
          resourceMetadataUrl: `${publicUrl.origin}${prmPath(resource)}`,
          challengeScope: ["openid", "email"],
          onReject: opts.onReject ?? auditAuthReject,
        }),
      ],
      readiness: [check],
      dispose,
    };
  }

  if (auth.mode === "jwt") {
    const publicUrl = cfg.http.publicUrl;
    const jwt = auth.jwt;
    if (!publicUrl || !jwt) {
      throw new Error("STEAMPIPE_MCP_PUBLIC_URL and STEAMPIPE_MCP_JWT_ISSUER are required when STEAMPIPE_MCP_AUTH_MODE=jwt");
    }
    // The issuer is operator-configured and trusted; anything discovery
    // points at must be on its host or JWT_ALLOWED_HOSTS.
    const policy: FetchPolicy = {
      allowedHosts: [new URL(jwt.issuer).hostname, ...jwt.allowedHosts],
      insecureAuthorities: [],
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxBytes: DEFAULT_MAX_BYTES,
    };
    const fetchImpl = guardedFetch(policy);
    const { jwksUri } = await discoverJwks(jwt.issuer, fetchImpl, policy);
    const keys = new Map([
      [
        jwt.issuer,
        createRemoteJWKSet(jwksUri, {
          timeoutDuration: JWKS_TIMEOUT_MS,
          cooldownDuration: jwt.jwksCooldownS * 1000,
          [customFetch]: fetchImpl,
        }),
      ],
    ]);
    const verifier = createJwtVerifier({
      issuers: [
        {
          issuer: jwt.issuer,
          audiences: jwt.audiences,
          algorithms: jwt.algorithms,
          acceptedTyp: jwt.acceptedTyp,
          clockSkewS: jwt.clockSkewS,
          maxTokenAgeS: jwt.maxTokenAgeS,
        },
      ],
      publicUrl,
      keys,
      now: opts.now,
    });
    // Same canonical href for the PRM resource, the expected token
    // resource and the default audience (R12).
    const resource = publicUrl.href;
    return {
      rootRouters: [
        prmRouter({
          resource,
          authorizationServers: [jwt.issuer],
          ...(jwt.scopesSupported.length > 0 && { scopesSupported: jwt.scopesSupported }),
          resourceName: "Steampipe MCP",
        }),
      ],
      mcpMiddleware: [
        bearerAuth({
          verifier,
          expectedResource: resource,
          resourceMetadataUrl: `${publicUrl.origin}${prmPath(resource)}`,
          challengeScope: jwt.challengeScope,
          onReject: opts.onReject ?? auditAuthReject,
        }),
      ],
      // Discovery already succeeded above; degraded start for jwt is T12.
      readiness: [{ name: "auth", check: async () => "ready" }],
      dispose: () => {},
    };
  }

  return { rootRouters: [], mcpMiddleware: [], readiness: [], dispose: () => {} };
}
