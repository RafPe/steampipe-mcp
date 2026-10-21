import type { RequestHandler } from "express";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { createRemoteJWKSet, customFetch, type JWTVerifyGetKey } from "jose";
import type { ServerConfig } from "../config.js";
import { auditAuthReject } from "../http/audit.js";
import type { ReadinessCheck } from "../http/ready.js";
import { bearerAuth, type RejectEvent } from "./bearer.js";
import { discoverJwks } from "./discovery.js";
import { VerifyError } from "./errors.js";
import { DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_MS, FetchRefused, guardedFetch, type FetchPolicy } from "./fetch-guard.js";
import { createGoogleVerifier, fetchGoogleMetadata, GOOGLE_ISSUER } from "./google.js";
import { createJwtVerifier, jwksBackoff, reloadOnUnusableKeys } from "./jwt.js";
import { prmPath, prmRouter, type PrmOptions } from "./prm.js";
import { createRetryLoader, type RetryLoaderOptions } from "./retry-loader.js";
import { createStaticTokenVerifier } from "./verifiers.js";

export interface AuthMiddleware {
  /** Public routes mounted at the app root (after Host/Origin checks). */
  rootRouters: RequestHandler[];
  /** Guards mounted on `POST {path}` only. */
  mcpMiddleware: RequestHandler[];
  /**
   * Checks for `GET /readyz`: one named `auth` in google and jwt mode, or
   * one `auth:<n>` per issuer (1-based config position, group
   * `jwt-issuers`) in jwt mode with degraded start.
   */
  readiness: ReadinessCheck[];
  /** Stop background work (the degraded-start discovery retries). */
  dispose(): void;
}

/** Test seams: tests never talk to Google. */
export interface AuthMiddlewareOptions {
  metadataFetcher?: (signal?: AbortSignal) => Promise<OAuthMetadata>;
  /** Retry schedule for degraded start (`sleep` above all). */
  discoveryRetry?: Omit<RetryLoaderOptions, "name">;
  tokeninfoUrl?: string;
  tokeninfoTimeoutMs?: number;
  /** Clock for JWT time checks and the JWKS backoff (ms). Default `Date.now`. */
  now?: () => number;
  onReject?: (e: RejectEvent) => void;
}

const JWKS_TIMEOUT_MS = 5000;

/** `error` with `label: ` before its message, keeping a `FetchRefused` one. */
function labelled(label: string, error: unknown): Error {
  const message = `${label}: ${error instanceof Error ? error.message : String(error)}`;
  return error instanceof FetchRefused ? new FetchRefused(error.cause_, message) : new Error(message);
}

/**
 * Build the auth layer for `cfg.auth.mode` (R15). In google mode this
 * fetches Google's discovery document up front and rejects if that fails,
 * so the server refuses to start when Google is unreachable or answers as
 * another issuer. jwt mode does the same with every configured issuer's
 * discovery document, each of which must name a `jwks_uri` that issuer's
 * fetch policy allows.
 *
 * With `cfg.auth.allowDegradedStart` in google mode, discovery instead runs
 * in the background through a retry loader: the PRM answers 503 with
 * `Retry-After` and the `auth` readiness check reports `pending` until it
 * succeeds. Bearer verification works throughout, since tokeninfo does not
 * depend on discovery.
 *
 * In jwt mode the flag gives every issuer its own retry loader instead.
 * Until an issuer's discovery succeeds, tokens routed to it get 503
 * (`issuer_unavailable`), it is left out of the PRM (503 while no
 * advertised issuer has resolved), and its `auth:<n>` readiness check (n is
 * the issuer's 1-based position in the config) reports `pending`. The other issuers are served meanwhile.
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
      throw new Error(
        "STEAMPIPE_MCP_PUBLIC_URL and STEAMPIPE_MCP_JWT_ISSUER or STEAMPIPE_MCP_JWT_ISSUERS are required when STEAMPIPE_MCP_AUTH_MODE=jwt",
      );
    }
    // Diagnostics name an issuer by position (as in `auth:<n>`) and origin,
    // never its full URL, whose path can carry a tenant ID.
    const label = (index: number) => `JWT issuer #${index + 1} (${new URL(jwt.issuers[index].issuer).origin})`;
    // Each issuer gets its own fetch policy, discovery and key set. Issuers
    // are operator-configured and trusted; anything an issuer's discovery
    // points at must be on that issuer's host or JWT_ALLOWED_HOSTS.
    const loadKeys = async (issuer: string, signal?: AbortSignal): Promise<JWTVerifyGetKey> => {
      const policy: FetchPolicy = {
        allowedHosts: [new URL(issuer).hostname, ...jwt.allowedHosts],
        insecureAuthorities: [],
        timeoutMs: DEFAULT_TIMEOUT_MS,
        maxBytes: DEFAULT_MAX_BYTES,
      };
      const fetchImpl = guardedFetch(policy);
      const discoveryFetch: typeof fetch = signal ? (input, init) => fetchImpl(input, { ...init, signal }) : fetchImpl;
      const { jwksUri } = await discoverJwks(issuer, discoveryFetch, policy);
      const gate = jwksBackoff(fetchImpl, new URL(issuer).origin, opts.now);
      const keySet = createRemoteJWKSet(jwksUri, {
        timeoutDuration: JWKS_TIMEOUT_MS,
        cooldownDuration: jwt.jwksCooldownS * 1000,
        [customFetch]: gate,
      });
      return reloadOnUnusableKeys(keySet, gate);
    };
    // Same canonical href for the PRM resource, the expected token
    // resource and the default audience (R12).
    const resource = publicUrl.href;
    const prm = (authorizationServers: string[]): PrmOptions => ({
      resource,
      authorizationServers,
      ...(jwt.scopesSupported.length > 0 && { scopesSupported: jwt.scopesSupported }),
      resourceName: "Steampipe MCP",
    });
    // Advertised issuers only, in config order (config guarantees one).
    const advertised = jwt.issuers.filter((i) => i.advertise).map((i) => i.issuer);

    let keys: Map<string, JWTVerifyGetKey>;
    let prmHandler: RequestHandler;
    let readiness: ReadinessCheck[];
    let dispose = () => {};
    if (auth.allowDegradedStart) {
      // One retry loader per issuer: an issuer that cannot be discovered
      // yet answers 503 and is left out of the PRM, without holding back
      // the others.
      const loaders = new Map(
        jwt.issuers.map(({ issuer }, index) => [
          issuer,
          createRetryLoader((signal) => loadKeys(issuer, signal), {
            ...opts.discoveryRetry,
            name: `${label(index)} discovery`,
          }),
        ]),
      );
      keys = new Map(
        [...loaders].map(([issuer, loader]) => [
          issuer,
          (header, token) => {
            const getKey = loader.current();
            if (!getKey) {
              throw new VerifyError("issuer_unavailable", "Token validation unavailable");
            }
            return getKey(header, token);
          },
        ]),
      );
      prmHandler = prmRouter(() => {
        const resolved = advertised.filter((issuer) => loaders.get(issuer)?.current());
        return resolved.length > 0 ? prm(resolved) : undefined;
      });
      // Named by 1-based config position, never by URL: /readyz is
      // unauthenticated and would otherwise reveal `advertise: false`
      // issuers (R22). One group, so a single ready issuer keeps the
      // pod ready (R28).
      readiness = [...loaders.values()].map((loader, index) => ({
        name: `auth:${index + 1}`,
        group: "jwt-issuers",
        check: async () => loader.status(),
      }));
      dispose = () => {
        for (const loader of loaders.values()) loader.dispose();
      };
    } else {
      keys = new Map(
        await Promise.all(
          jwt.issuers.map(async ({ issuer }, index) => {
            try {
              return [issuer, await loadKeys(issuer)] as const;
            } catch (error) {
              throw labelled(label(index), error);
            }
          }),
        ),
      );
      prmHandler = prmRouter(prm(advertised));
      // Every issuer's discovery already succeeded above.
      readiness = [{ name: "auth", check: async () => "ready" }];
    }
    const verifier = createJwtVerifier({ issuers: jwt.issuers, policy: cfg.policy, publicUrl, keys, now: opts.now });
    return {
      rootRouters: [prmHandler],
      mcpMiddleware: [
        bearerAuth({
          verifier,
          expectedResource: resource,
          resourceMetadataUrl: `${publicUrl.origin}${prmPath(resource)}`,
          challengeScope: jwt.challengeScope,
          onReject: opts.onReject ?? auditAuthReject,
        }),
      ],
      readiness,
      dispose,
    };
  }

  return { rootRouters: [], mcpMiddleware: [], readiness: [], dispose: () => {} };
}
