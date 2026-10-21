import type { RequestHandler } from "express";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { ServerConfig } from "../config.js";
import { auditAuthReject } from "../http/audit.js";
import { bearerAuth } from "./bearer.js";
import { createGoogleVerifier, fetchGoogleMetadata } from "./google.js";
import { createStaticTokenVerifier } from "./verifiers.js";

export interface AuthMiddleware {
  /** Public routes mounted at the app root (after Host/Origin checks). */
  rootRouters: RequestHandler[];
  /** Guards mounted on `POST {path}` only. */
  mcpMiddleware: RequestHandler[];
}

/** Test seams: tests never talk to Google. */
export interface AuthMiddlewareOptions {
  metadataFetcher?: () => Promise<OAuthMetadata>;
  tokeninfoUrl?: string;
  tokeninfoTimeoutMs?: number;
}

/**
 * Build the auth layer for `cfg.auth.mode` (R15). In google mode this
 * fetches Google's metadata up front and rejects if that fails, so the
 * server refuses to start rather than serve without a working PRM.
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
      mcpMiddleware: [bearerAuth({ verifier: createStaticTokenVerifier(auth.token), onReject: auditAuthReject })],
    };
  }

  if (auth.mode === "google") {
    const publicUrl = cfg.http.publicUrl;
    if (!publicUrl || !auth.googleClientId) {
      throw new Error(
        "STEAMPIPE_MCP_PUBLIC_URL and STEAMPIPE_MCP_GOOGLE_CLIENT_ID are required when STEAMPIPE_MCP_AUTH_MODE=google",
      );
    }
    const oauthMetadata = await (opts.metadataFetcher ?? fetchGoogleMetadata)();
    const verifier = createGoogleVerifier({
      clientId: auth.googleClientId,
      allowedEmails: auth.allowedEmails,
      allowedDomains: auth.allowedDomains,
      publicUrl,
      tokeninfoUrl: opts.tokeninfoUrl,
      timeoutMs: opts.tokeninfoTimeoutMs,
    });
    return {
      rootRouters: [
        mcpAuthMetadataRouter({
          oauthMetadata,
          resourceServerUrl: publicUrl,
          scopesSupported: ["openid", "email"],
          resourceName: "Steampipe MCP",
        }),
      ],
      mcpMiddleware: [
        bearerAuth({
          verifier,
          expectedResource: publicUrl.href,
          resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(publicUrl),
          challengeScope: ["openid", "email"],
          onReject: auditAuthReject,
        }),
      ],
    };
  }

  return { rootRouters: [], mcpMiddleware: [] };
}
