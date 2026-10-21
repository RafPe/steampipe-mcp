import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

// Supplied by the SDK's requireBearerAuth until src/auth/bearer.ts replaced it.
declare module "express-serve-static-core" {
  interface Request {
    /** The validated access token, set by `bearerAuth`. */
    auth?: AuthInfo;
  }
}
