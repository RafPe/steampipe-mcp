import type { RequestHandler } from "express";

/**
 * Reject any request whose `Origin` header is present and not exactly one of
 * `allowed`. A missing `Origin` passes: non-browser MCP clients never send
 * one, and a browser always does on the cross-origin POST a DNS-rebinding or
 * CSRF attack would need. `Origin: null` (sandboxed iframe, `file://`) is
 * just another value, so it is rejected unless the literal `null` is
 * allowlisted.
 */
export function originValidation(allowed: string[]): RequestHandler {
  const allowedSet = new Set(allowed);
  return (req, res, next) => {
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedSet.has(origin)) {
      res.status(403).json({ jsonrpc: "2.0", error: { code: -32000, message: "Forbidden origin" }, id: null });
      return;
    }
    next();
  };
}
