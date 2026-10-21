import { isIPv4 } from "node:net";

/**
 * Restricted, bounded `fetch` for identity-provider traffic (tokeninfo,
 * OIDC discovery, JWKS).
 *
 * Threat model:
 * - Issuer URLs are operator-configured, so they are trusted. Their hosts
 *   go into `allowedHosts` (or, for plain-http test/dev IdPs,
 *   `insecureAuthorities`).
 * - URLs that come out of discovery documents (e.g. `jwks_uri`) are not
 *   trusted. A compromised or spoofed discovery document must not be able to
 *   point the server at an arbitrary host or scheme, bounce it through a
 *   redirect, hang it, or make it buffer an unbounded body.
 *
 * Rules, all enforced per request:
 * - `https:` is allowed only when the URL's hostname is in `allowedHosts`
 *   (exact, case-insensitive; no subdomain or trailing-dot matching).
 * - `http:` is allowed only to a loopback literal (127.0.0.0/8, `[::1]`) or
 *   `localhost`, or when its `host:port` (port defaulting to 80) is in
 *   `insecureAuthorities`.
 * - Every other scheme (`ftp:`, `data:`, `blob:`, `file:`, ...) is refused.
 * - Policy refusals happen before any I/O: no DNS lookup, no connection.
 * - Redirects are never followed; any 3xx response is refused.
 * - The whole exchange, headers and body, is bounded by `timeoutMs`.
 * - The body is read through a byte counter and refused past `maxBytes`.
 *
 * Every refusal throws `FetchRefused`; callers map it to their own
 * "issuer unavailable" error. Messages name at most the scheme and host,
 * never the path or query, so tokens in URLs cannot leak into logs.
 *
 * Non-goals: this is transport restriction for identity-provider traffic,
 * not general SSRF protection. Hostnames are not resolved and checked
 * against private address ranges; an allowlisted name that resolves to an
 * internal address is reached. Hand-rolled IP filtering is deliberately
 * avoided.
 */
export interface FetchPolicy {
  allowedHosts: string[];
  insecureAuthorities: string[];
  timeoutMs: number;
  maxBytes: number;
}

export type FetchRefusedCause = "policy" | "redirect" | "timeout" | "too_large" | "network";

export class FetchRefused extends Error {
  constructor(
    readonly cause_: FetchRefusedCause,
    message: string,
  ) {
    super(message);
    this.name = "FetchRefused";
  }
}

export const DEFAULT_TIMEOUT_MS = 5000;
export const DEFAULT_MAX_BYTES = 65536;

export const GOOGLE_FETCH_POLICY: FetchPolicy = {
  allowedHosts: ["oauth2.googleapis.com", "accounts.google.com"],
  insecureAuthorities: [],
  timeoutMs: DEFAULT_TIMEOUT_MS,
  maxBytes: DEFAULT_MAX_BYTES,
};

// Responses with these statuses must be built with a null body.
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);

function isLoopback(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "[::1]") return true;
  return isIPv4(hostname) && hostname.startsWith("127.");
}

// `host:port` with the http default port filled in, lowercased. URL drops
// the default port, so both the request URL and policy entries go through
// this before comparison.
function httpAuthority(hostname: string, port: string): string {
  return `${hostname.toLowerCase()}:${port || "80"}`;
}

function normaliseAuthority(entry: string): string | undefined {
  try {
    const u = new URL(`http://${entry}`);
    return httpAuthority(u.hostname, u.port);
  } catch {
    return undefined;
  }
}

/**
 * Throws `FetchRefused("policy")` unless `url` is allowed by `policy`. Used
 * per request by `guardedFetch` and at startup to validate configured URLs.
 */
export function assertAllowedUrl(url: URL, policy: FetchPolicy): void {
  const hostname = url.hostname.toLowerCase();
  if (url.protocol === "https:") {
    if (policy.allowedHosts.some((h) => h.toLowerCase() === hostname)) return;
    throw new FetchRefused("policy", `https host ${hostname} is not in the allowed identity-provider hosts`);
  }
  if (url.protocol === "http:") {
    if (isLoopback(hostname)) return;
    const authority = httpAuthority(hostname, url.port);
    if (policy.insecureAuthorities.some((a) => normaliseAuthority(a) === authority)) return;
    throw new FetchRefused("policy", `plain http to ${authority} is not allowed`);
  }
  throw new FetchRefused("policy", `scheme ${url.protocol} is not allowed`);
}

function requestUrl(input: string | URL | Request): URL {
  if (input instanceof Request) return new URL(input.url);
  try {
    return new URL(input);
  } catch {
    throw new FetchRefused("policy", "request URL is not a valid absolute URL");
  }
}

function tooLarge(maxBytes: number): FetchRefused {
  return new FetchRefused("too_large", `response body exceeds ${maxBytes} bytes`);
}

async function readBounded(res: Response, maxBytes: number): Promise<Uint8Array | null> {
  if (!res.body) return null;
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body.cancel().catch(() => {});
    throw tooLarge(maxBytes);
  }
  // Content-Length is only an early exit: it may be absent or describe the
  // encoded body. The counter over the decoded stream is authoritative.
  const out = new Uint8Array(maxBytes);
  let length = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (length + value.byteLength > maxBytes) {
      await reader.cancel().catch(() => {});
      throw tooLarge(maxBytes);
    }
    out.set(value, length);
    length += value.byteLength;
  }
  return out.subarray(0, length);
}

// `AbortSignal.any` only exists from Node 20.3; engines allows 20.0. The
// fallback aborts one controller from whichever input fires first, and
// `release` detaches its listeners once the request settles.
function anySignal(signals: AbortSignal[]): { signal: AbortSignal; release: () => void } {
  if (typeof AbortSignal.any === "function") {
    return { signal: AbortSignal.any(signals), release: () => {} };
  }
  const controller = new AbortController();
  const listeners: Array<[AbortSignal, () => void]> = [];
  const release = () => {
    for (const [s, l] of listeners) s.removeEventListener("abort", l);
  };
  for (const s of signals) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    const l = () => {
      controller.abort(s.reason);
      release();
    };
    s.addEventListener("abort", l, { once: true });
    listeners.push([s, l]);
  }
  if (controller.signal.aborted) release();
  return { signal: controller.signal, release };
}

/**
 * Returns a `fetch` that enforces `policy` (see the module comment). The
 * returned Response has its body fully buffered (at most `maxBytes`), so
 * callers read it without any further network I/O.
 */
export function guardedFetch(policy: FetchPolicy): typeof fetch {
  return async (input, init) => {
    const url = requestUrl(input);
    assertAllowedUrl(url, policy);

    const timeout = AbortSignal.timeout(policy.timeoutMs);
    const callerSignal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
    const { signal, release } = callerSignal
      ? anySignal([callerSignal, timeout])
      : { signal: timeout, release: () => {} };
    const where = `${url.protocol}//${url.host}`;

    try {
      // Spread init first so neither a caller's nor a Request's redirect
      // mode or signal can override the guard's.
      const res = await fetch(input, { ...init, redirect: "manual", signal });
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => {});
        throw new FetchRefused("redirect", `redirect from ${where} refused`);
      }
      const body = await readBounded(res, policy.maxBytes);
      return new Response(NULL_BODY_STATUSES.has(res.status) ? null : body, {
        status: res.status,
        statusText: res.statusText,
        headers: res.headers,
      });
    } catch (error) {
      if (error instanceof FetchRefused) throw error;
      if (timeout.aborted) {
        throw new FetchRefused("timeout", `request to ${where} exceeded ${policy.timeoutMs}ms`);
      }
      throw new FetchRefused("network", `request to ${where} failed`);
    } finally {
      release();
    }
  };
}
