import { assertAllowedUrl, FetchRefused, type FetchPolicy } from "./fetch-guard.js";

export interface JwksDiscovery {
  issuer: string;
  jwksUri: URL;
}

/**
 * The two well-known locations for an issuer's metadata, in the order tried:
 *
 * - OpenID Connect Discovery §4: the suffix is appended to the issuer, after
 *   removing one trailing "/".
 * - RFC 8414 §3: the suffix is inserted between the host and the issuer's
 *   path, so `https://h/tenant` becomes
 *   `https://h/.well-known/oauth-authorization-server/tenant`.
 */
function discoveryUrls(issuer: string): URL[] {
  const url = new URL(issuer);
  const path = url.pathname.replace(/\/$/, "");
  return [
    new URL(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`),
    new URL(`${url.origin}/.well-known/oauth-authorization-server${path}`),
  ];
}

async function fetchDocument(url: URL, fetchImpl: typeof fetch): Promise<Record<string, unknown>> {
  const where = `${url.origin}${url.pathname}`;
  const res = await fetchImpl(url, { headers: { Accept: "application/json" } });
  if (res.status !== 200) {
    throw new Error(`${where} answered ${res.status}`);
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new Error(`${where} did not return JSON`);
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new Error(`${where} did not return a JSON object`);
  }
  return body as Record<string, unknown>;
}

/**
 * Find the JWKS for `issuer` from its OIDC or RFC 8414 metadata, trying
 * both locations in order (see `discoveryUrls`). A document is used only
 * when its `issuer` equals the configured string exactly; only `issuer` and
 * `jwks_uri` are read, so M2M issuers without interactive endpoints work.
 *
 * `jwks_uri` comes from the network and is untrusted: it must parse, use
 * https unless the configured issuer is itself plain http (R15: config only
 * allows that on loopback, and the fetch policy admits any loopback http, so
 * without this an https issuer could point its keys at
 * `http://127.0.0.1:…`), and pass `policy`. Otherwise this throws
 * (`FetchRefused` for a scheme or policy refusal) before anything is
 * fetched from it.
 */
export async function discoverJwks(
  issuer: string,
  fetchImpl: typeof fetch,
  policy: FetchPolicy,
): Promise<JwksDiscovery> {
  const failures: string[] = [];
  let doc: Record<string, unknown> | undefined;
  for (const url of discoveryUrls(issuer)) {
    try {
      const candidate = await fetchDocument(url, fetchImpl);
      if (candidate.issuer !== issuer) {
        failures.push(`${url.origin}${url.pathname} names a different issuer`);
        continue;
      }
      doc = candidate;
      break;
    } catch (error) {
      failures.push(error instanceof Error ? error.message : "unknown error");
    }
  }
  if (!doc) {
    throw new Error(`Issuer discovery failed: ${failures.join("; ")}`);
  }

  if (typeof doc.jwks_uri !== "string") {
    throw new Error("Issuer discovery document has no jwks_uri");
  }
  let jwksUri: URL;
  try {
    jwksUri = new URL(doc.jwks_uri);
  } catch {
    throw new Error("Issuer discovery document has an invalid jwks_uri");
  }
  if (jwksUri.protocol !== "https:" && new URL(issuer).protocol === "https:") {
    throw new FetchRefused("policy", "jwks_uri must use https for an https issuer");
  }
  assertAllowedUrl(jwksUri, policy);
  return { issuer, jwksUri };
}
