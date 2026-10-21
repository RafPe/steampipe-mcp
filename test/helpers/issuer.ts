import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createPublicKey, randomUUID, type KeyObject } from "node:crypto";
import { CompactSign, exportJWK, generateKeyPair, type JWK } from "jose";

export interface TestIssuerOptions {
  alg?: "RS256" | "ES256";
  /** Issuer path, e.g. "/t1" for a tenant issuer. Default: none (bare origin). */
  path?: string;
  /** Which well-known documents are served. Default "both". */
  discovery?: "both" | "oidc" | "oauth";
  /** `issuer` written into the discovery document, or a function of the real one. Default: the real issuer. */
  discoveryIssuer?: string | ((issuer: string) => string);
  /** `jwks_uri` written into the discovery document. Default: this server's /jwks. */
  jwksUri?: string;
}

export interface SignOptions {
  kid?: string;
  alg?: string;
  /** Header `typ`. Default "at+jwt"; `null` leaves it out. */
  typ?: string | null;
  key?: CryptoKey | KeyObject | Uint8Array;
}

export interface TestIssuer {
  issuer: string;
  /** Current signing key id. */
  kid(): string;
  /** The current public key as published in the JWKS (with kid, alg and use). */
  publicJwk(): JWK;
  /** PEM (SPKI) of the current public key, for algorithm-confusion tests. */
  publicKeyPem(): Promise<string>;
  /**
   * Sign `claims` as a compact JWS. Defaults fill `iat` (real clock),
   * `jti` and `client_id`; a claim given as `undefined` is left out.
   */
  sign(claims: Record<string, unknown>, o?: SignOptions): Promise<string>;
  /** Add a new signing key (published alongside the old ones) and return its kid. */
  rotate(): Promise<string>;
  jwksRequests(): number;
  /** Every request path the server has seen, in order. */
  requests(): string[];
  setDiscoveryFailing(on: boolean): void;
  /** `true` drops the connection; a number answers with that HTTP status. */
  setJwksFailing(on: boolean | number): void;
  /** Serve `{"keys": keys}` at /jwks instead of the real keys; `undefined` restores them. */
  setJwksKeys(keys: object[] | undefined): void;
  close(): Promise<void>;
}

interface Key {
  kid: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  jwk: JWK;
}

/**
 * A plain-http OAuth/OIDC issuer on 127.0.0.1 for JWT tests: serves the
 * discovery documents (OIDC appended path and RFC 8414 inserted path), a
 * JWKS at /jwks, and signs tokens with its keys.
 */
export async function startTestIssuer(opts: TestIssuerOptions = {}): Promise<TestIssuer> {
  const alg = opts.alg ?? "RS256";
  const path = opts.path ?? "";
  const discovery = opts.discovery ?? "both";
  const keys: Key[] = [];
  const seen: string[] = [];
  let jwksCount = 0;
  let discoveryFailing = false;
  let jwksFailing: boolean | number = false;
  let jwksKeys: object[] | undefined;

  async function newKey(): Promise<Key> {
    const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
    const kid = randomUUID();
    const jwk = { ...(await exportJWK(publicKey)), kid, alg, use: "sig" };
    const key = { kid, privateKey, publicKey, jwk };
    keys.push(key);
    return key;
  }
  let current = await newKey();

  let issuer = "";
  const server: Server = createServer((req, res) => {
    const url = req.url ?? "";
    seen.push(url);
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const oidcPath = `${path}/.well-known/openid-configuration`;
    const oauthPath = `/.well-known/oauth-authorization-server${path}`;
    const isOidc = url === oidcPath && discovery !== "oauth";
    const isOauth = url === oauthPath && discovery !== "oidc";
    if (isOidc || isOauth) {
      if (discoveryFailing) {
        json(500, { error: "unavailable" });
        return;
      }
      json(200, {
        issuer: typeof opts.discoveryIssuer === "function" ? opts.discoveryIssuer(issuer) : (opts.discoveryIssuer ?? issuer),
        jwks_uri: opts.jwksUri ?? `${origin}/jwks`,
      });
      return;
    }
    if (url === "/jwks") {
      jwksCount++;
      if (jwksFailing === true) {
        req.socket.destroy();
        return;
      }
      if (typeof jwksFailing === "number") {
        json(jwksFailing, { error: "unavailable" });
        return;
      }
      json(200, { keys: jwksKeys ?? keys.map((k) => k.jwk) });
      return;
    }
    json(404, { error: "not_found" });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  issuer = `${origin}${path}`;

  return {
    issuer,
    kid: () => current.kid,
    publicJwk: () => ({ ...current.jwk }),
    async publicKeyPem() {
      return createPublicKey({ key: current.jwk as never, format: "jwk" })
        .export({ type: "spki", format: "pem" })
        .toString();
    },
    async sign(claims, o = {}) {
      const payload: Record<string, unknown> = {
        iat: Math.floor(Date.now() / 1000),
        jti: randomUUID(),
        client_id: "test-client",
        ...claims,
      };
      for (const [k, v] of Object.entries(payload)) {
        if (v === undefined) delete payload[k];
      }
      const header: Record<string, unknown> = { alg: o.alg ?? alg, kid: o.kid ?? current.kid };
      const typ = o.typ === undefined ? "at+jwt" : o.typ;
      if (typ !== null) header.typ = typ;
      return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader(header as { alg: string })
        .sign(o.key ?? current.privateKey);
    },
    async rotate() {
      current = await newKey();
      return current.kid;
    },
    jwksRequests: () => jwksCount,
    requests: () => [...seen],
    setDiscoveryFailing(on) {
      discoveryFailing = on;
    },
    setJwksFailing(on) {
      jwksFailing = on;
    },
    setJwksKeys(k) {
      jwksKeys = k;
    },
    async close() {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
