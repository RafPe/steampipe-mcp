## Unreleased

_What's new_

* `STEAMPIPE_MCP_AUTH_MODE=jwt`: accept RFC 9068 JWT access tokens from one OAuth/OIDC issuer (`STEAMPIPE_MCP_JWT_ISSUER`), verified locally against the issuer's JWKS. At startup the server discovers the JWKS from the issuer's OIDC or RFC 8414 metadata (the document's `issuer` must match exactly, and `jwks_uri` must use https, unless the issuer itself is loopback http, and be on the issuer's host or `STEAMPIPE_MCP_JWT_ALLOWED_HOSTS`) and refuses to start if that fails. Tokens must carry `typ: at+jwt` (configurable with `STEAMPIPE_MCP_JWT_ACCEPTED_TYP`), an allowed asymmetric `alg` (`none` and `HS*` are refused at startup), the exact issuer, an accepted audience (default: `PUBLIC_URL`), and the RFC 9068 claims `exp`, `iat`, `jti`, `client_id` and `sub`. Clock skew (default 0), maximum token age (default off) and the JWKS refetch cooldown (default 30 s) are configurable. A JWKS outage answers `503` with `Retry-After: 5`. The PRM document names the issuer as the authorization server.

_Behaviour changes_

* The per-principal rate limit keys on the token's issuer-qualified principal (`iss|sub`) when one is present (jwt mode), so the same `sub` from two issuers never shares a quota. Token and Google mode still key on `sub`.
* The audit line gains an `iss` field when the principal has an issuer (jwt mode), bounded like the other token-derived fields.
* Rejected auth attempts (`auth_reject` audit lines) are now also written in `jwt` mode.

## 0.3.1 [2026-10-21]

_Fixes_

* The multi-arch Docker image builds again. Node no longer runs under QEMU emulation during the build: the TypeScript build and the production `npm ci` run on the build host's own platform, and the per-architecture runtime stage only upgrades Alpine packages, removes npm/corepack/yarn and copies the result in. The build now fails if a production dependency ever gains an install script, a gyp file or a `cpu`/`os`/`libc` restriction, since that output would no longer be the same on every architecture. The release workflow pins the QEMU image (`tonistiigi/binfmt:qemu-v10.0.4`) instead of using `latest`, and CI builds `linux/amd64` and `linux/arm64` on every push and pull request. 0.3.0 was tagged but never published: the release workflow's `linux/arm64` build failed with `SIGILL` (exit 132) while running `npm ci` under QEMU.

## 0.3.0 [2026-10-21]

_What's new_

* Declarative identity policy (`STEAMPIPE_MCP_REQUIRED_CLAIMS`, `STEAMPIPE_MCP_ALLOWED_SUBJECTS`, `STEAMPIPE_MCP_SUBJECT_PREFIXES`): required claim values, an exact subject allowlist, and subject prefixes, parsed and validated at startup in `http` mode. All default to empty (no policy). Google mode enforces it after the email/domain allowlist (both must pass); its claims are the tokeninfo fields `sub`, `email`, `email_verified`, `hd`, `aud`, `azp` and `scope`, compared exactly as Google returns them, and its subject is `sub`. A principal that fails the policy gets `403 access_denied` with no challenge. In `http` mode, configuring a non-empty policy with `STEAMPIPE_MCP_AUTH_MODE=none` or `token`, which cannot enforce it, is a startup `ConfigError` naming the variables, so a policy is never silently ignored (`REQUIRED_CLAIMS={}` and `ALLOWED_SUBJECTS=[]`/`SUBJECT_PREFIXES=[]` are an empty policy and are accepted).
* `GET /readyz` readiness probe for HTTP mode, separate from `/healthz` (which still never touches the database). It returns `200 {"status":"ready","checks":{...}}` or `503 {"status":"not_ready","checks":{...}}` with check names and statuses only, answers within about 2 s even when the database is wedged, and coalesces concurrent probes into one evaluation cached for 1 s. The `db` check runs `select 1` on a dedicated short-lived connection, never a pooled one, with connect and query together bounded by an independent 2 s deadline that destroys the socket, and a further 2 s for cleanup (so the connection itself lives at most about 4 s). Timeout parameters in the database URL (`connect_timeout`, `query_timeout`, `statement_timeout`) are stripped from this connection, so they cannot extend the deadline. Like `/healthz`, it is exempt from Host/Origin validation so Kubernetes probes work.
* Rejected auth attempts are audited: in `token` and `google` mode, each request refused by the bearer check writes one info-level `{"event":"auth_reject","reason","status","ip","durationMs"}` line (plus `iss`/`sub` when known) with a typed reason such as `missing`, `invalid`, `audience`, `expired`, `not_allowed` or `issuer_unavailable`. `ip`, `iss` and `sub` are sanitised and capped like other logged values; the line never contains the token.
* Optional degraded start for Google mode (`STEAMPIPE_MCP_ALLOW_DEGRADED_START`, default `false`): when Google's discovery document cannot be fetched at startup, the server starts anyway and retries discovery in the background (1 s doubling to 60 s, ±20% jitter). Until it succeeds, the Protected Resource Metadata answers `503` with `Retry-After: 5` and `/readyz` reports `"auth":"pending"`; bearer tokens keep working. The retry stops on shutdown, before the database pool closes. With the default `false`, an unreachable Google still fails startup.

_Security_

* Untrusted text written to logs (the audit line's `sub`, `clientId`, `method` and `tool`, HTTP/MCP request error messages, database driver error messages, and the Google principal email at debug level) is now stripped of control, line-separator and bidi characters and capped at 256 characters with a `…(+N)` suffix; the debug-level SQL line gets the same stripping with an 8192-character cap, so a client cannot forge extra log lines or flood the log. The same applies to tool-layer error lines: the `Unknown tool` error (which echoes the client-supplied tool name), argument-validation diagnostics (capped at 512 characters), and database errors raised under every tool.

_Behaviour changes_

* HTTP bearer auth now uses the server's own middleware instead of the SDK's `requireBearerAuth`. Every rejection carries a typed reason internally; responses follow RFC 6750.
* A request with no `Authorization: Bearer` header (or another scheme) gets `401` with a challenge that has no `error` code (RFC 6750 §3.1): `WWW-Authenticate: Bearer resource_metadata="…"` in google mode, and a bare `WWW-Authenticate: Bearer` in token mode. A rejected token still gets `error="invalid_token"`.
* `WWW-Authenticate` values are escaped and sanitised: quotes, backslashes, control characters (including CR/LF) and non-ASCII are dropped, and `error_description` is capped at 200 characters.
* Google mode: when tokeninfo is unreachable, times out, or answers `429`/`5xx`, requests get `503 temporarily_unavailable` with `Retry-After: 5` instead of `500`.
* Google mode: a `401` now carries the scope hint `scope="openid email"`.
* Google mode: a principal outside the allowlist (or with an unverified email or mismatched `hd`) gets `403 access_denied` with **no** `WWW-Authenticate` challenge, instead of `403 insufficient_scope`, so clients do not loop on scope step-up.
* Bearer tokens longer than 8192 bytes are rejected with `401` before any verification call.
* Token mode: the static verifier no longer reports a rolling one-hour `expiresAt`.
* Google mode: the RFC 9728 Protected Resource Metadata document at `/.well-known/oauth-protected-resource/<path>` is now rendered by the server instead of the SDK's `mcpAuthMetadataRouter`. It gains `"bearer_methods_supported":["header"]`, is served with `Cache-Control: max-age=300`, and answers only `GET`/`HEAD` (anything else, `OPTIONS` included, gets `405` with `Allow: GET, HEAD`). `resource` is the canonical form of `PUBLIC_URL` (a bare origin gains a trailing `/`, e.g. `https://mcp.example.com/`), matching the resource the bearer check expects; `authorization_servers` entries are byte-exact, so the issuer stays `https://accounts.google.com` with no trailing slash.
* Google mode: the copy of Google's metadata at `/.well-known/oauth-authorization-server` is gone (`404`). MCP clients fetch authorization-server metadata from the server named in `authorization_servers`, i.e. from Google.
* Google mode: `/readyz` reports an `auth` check next to `db`. It is always `ready` unless degraded start is enabled and discovery has not succeeded yet.
* Google mode: the tokeninfo call and the startup discovery fetch go through the restricted identity-provider fetch: only `oauth2.googleapis.com` and `accounts.google.com` over https, no redirects followed, bodies capped at 64 KiB, 5 s for headers and body together. A refusal (another host, any `3xx`, an oversized body, a timeout or a network error) answers `503 temporarily_unavailable` with `Retry-After: 5`, never `401`; at startup it fails the start as before, unless degraded start (`STEAMPIPE_MCP_ALLOW_DEGRADED_START=true`) is enabled, in which case discovery is retried in the background.

## 0.2.1 [2026-10-21]

_Fixes_

* The runtime Docker image upgrades OpenSSL (`libcrypto3`/`libssl3`, CVE-2026-31789) and drops the bundled npm/corepack/yarn, which carried a vulnerable `node-tar` (CVE-2026-59873); the app's own production dependencies never included `tar`. 0.2.0 was tagged but never published: the GHCR release workflow's pre-push Trivy scan correctly blocked it on these two CRITICAL findings.

## 0.2.0 [2026-10-21]

_Breaking / security defaults_

* Remote (non-loopback) databases with no `sslmode` set now verify TLS certificates by default, instead of accepting any certificate (previously `rejectUnauthorized:false`). `sslmode=prefer`/`allow` behave the same way for a remote host. Loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) keep encrypted-but-unverified by default, with or without `sslmode=prefer`/`allow`/unset, since a local Steampipe/Postgres typically has no CA-signed certificate. `sslmode=disable` remains the explicit opt-out of TLS; `sslmode=no-verify` keeps encryption without certificate verification.
* The connection string's `ssl`, `host`, and `hostaddr` query parameters are no longer honoured: `ssl` can no longer override the TLS decision above, and a connection string with `host=`/`hostaddr=` is now rejected outright (put the host in the URL authority), since either could otherwise redirect the actual TCP connection to a different host than the one TLS was evaluated against.
* The `steampipe://status` resource no longer includes the connection string unless connection details are explicitly exposed, so it never leaks the database password.
* `steampipe_query` now rejects multi-statement SQL (e.g. `SELECT 1; SELECT 2`) in every transport, including stdio: user SQL runs over the extended query protocol, which accepts a single statement only.
* `engines.node` is raised from `>=18.0.0` to `>=20`.
* HTTP mode caps `steampipe_query` results at 10000 rows by default (`STEAMPIPE_MCP_MAX_ROWS`; `0` means unlimited, the stdio default). A truncated result changes shape from a plain JSON array to `{"rows": [...], "truncated": true}`; untruncated results stay a plain array.

_What's new_

* User query hardening on top of the existing `READ ONLY` transaction: single-statement enforcement, session reset (`DISCARD ALL`) before a connection returns to the pool, a per-connection statement timeout (`STEAMPIPE_MCP_STATEMENT_TIMEOUT_MS`, default 120000 ms), and a row cap (`STEAMPIPE_MCP_MAX_ROWS`).
* All server configuration moves to env vars under a single `STEAMPIPE_MCP_` prefix, parsed in one place (`src/config.ts`); existing stdio defaults (connection string, unlimited row cap) are unchanged except for the TLS default and multi-statement rejection above.
* `@modelcontextprotocol/sdk` upgraded to `1.32.1`; every dependency is now pinned to an exact version.
* New `STEAMPIPE_MCP_TRANSPORT=http` mode serves MCP over stateless Streamable HTTP, with `GET /healthz`, request body size caps, Origin validation (always on), and Host validation (DNS rebinding) on a loopback bind or when `STEAMPIPE_MCP_ALLOWED_HOSTS`/`STEAMPIPE_MCP_PUBLIC_URL` is set for a non-loopback one.
* Two HTTP auth modes: `STEAMPIPE_MCP_AUTH_MODE=token` (static bearer token) and `=google` (Google OAuth access tokens against an email/domain allowlist); see `docs/remote-deployment.md`.
* Per-principal and pre-auth rate limiting, request guards (body size, batch-request rejection, Host/Origin checks), and an audit log for HTTP requests.
* Docker image (`ghcr.io/rafpe/steampipe-mcp`), multi-arch (`linux/amd64`, `linux/arm64`), running as a non-root user with a built-in `HEALTHCHECK`; a `docker-compose.example.yml` pairs it with a Steampipe container; a GHCR release workflow builds, pushes, and Trivy-scans the image on a semver tag.

## v0.1.2 [2024-05-19]

_What's new_

* Return safe bigint values as int instead of string
* Include MCP server version in status resource

## v0.1.1 [2025-04-29]

_What's new_

* Improved performance recommendations in steampipe query tool to suggest materialized CTEs
* Simplified JSON output formatting in status responses

## v0.1.0 [2025-04-16]

_What's new_

* Initial version of Steampipe MCP server
* Query cloud infrastructure, SaaS, APIs and more using AI
