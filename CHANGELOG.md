## Unreleased

_What's new_

* Declarative identity policy (`STEAMPIPE_MCP_REQUIRED_CLAIMS`, `STEAMPIPE_MCP_ALLOWED_SUBJECTS`, `STEAMPIPE_MCP_SUBJECT_PREFIXES`): required claim values, an exact subject allowlist, and subject prefixes, parsed and validated at startup in `http` mode. All default to empty (no policy). This release adds the policy core and its configuration only; the verifiers enforce it in a later change.

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
