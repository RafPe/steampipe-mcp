## 0.2.0 [2026-10-21]

_Breaking / security defaults_

* Remote (non-loopback) databases with no `sslmode` set now verify TLS certificates by default, instead of accepting any certificate (previously `rejectUnauthorized:false`). `sslmode=prefer`/`allow` behave the same way for a remote host. Loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) keep encrypted-but-unverified by default, with or without `sslmode=prefer`/`allow`/unset, since a local Steampipe/Postgres typically has no CA-signed certificate. `sslmode=disable` remains the explicit opt-out of TLS; `sslmode=no-verify` keeps encryption without certificate verification.
* The connection string's `ssl`, `host`, and `hostaddr` query parameters are no longer honoured: `ssl` can no longer override the TLS decision above, and a connection string with `host=`/`hostaddr=` is now rejected outright (put the host in the URL authority), since either could otherwise redirect the actual TCP connection to a different host than the one TLS was evaluated against.
* The `steampipe://status` resource no longer includes the connection string unless connection details are explicitly exposed, so it never leaks the database password.

_What's new_

* Queries are enforced read-only at the database session level, independent of SQL parsing.
* All server configuration moves to env vars under a single `STEAMPIPE_MCP_` prefix, parsed in one place (`src/config.ts`); existing stdio defaults (connection string, unlimited row cap) are unchanged except for the TLS default above.
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
