## Unreleased

_Breaking / security defaults_

* Remote (non-loopback) databases with no `sslmode` set now verify TLS certificates by default, instead of accepting any certificate (previously `rejectUnauthorized:false`). `sslmode=prefer`/`allow` behave the same way for a remote host. Loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) keep encrypted-but-unverified by default, with or without `sslmode=prefer`/`allow`/unset, since a local Steampipe/Postgres typically has no CA-signed certificate. `sslmode=disable` remains the explicit opt-out of TLS; `sslmode=no-verify` keeps encryption without certificate verification.
* The connection string's `ssl`, `host`, and `hostaddr` query parameters are no longer honoured: `ssl` can no longer override the TLS decision above, and a connection string with `host=`/`hostaddr=` is now rejected outright (put the host in the URL authority), since either could otherwise redirect the actual TCP connection to a different host than the one TLS was evaluated against.
* The `steampipe://status` resource no longer includes the connection string unless connection details are explicitly exposed, so it never leaks the database password.

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
