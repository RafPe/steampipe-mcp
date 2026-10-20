## Unreleased

_Breaking / security defaults_

* Remote (non-loopback) databases now verify TLS certificates by default, instead of accepting any certificate. This applies whether `sslmode` is unset or set to `prefer`/`allow` - those modes no longer mean "maybe plaintext"; they mean encrypted and verified for remote hosts, same as no `sslmode` at all. `sslmode=disable` is the only explicit opt-out of TLS; `sslmode=no-verify` restores the previous "encrypted but don't check the certificate" behaviour.
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
