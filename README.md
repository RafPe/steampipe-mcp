# Steampipe Model Context Protocol (MCP) Server

Unlock the power of AI-driven infrastructure analysis with [Steampipe](https://steampipe.io)! This Model Context Protocol server seamlessly connects AI assistants like Claude to your cloud infrastructure data, enabling natural language exploration and analysis of your entire cloud estate.

Steampipe MCP bridges AI assistants and your infrastructure data, allowing natural language:
- Queries across AWS, Azure, GCP and 100+ cloud services
- Security and compliance analysis
- Cost and resource optimization
- Query development assistance

Works with both local [Steampipe](https://steampipe.io/downloads) installations and [Turbot Pipes](https://turbot.com/pipes) workspaces, providing safe, read-only access to all your cloud and SaaS data.

## Installation

### Prerequisites

- [Node.js](https://nodejs.org/) v20 or higher (includes `npx`)
- For local use: [Steampipe](https://steampipe.io/downloads) installed and running (`steampipe service start`)
- For Turbot Pipes: A [Turbot Pipes](https://turbot.com/pipes) workspace and connection string

### Configuration

Add Steampipe MCP to your AI assistant's configuration file:

```json
{
  "mcpServers": {
    "steampipe": {
      "command": "npx",
      "args": [
        "-y",
        "@turbot/steampipe-mcp"
      ]
    }
  }
}
```

> **Note:** `npx -y @turbot/steampipe-mcp` installs the upstream npm package (`0.1.2`), which only supports stdio. This fork is not published to npm: the HTTP transport, auth modes, row cap, and other hardening described below are only available when you run it [from a clone](#clone-and-setup) or from the [Docker image](#run-as-a-remote-mcp-docker).

By default, this connects to your local Steampipe installation at `postgresql://steampipe@localhost:9193/steampipe`. Make sure to run `steampipe service start` first.

To connect to a [Turbot Pipes](https://turbot.com/pipes) workspace instead, add your connection string to the args:

```json
{
  "mcpServers": {
    "steampipe": {
      "command": "npx",
      "args": [
        "-y",
        "@turbot/steampipe-mcp",
        "postgresql://my_name:my_pw@workspace-name.usea1.db.pipes.turbot.com:9193/abc123"
      ]
    }
  }
}
```

### AI Assistant Setup

| Assistant | Config File Location | Setup Guide |
|-----------|---------------------|-------------|
| Claude Desktop | `claude_desktop_config.json` | [Claude Desktop MCP Guide →](https://modelcontextprotocol.io/quickstart/user) |
| Cursor | `~/.cursor/mcp.json` | [Cursor MCP Guide →](https://docs.cursor.com/context/model-context-protocol) |

Save the configuration file and restart your AI assistant for the changes to take effect.

### Remote access over HTTP

Besides stdio (the default), the server can serve [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http) so clients can reach it over the network:

```sh
git clone https://github.com/RafPe/steampipe-mcp.git
cd steampipe-mcp
npm ci && npm run build
STEAMPIPE_MCP_TRANSPORT=http node dist/index.js
# Streamable HTTP server listening on http://127.0.0.1:27123/mcp
```

Or run the Docker image `ghcr.io/rafpe/steampipe-mcp:0.2.1` (see [Run as a remote MCP (Docker)](#run-as-a-remote-mcp-docker)). The upstream `npx -y @turbot/steampipe-mcp` package has no HTTP mode.

The HTTP transport is **stateless**: every `POST /mcp` gets its own MCP server instance and there are no session IDs (no `Mcp-Session-Id` header). `GET` and `DELETE` on the MCP path return `405`, and `GET /healthz` returns `{"status":"ok"}` without touching the database; it is exempt from the Origin and Host checks below so container and Kubernetes health probes work. `GET /readyz` is the readiness probe: it answers `200 {"status":"ready","checks":{"db":"ready"}}` or `503 {"status":"not_ready","checks":{"db":"failing"}}` (check names and statuses only, never error details), is exempt from the same checks, and always answers within about 2 s. The `db` check runs `select 1` on a dedicated short-lived connection (never one from the query pool) with 2 s connect, query and cleanup timeouts, so that connection lives at most about 6 s even when the probe has already answered `failing`; concurrent probes share one evaluation and a result is reused for 1 s. In HTTP mode the `steampipe://status` resource never includes the connection string, and `steampipe_query` returns at most `STEAMPIPE_MCP_MAX_ROWS` rows (default `10000`).

Built-in protections:

- **Loopback by default.** The server binds `127.0.0.1`. Binding a non-loopback address without auth is refused unless `STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE=true`.
- **Origin validation (always on).** A request with an `Origin` header that is not exactly listed in `STEAMPIPE_MCP_ALLOWED_ORIGINS` gets `403`. Requests without an `Origin` header (non-browser clients) pass. `Origin: null` is rejected unless the literal `null` is listed.
- **Host validation (DNS rebinding).** On a loopback bind only `localhost`, `127.0.0.1` and `[::1]` are accepted as `Host`. On a non-loopback bind the `Host` hostname must be in `STEAMPIPE_MCP_ALLOWED_HOSTS`, or else match the hostname of `STEAMPIPE_MCP_PUBLIC_URL`; if neither is set, Host validation is skipped and a warning is logged at startup.
- **Body size cap.** Request bodies larger than `STEAMPIPE_MCP_MAX_BODY_BYTES` get `413`; bodies that are not `application/json` get `415`, and an empty `application/json` body gets `400`.
- **Authentication.** `STEAMPIPE_MCP_AUTH_MODE=token` requires a static bearer token; `STEAMPIPE_MCP_AUTH_MODE=google` accepts Google OAuth access tokens for allowlisted users. See [docs/remote-deployment.md](docs/remote-deployment.md).

Quick check with curl (clients must accept both `application/json` and `text/event-stream`):

```sh
curl -s http://127.0.0.1:27123/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

To try the server with the MCP Inspector, use the Inspector's proxy mode, where the Inspector's local proxy (not the browser) connects to the server; or use curl as above. Direct mode, where the browser connects itself, does not work: the server sends no CORS headers and answers the `OPTIONS` preflight with `404` (or `403` if the origin is not in `STEAMPIPE_MCP_ALLOWED_ORIGINS`).

### Run as a remote MCP (Docker)

A multi-arch (`linux/amd64`, `linux/arm64`) image is published to
`ghcr.io/rafpe/steampipe-mcp`. It runs as a non-root user, defaults to
`STEAMPIPE_MCP_TRANSPORT=http` on `0.0.0.0:27123`, and has a built-in
`HEALTHCHECK` against `GET /healthz`. Because of the bind guard above, it
refuses to start unless `STEAMPIPE_MCP_AUTH_MODE` is `token` or `google` (or
`STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE=true` is set).

Token mode, pointed at a Turbot Pipes workspace:

```sh
TOKEN=$(openssl rand -hex 32)
docker run -d --name steampipe-mcp -p 27123:27123 \
  -e STEAMPIPE_MCP_AUTH_MODE=token \
  -e STEAMPIPE_MCP_AUTH_TOKEN="$TOKEN" \
  -e STEAMPIPE_MCP_WORKSPACE_DATABASE="postgresql://my_name:my_pw@workspace-name.usea1.db.pipes.turbot.com:9193/abc123" \
  ghcr.io/rafpe/steampipe-mcp:0.2.1
echo "Token: $TOKEN"   # save this - you'll need it below
```

Or bring your own Steampipe container with
[`docker-compose.example.yml`](docker-compose.example.yml), which also needs
a database password (Steampipe requires one for connections from another
container):

```sh
cp docker-compose.example.yml docker-compose.yml
TOKEN=$(openssl rand -hex 32)
{
  echo "STEAMPIPE_MCP_AUTH_TOKEN=$TOKEN"
  echo "STEAMPIPE_PASSWORD=$(openssl rand -hex 20)"
} > .env
docker compose up -d
```

Connect Claude Code to either:

```sh
claude mcp add --transport http steampipe http://localhost:27123/mcp \
  --header "Authorization: Bearer $TOKEN"
```

Stop the container with a grace period longer than its 10s forced-close
shutdown timeout, e.g. `docker stop -t 15 steampipe-mcp` (the compose example
sets `stop_grace_period: 15s` for the same reason; docker/compose's own
default stop grace period is 10s).

On Kubernetes, use `/healthz` for liveness (it never touches the database,
so a Steampipe outage does not restart the pod) and `/readyz` for readiness
(it takes the pod out of the Service while the database is unreachable).
`/readyz` answers within about 2 s, so keep `timeoutSeconds` at 3 or more:

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 27123 }
  periodSeconds: 10
readinessProbe:
  httpGet: { path: /readyz, port: 27123 }
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

See [docs/remote-deployment.md](docs/remote-deployment.md) for Google OAuth
mode, the threat model, and reverse-proxy/TLS guidance (the server itself
speaks plain HTTP).

## Prompting Guide

First, run the `best_practices` prompt included in the MCP server to teach your LLM how best to work with Steampipe. Then, ask anything!

Explore your cloud infrastructure:
```
What AWS accounts can you see?
```

Simple, specific questions work well:
```
Show me all S3 buckets that were created in the last week
```

Generate infrastructure reports:
```
List my EC2 instances with their attached EBS volumes
```

Dive into security analysis:
```
Find any IAM users with access keys that haven't been rotated in the last 90 days
```

Get compliance insights:
```
Show me all EC2 instances that don't comply with our tagging standards
```

Explore potential risks:
```
Analyze my S3 buckets for security risks including public access, logging, and encryption
```

Remember to:
- Be specific about which cloud resources you want to analyze (EC2, S3, IAM, etc.)
- Mention regions or accounts if you're interested in specific ones
- Start with simple queries before adding complex conditions
- Use natural language - the LLM will handle the SQL translation
- Be bold and exploratory - the LLM can help you discover insights across your entire infrastructure!

## Capabilities

### Tools

- **steampipe_query**
  - Query cloud and security logs with SQL.
  - For best performance: use CTEs instead of joins, limit columns requested.
  - All queries are read-only and use PostgreSQL syntax.
  - Input: `sql` (string): The SQL query to execute using PostgreSQL syntax

- **steampipe_table_list**
  - List all available Steampipe tables.
  - Optional input: `schema` (string): Filter tables by specific schema
  - Optional input: `filter` (string): Filter tables by ILIKE pattern (e.g. '%ec2%')

- **steampipe_table_show**
  - Get detailed information about a specific table, including column definitions, data types, and descriptions.
  - Input: `name` (string): The name of the table to show details for (can be schema qualified e.g. 'aws_account' or 'aws.aws_account')
  - Optional input: `schema` (string): The schema containing the table

- **steampipe_plugin_list**
  - List all Steampipe plugins installed on the system. Plugins provide access to different data sources like AWS, GCP, or Azure.
  - No input parameters required

- **steampipe_plugin_show**
  - Get details for a specific Steampipe plugin installation, including version, memory limits, and configuration.
  - Input: `name` (string): Name of the plugin to show details for

### Prompts

- **best_practices**
  - Best practices for working with Steampipe data
  - Provides detailed guidance on:
    - Response style and formatting conventions
    - Using CTEs (WITH clauses) vs joins
    - SQL syntax and style conventions
    - Column selection and optimization
    - Schema exploration and understanding
    - Query structure and organization
    - Performance considerations and caching
    - Error handling and troubleshooting

### Resources

- **status**
  - Represents the current state of the Steampipe connection
  - Properties include:
    - connection_string: The current database connection string, password masked (stdio only; never included in HTTP mode)
    - status: The connection state (connected/disconnected)

This resource enables AI tools to check and verify the connection status to your Steampipe instance.

## Development

### Clone and Setup

1. Clone the repository and navigate to the directory:
```sh
git clone https://github.com/RafPe/steampipe-mcp.git
cd steampipe-mcp
```

2. Install dependencies:
```sh
npm install
```

3. Build the project:
```sh
npm run build
```

### Testing

To test your local development build with AI tools that support MCP, update your MCP configuration to use the local `dist/index.js` instead of the npm package. For example:

```json
{
  "mcpServers": {
    "steampipe": {
      "command": "node",
      "args": [
        "/absolute/path/to/steampipe-mcp/dist/index.js",
        "postgresql://steampipe@localhost:9193/steampipe"
      ]
    }
  }
}
```

Or, use the MCP Inspector to validate the server implementation:
```sh
npx @modelcontextprotocol/inspector dist/index.js
```

### Environment Variables

The following environment variables can be used to configure the MCP server:

- `STEAMPIPE_MCP_LOG_LEVEL`: Control server logging verbosity (default: `info`)
- `STEAMPIPE_MCP_WORKSPACE_DATABASE`: Override the default Steampipe connection string (default: `postgresql://steampipe@localhost:9193/steampipe`)

Query limits (both transports):

| Variable | Default | Description |
|----------|---------|-------------|
| `STEAMPIPE_MCP_MAX_ROWS` | `0` on stdio, `10000` on http | Maximum rows `steampipe_query` returns; `0` means unlimited. When the cap cuts a result short, the tool returns `{"rows": [...], "truncated": true}` instead of a plain array |
| `STEAMPIPE_MCP_STATEMENT_TIMEOUT_MS` | `120000` | Per-connection Postgres `statement_timeout` (and `idle_in_transaction_session_timeout`) in milliseconds; minimum `1` |

HTTP transport settings. Some are validated in every mode, so a malformed value fails startup even on stdio: the numeric settings, `TRANSPORT`, `AUTH_MODE`, `ALLOW_INSECURE_REMOTE`, `TRUST_PROXY`, and the syntax of `PUBLIC_URL`, `ALLOWED_ORIGINS` and `ALLOWED_HOSTS`. The policy checks (the non-loopback bind guard, the `token`/`google` auth requirements, and `https` for a non-loopback `PUBLIC_URL`) apply only when `STEAMPIPE_MCP_TRANSPORT=http`:

| Variable | Default | Description |
|----------|---------|-------------|
| `STEAMPIPE_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `STEAMPIPE_MCP_HTTP_HOST` | `127.0.0.1` | Address to bind |
| `STEAMPIPE_MCP_HTTP_PORT` | `27123` | Port to bind |
| `STEAMPIPE_MCP_HTTP_PATH` | `/mcp` | Path of the MCP endpoint |
| `STEAMPIPE_MCP_PUBLIC_URL` | _(unset)_ | Public URL clients use (must be `https` unless loopback); its hostname is the Host-validation fallback |
| `STEAMPIPE_MCP_ALLOWED_ORIGINS` | _(empty)_ | Comma-separated origins to accept (e.g. `https://app.example.com`); each entry is normalised to its origin, so case, a trailing slash, or a default port don't matter. The literal `null` allows `Origin: null`. Any other present `Origin` gets `403` |
| `STEAMPIPE_MCP_ALLOWED_HOSTS` | _(empty)_ | Comma-separated hostnames (optionally `host:port`) accepted in the `Host` header on a non-loopback bind; ports and case are ignored. Entries with a scheme or path (e.g. `https://x`) are rejected at startup |
| `STEAMPIPE_MCP_MAX_BODY_BYTES` | `1048576` | Maximum request body size in bytes; larger bodies get `413` |
| `STEAMPIPE_MCP_RATE_LIMIT_PER_MIN` | `60` | Per-principal (authenticated `sub`, or client IP in `none` mode) requests per rolling 60s window; over-limit requests get `429`. A coarser, IP-only limit at 10x this value also applies ahead of auth, so an unauthenticated flood can't reach the token verifier |
| `STEAMPIPE_MCP_TRUST_PROXY` | _(unset)_ | Passed to Express's `trust proxy` setting (a hop count, or `true`) so rate limiting sees the real client IP behind a reverse proxy. Only set this when every request actually goes through that trusted proxy: it makes `X-Forwarded-For` authoritative, so setting it without one lets a client spoof its own rate-limit key and bypass the limit |
| `STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE` | `false` | Allow a non-loopback bind without auth (not recommended) |
| `STEAMPIPE_MCP_AUTH_MODE` | `none` | `none`, `token`, or `google` ([docs/remote-deployment.md](docs/remote-deployment.md)) |
| `STEAMPIPE_MCP_AUTH_TOKEN` | _(unset)_ | Static bearer token, at least 32 characters (`token` mode) |
| `STEAMPIPE_MCP_GOOGLE_CLIENT_ID` | _(unset)_ | Google OAuth client ID that tokens must be issued to (`google` mode) |
| `STEAMPIPE_MCP_ALLOWED_EMAILS` | _(empty)_ | Comma-separated emails allowed in `google` mode (case-insensitive) |
| `STEAMPIPE_MCP_ALLOWED_DOMAINS` | _(empty)_ | Comma-separated email domains allowed in `google` mode (case-insensitive). Only a membership boundary with an Internal consent screen on Google Workspace; with External, use `ALLOWED_EMAILS` ([details](docs/remote-deployment.md#allowed_domains-is-only-a-boundary-with-an-internal-consent-screen)) |
| `STEAMPIPE_MCP_REQUIRED_CLAIMS` | _(empty)_ | Identity policy: a JSON object mapping a claim name to the values it may take, e.g. `{"hd":["corp.com"],"groups":["platform"]}`. Every listed claim must match: a string claim must equal an allowed value, an array claim must contain one, and a boolean or number matches its string form (`true` matches `"true"`). An absent, `null`, or object claim fails. Validated at startup: every claim must list at least one value (an empty list `[]` is rejected), and claim names and values must be 1 to 256 characters (an empty string `""` is rejected) |
| `STEAMPIPE_MCP_ALLOWED_SUBJECTS` | _(empty)_ | Identity policy: a JSON array of exact subjects (`sub`) allowed, at most 1024 entries. Each entry must be 1 to 256 characters; an empty string `""` is rejected at startup |
| `STEAMPIPE_MCP_SUBJECT_PREFIXES` | _(empty)_ | Identity policy: a JSON array of subject prefixes allowed, at most 64 entries (prefix `"platform-"` does not admit `"platform"`). A subject passes when it is on `ALLOWED_SUBJECTS` or starts with a prefix; when both are empty, any subject passes. No regex is supported. Each entry must be 1 to 256 characters; an empty string `""` is rejected at startup, since it would match every subject. All three policy variables default to empty, meaning no policy, and are read in `http` mode only |

### Logging

Logs go to stderr. Values in log lines that come from clients, tokens, or the database (the audit line's `sub`, `clientId`, `method` and `tool`, request and driver error messages, and the Google principal email at debug level) are sanitised: control, line-separator and bidi characters are stripped, and each value is capped at 256 characters, with a `…(+N)` suffix giving the number of characters cut. The debug-level SQL line is sanitised the same way, with a cap of 8192 characters.

In `token` and `google` mode, every request the bearer check refuses writes one info-level line:

```
{"event":"auth_reject","reason":"expired","status":401,"ip":"203.0.113.7","durationMs":42}
```

`reason` says why, for example `missing`, `malformed`, `invalid`, `audience`, `expired`, `not_allowed` (status `403`) or `issuer_unavailable` (status `503`). `ip` is the client address as Express sees it (with `STEAMPIPE_MCP_TRUST_PROXY` set, it comes from `X-Forwarded-For`), or `"unknown"`; `iss` and `sub` appear only when known. `ip`, `iss` and `sub` are sanitised like the values above. The line never contains the token, the `Authorization` header or an error message. A refused request writes no normal audit line, and an accepted one writes no `auth_reject` line.

## Open Source & Contributing

This repository is published under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0). Please see our [code of conduct](https://github.com/turbot/.github/blob/main/CODE_OF_CONDUCT.md). We look forward to collaborating with you!

[Steampipe](https://steampipe.io) is a product produced from this open source software, exclusively by [Turbot HQ, Inc](https://turbot.com). It is distributed under our commercial terms. Others are allowed to make their own distribution of the software, but they cannot use any of the Turbot trademarks, cloud services, etc. You can learn more in our [Open Source FAQ](https://turbot.com/open-source).

## Get Involved

**[Join #steampipe on Slack →](https://turbot.com/community/join)**

Want to help but don't know where to start? Pick up one of the `help wanted` issues:
* [Steampipe](https://github.com/turbot/steampipe/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22)
* [Steampipe MCP](https://github.com/turbot/steampipe-mcp/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22)
