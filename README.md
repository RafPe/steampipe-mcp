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
STEAMPIPE_MCP_TRANSPORT=http npx -y @turbot/steampipe-mcp
# Streamable HTTP server listening on http://127.0.0.1:27123/mcp
```

The HTTP transport is **stateless**: every `POST /mcp` gets its own MCP server instance and there are no session IDs (no `Mcp-Session-Id` header). `GET` and `DELETE` on the MCP path return `405`, and `GET /healthz` returns `{"status":"ok"}` without touching the database; it is exempt from the Origin and Host checks below so container and Kubernetes health probes work. In HTTP mode the `steampipe://status` resource never includes the connection string.

Built-in protections:

- **Loopback by default.** The server binds `127.0.0.1`. Binding a non-loopback address without auth is refused unless `STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE=true`.
- **Origin validation (always on).** A request with an `Origin` header that is not exactly listed in `STEAMPIPE_MCP_ALLOWED_ORIGINS` gets `403`. Requests without an `Origin` header (non-browser clients) pass. `Origin: null` is rejected unless the literal `null` is listed.
- **Host validation (DNS rebinding).** On a loopback bind only `localhost`, `127.0.0.1` and `[::1]` are accepted as `Host`. On a non-loopback bind the `Host` hostname must be in `STEAMPIPE_MCP_ALLOWED_HOSTS`, or else match the hostname of `STEAMPIPE_MCP_PUBLIC_URL`; if neither is set, Host validation is skipped and a warning is logged at startup.
- **Body size cap.** Request bodies larger than `STEAMPIPE_MCP_MAX_BODY_BYTES` get `413`; bodies that are not `application/json` get `415`.
- **Authentication.** `STEAMPIPE_MCP_AUTH_MODE=token` requires a static bearer token; `STEAMPIPE_MCP_AUTH_MODE=google` accepts Google OAuth access tokens for allowlisted users. See [docs/remote-deployment.md](docs/remote-deployment.md).

Quick check with curl (clients must accept both `application/json` and `text/event-stream`):

```sh
curl -s http://127.0.0.1:27123/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

When connecting from a browser-based client such as the MCP Inspector in direct mode, add its origin to `STEAMPIPE_MCP_ALLOWED_ORIGINS` (or use the Inspector's proxy mode).

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
    - connection_string: The current database connection string
    - status: The connection state (connected/disconnected)

This resource enables AI tools to check and verify the connection status to your Steampipe instance.

## Development

### Clone and Setup

1. Clone the repository and navigate to the directory:
```sh
git clone https://github.com/turbot/steampipe-mcp.git
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

HTTP transport settings (only read when `STEAMPIPE_MCP_TRANSPORT=http`):

| Variable | Default | Description |
|----------|---------|-------------|
| `STEAMPIPE_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `STEAMPIPE_MCP_HTTP_HOST` | `127.0.0.1` | Address to bind |
| `STEAMPIPE_MCP_HTTP_PORT` | `27123` | Port to bind |
| `STEAMPIPE_MCP_HTTP_PATH` | `/mcp` | Path of the MCP endpoint |
| `STEAMPIPE_MCP_PUBLIC_URL` | _(unset)_ | Public URL clients use (must be `https` unless loopback); its hostname is the Host-validation fallback |
| `STEAMPIPE_MCP_ALLOWED_ORIGINS` | _(empty)_ | Comma-separated exact `Origin` values to accept; any other present `Origin` gets `403` |
| `STEAMPIPE_MCP_ALLOWED_HOSTS` | _(empty)_ | Comma-separated hostnames accepted in the `Host` header on a non-loopback bind (ports and case are ignored) |
| `STEAMPIPE_MCP_MAX_BODY_BYTES` | `1048576` | Maximum request body size in bytes; larger bodies get `413` |
| `STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE` | `false` | Allow a non-loopback bind without auth (not recommended) |
| `STEAMPIPE_MCP_AUTH_MODE` | `none` | `none`, `token`, or `google` ([docs/remote-deployment.md](docs/remote-deployment.md)) |
| `STEAMPIPE_MCP_AUTH_TOKEN` | _(unset)_ | Static bearer token, at least 32 characters (`token` mode) |
| `STEAMPIPE_MCP_GOOGLE_CLIENT_ID` | _(unset)_ | Google OAuth client ID that tokens must be issued to (`google` mode) |
| `STEAMPIPE_MCP_ALLOWED_EMAILS` | _(empty)_ | Comma-separated emails allowed in `google` mode (case-insensitive) |
| `STEAMPIPE_MCP_ALLOWED_DOMAINS` | _(empty)_ | Comma-separated email domains allowed in `google` mode (case-insensitive). Only a membership boundary with an Internal consent screen on Google Workspace; with External, use `ALLOWED_EMAILS` ([details](docs/remote-deployment.md#allowed_domains-is-only-a-boundary-with-an-internal-consent-screen)) |

## Open Source & Contributing

This repository is published under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0). Please see our [code of conduct](https://github.com/turbot/.github/blob/main/CODE_OF_CONDUCT.md). We look forward to collaborating with you!

[Steampipe](https://steampipe.io) is a product produced from this open source software, exclusively by [Turbot HQ, Inc](https://turbot.com). It is distributed under our commercial terms. Others are allowed to make their own distribution of the software, but they cannot use any of the Turbot trademarks, cloud services, etc. You can learn more in our [Open Source FAQ](https://turbot.com/open-source).

## Get Involved

**[Join #steampipe on Slack →](https://turbot.com/community/join)**

Want to help but don't know where to start? Pick up one of the `help wanted` issues:
* [Steampipe](https://github.com/turbot/steampipe/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22)
* [Steampipe MCP](https://github.com/turbot/steampipe-mcp/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22)
