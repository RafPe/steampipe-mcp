# Remote deployment

This guide covers running the Steampipe MCP server over Streamable HTTP for
clients on other machines, with authentication. For local use, stdio (the
default) needs none of this.

The server supports two auth modes:

| Mode | `STEAMPIPE_MCP_AUTH_MODE` | Who can connect | Setup cost |
|------|---------------------------|-----------------|------------|
| Static token | `token` | Anyone holding one shared secret | Low |
| Google OAuth | `google` | Allowlisted Google accounts, each signing in as themselves | Google Cloud OAuth client |

`none` is the default and is only accepted on a loopback bind, unless you set
`STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE=true`.

## Threat model

**What is protected:** the MCP endpoint (`POST {STEAMPIPE_MCP_HTTP_PATH}`,
default `/mcp`). Every tool, prompt and resource is reached through it, and the
tools run arbitrary read-only SQL against Steampipe with the server's own
database credentials.

**Read this first: every authenticated principal gets full access.** Neither
mode has per-user or per-connection authorization. Every allowlisted Google
account, and everyone holding the static token, can query **every** Steampipe
connection the server's database user can see: every cloud account, SaaS
tenant and plugin. Google cannot issue custom scopes, so there are none. If
different people need different data, run separate servers against separate
Steampipe instances or workspaces.

**In scope:**

- *Unauthenticated network callers.* `POST /mcp` without a valid
  `Authorization: Bearer` header gets `401` with a `WWW-Authenticate: Bearer`
  challenge. Tokens in the query string (`?access_token=`) are ignored.
- *Tokens minted for other applications* (google mode). Audience binding is
  `aud` = `STEAMPIPE_MCP_GOOGLE_CLIENT_ID`: a Google access token is accepted
  only if tokeninfo reports our client ID as its `aud`. A matching `azp` alone
  is not enough. A token another app obtained for the same user gets `401`.
  The flip side is that **every** token minted for that client ID is accepted,
  so use a **dedicated** OAuth client for this server and nothing else.
- *Google users who are not allowed* (google mode). An email that is
  unverified, or that is neither in `STEAMPIPE_MCP_ALLOWED_EMAILS` nor in a
  domain in `STEAMPIPE_MCP_ALLOWED_DOMAINS`, gets `403 insufficient_scope` and
  never reaches the tools. The domain is the part after the last `@`, compared
  as a whole string, so `corp.com` does not match `evilcorp.com`,
  `sub.corp.com` or `a@corp.com.evil.com`. This is a string match on the email
  address, **not proof of membership** in your organization. See
  [ALLOWED_DOMAINS is only a boundary with an Internal consent screen](#allowed_domains-is-only-a-boundary-with-an-internal-consent-screen).
- *Browser-based attacks.* Origin validation (`403` for unknown `Origin`) and
  Host validation (DNS rebinding) still apply in front of auth.
- *Token leakage through the server.* Tokens are never logged and never
  forwarded to Postgres or Steampipe. In google mode the server sends the token
  to Google in a POST form body, so it never appears in a URL or access log.

**Out of scope / residual risk:**

- *TLS.* The server speaks plain HTTP. Put it behind a TLS-terminating proxy
  or load balancer. `STEAMPIPE_MCP_PUBLIC_URL` must be `https` unless its host
  is loopback.
- *Revocation latency* (google mode). A successful validation is cached in
  memory for up to 60 seconds (never past the token's expiry), so a token
  revoked at Google can keep working for up to 60 seconds. Failed validations
  are never cached. The allowlist is read from the environment, so changing it
  needs a restart, which also clears the cache.
- *Static token compromise* (token mode). One shared secret, no identity, no
  expiry. Rotate it by changing `STEAMPIPE_MCP_AUTH_TOKEN` and restarting.
- *Google availability* (google mode). If tokeninfo is unreachable or slower
  than 5 seconds, requests fail closed with `500`. They are never accepted.
  The server also refuses to start if it cannot fetch Google's discovery
  document.

The unauthenticated endpoints are `GET /healthz` (static `{"status":"ok"}`),
`GET`/`DELETE /mcp` (always `405`), and in google mode the public metadata
under `/.well-known/` (see below). None of them touch the database.

## Common server settings

```sh
STEAMPIPE_MCP_TRANSPORT=http
STEAMPIPE_MCP_HTTP_HOST=0.0.0.0           # or the interface your proxy reaches
STEAMPIPE_MCP_HTTP_PORT=27123
STEAMPIPE_MCP_PUBLIC_URL=https://mcp.example.com/mcp   # the URL clients use
```

`STEAMPIPE_MCP_PUBLIC_URL` is the externally visible URL of the MCP endpoint,
path included. Its hostname is also used for Host validation unless
`STEAMPIPE_MCP_ALLOWED_HOSTS` is set. In google mode its path must match the
path your proxy forwards to `STEAMPIPE_MCP_HTTP_PATH`, because the metadata URL
is derived from it.

## Option 1: static token

Generate a long random token (at least 32 characters; the server refuses
anything shorter):

```sh
openssl rand -hex 32
```

Server:

```sh
STEAMPIPE_MCP_AUTH_MODE=token
STEAMPIPE_MCP_AUTH_TOKEN=<token>
```

Claude Code:

```sh
claude mcp add --transport http steampipe https://<host>/mcp \
  --header "Authorization: Bearer <token>"
```

The token is compared in constant time over sha256 digests, so response timing
does not reveal its content or length. In token mode a `401` carries
`WWW-Authenticate: Bearer error="invalid_token"` with no `resource_metadata`
parameter: there is no OAuth server to discover, so the client simply needs the
header above.

This is also the fallback if google mode does not work with your client (see
[Known unknown](#known-unknown-rfc-8707-resource-and-google) below).

## Option 2: Google OAuth

In this mode the server is an OAuth 2.0 *resource server*. Google is the
authorization server. The MCP client signs the user in with Google, gets a
Google access token, and sends it as a bearer token. The server checks each
token against Google's tokeninfo endpoint and then applies the email
allowlist.

Two Google constraints shape the setup:

- **No dynamic client registration.** MCP clients cannot register themselves
  with Google, so you create an OAuth client once and give its credentials to
  each user's MCP client.
- **Opaque access tokens and no custom scopes.** Tokens are validated online
  through tokeninfo, and authorization is by email allowlist only.

### 1. Google Cloud setup

1. **OAuth consent screen** (Google Cloud console, *Google Auth Platform* /
   *APIs & Services → OAuth consent screen*):
   - **Internal** (requires Google Workspace): only accounts managed by your
     Workspace organization can sign in. This is the **only** setup in which
     `STEAMPIPE_MCP_ALLOWED_DOMAINS` is a real membership boundary.
   - **External**: any Google account can sign in. You **must** list users
     explicitly in `STEAMPIPE_MCP_ALLOWED_EMAILS` and must not rely on
     `STEAMPIPE_MCP_ALLOWED_DOMAINS` (see below). While the app is in
     *Testing*, also add each user as a test user.
   - Scopes: `openid` and `email` only. No sensitive or restricted scopes are
     needed.
2. **OAuth client** (*Credentials → Create credentials → OAuth client ID*):
   - Create a **dedicated** client for this server. Do not reuse a client that
     any other application uses: the server accepts every token whose `aud` is
     this client ID, so a token issued to another app sharing the client would
     be accepted too.
   - Application type: **Web application**.
   - **Authorized redirect URIs:** the loopback redirect URI(s) your MCP
     client uses. For Claude Code, pick a fixed port (for example `33418`) and
     pass it as `--callback-port` (below). The redirect URI is then
     `http://localhost:<port>/<callback path>`. Claude Code's callback path is
     not documented in `claude mcp add --help`, so read the exact
     `redirect_uri` parameter from the Google sign-in URL that Claude Code
     opens on its first attempt. If it is not registered yet, Google shows
     `redirect_uri_mismatch`, and the error details include the URI to add.
   - Note the **client ID** and **client secret**.

### 2. Server

```sh
STEAMPIPE_MCP_AUTH_MODE=google
STEAMPIPE_MCP_PUBLIC_URL=https://mcp.example.com/mcp
STEAMPIPE_MCP_GOOGLE_CLIENT_ID=<client id>.apps.googleusercontent.com
STEAMPIPE_MCP_ALLOWED_DOMAINS=example.com              # and/or:
STEAMPIPE_MCP_ALLOWED_EMAILS=alice@example.com,bob@partner.example
```

At least one of `ALLOWED_EMAILS` / `ALLOWED_DOMAINS` is required. Both are
case-insensitive. The server never needs the client secret.

#### ALLOWED_DOMAINS is only a boundary with an Internal consent screen

Anyone can create a consumer Google account (a "Google Account with an
existing email address") for an address such as `bob@corp.com`, without
access to Workspace. This includes an ex-employee whose Workspace account was
deleted. Google marks that account's email as verified. With an **External**
consent screen, such an account can sign in, and its email matches
`ALLOWED_DOMAINS=corp.com`.

- With an **Internal** consent screen on Google Workspace, only accounts your
  organization manages can sign in, so `ALLOWED_DOMAINS` works as a
  membership boundary.
- With an **External** consent screen, use **explicit
  `STEAMPIPE_MCP_ALLOWED_EMAILS` only**, and leave `ALLOWED_DOMAINS` unset.

As defence in depth, when a user is admitted only by `ALLOWED_DOMAINS` and
tokeninfo reports a hosted domain (`hd`), the server requires `hd` to equal
the email's domain and otherwise returns `403`. tokeninfo for access tokens
often omits `hd`. A missing `hd` is not rejected, so this check is **not** a
substitute for the Internal consent screen.

At startup the server fetches
`https://accounts.google.com/.well-known/openid-configuration`, and refuses to
start if that fails or names any issuer other than
`https://accounts.google.com`. Once running it serves:

- `GET /.well-known/oauth-protected-resource/mcp`: RFC 9728 Protected
  Resource Metadata. `resource` is your `PUBLIC_URL`, `authorization_servers`
  is `["https://accounts.google.com"]`, and `scopes_supported` is
  `["openid","email"]`.
- `GET /.well-known/oauth-authorization-server`: a copy of Google's metadata,
  for clients that look for it on the resource host.

These are public, but still subject to Host and Origin validation. An
unauthenticated `POST /mcp` gets:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
```

How each token is validated:

1. POST `access_token=<token>` (form body) to
   `https://oauth2.googleapis.com/tokeninfo`, with a 5s timeout.
2. Any non-200 response, `aud` different from `GOOGLE_CLIENT_ID` (`azp` is
   not consulted), or `exp` missing or in the past → `401 invalid_token`.
3. `email_verified` not `"true"`, an email that is neither allowlisted nor in
   an allowlisted domain, or a domain-only match where `hd` is present and
   differs from the email's domain → `403 insufficient_scope`.
4. Otherwise accept. The result is cached for at most 60 seconds, keyed by the
   token's sha256.

At `STEAMPIPE_MCP_LOG_LEVEL=debug` the server logs the authenticated (or
rejected) email. It never logs tokens.

### 3. Claude Code client

Give each user the client ID and secret. They run:

```sh
claude mcp add --transport http steampipe https://mcp.example.com/mcp \
  --client-id <client id>.apps.googleusercontent.com \
  --client-secret \
  --callback-port 33418
```

`--client-secret` prompts for the secret (or reads the `MCP_CLIENT_SECRET`
environment variable). `--callback-port` must match the port in the redirect
URI you registered. Then authenticate with `/mcp` inside Claude Code, which
opens the Google sign-in page.

These are the OAuth flags `claude mcp add --help` lists:

```
--callback-port <port>   Fixed port for OAuth callback (for servers
                         requiring pre-registered redirect URIs)
--client-id <clientId>   OAuth client ID for HTTP/SSE servers
--client-secret          Prompt for OAuth client secret (or set
                         MCP_CLIENT_SECRET env var)
```

### Known unknown: RFC 8707 `resource` and Google

MCP clients that follow the 2025-06-18+ authorization spec send the RFC 8707
`resource` parameter (here `https://mcp.example.com/mcp`) in the authorization
and token requests. Google does not document support for `resource`. It
might:

- ignore it (expected, and fine: the server checks `aud` against your
  client ID, not against `resource`), or
- reject the request with `invalid_request`.

Related: Google publishes its metadata at
`/.well-known/openid-configuration`, not at
`/.well-known/oauth-authorization-server`. Spec-compliant clients try both, but
an older client may not.

**This has not been verified end-to-end with a real Google client.** Before you
roll google mode out, sign in once with Claude Code against a staging
deployment. If Google rejects the authorization or token request, use token
mode instead. Please report the result so this section can be updated.
