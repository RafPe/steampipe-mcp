# Remote deployment

This guide covers running the Steampipe MCP server over Streamable HTTP for
clients on other machines, with authentication. For local use, stdio (the
default) needs none of this.

The server supports three auth modes:

| Mode | `STEAMPIPE_MCP_AUTH_MODE` | Who can connect | Setup cost |
|------|---------------------------|-----------------|------------|
| Static token | `token` | Anyone holding one shared secret | Low |
| Google OAuth | `google` | Allowlisted Google accounts, each signing in as themselves | Google Cloud OAuth client |
| JWT access tokens | `jwt` | Anyone your OAuth/OIDC issuer mints an RFC 9068 access token for this server, narrowed by an optional identity policy | An issuer that mints RFC 9068 JWT access tokens (`typ: at+jwt`, with `client_id` and `jti`); see [Issuer requirements](#issuer-requirements) |

`none` is the default and is only accepted on a loopback bind, unless you set
`STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE=true`.

## Threat model

**What is protected:** the MCP endpoint (`POST {STEAMPIPE_MCP_HTTP_PATH}`,
default `/mcp`). Every tool, prompt and resource is reached through it, and the
tools run arbitrary read-only SQL against Steampipe with the server's own
database credentials.

**Read this first: every authenticated principal gets full access.** No
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
  domain in `STEAMPIPE_MCP_ALLOWED_DOMAINS`, gets `403 access_denied` (with no
  `WWW-Authenticate` challenge, so clients do not retry with more scopes) and
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
- *Issuer trust* (jwt mode). Every token your issuer signs for this server's
  audience is accepted, unless the [identity policy](#identity-policy-jwt-mode)
  refuses it. That policy (`STEAMPIPE_MCP_REQUIRED_CLAIMS`,
  `STEAMPIPE_MCP_ALLOWED_SUBJECTS`, `STEAMPIPE_MCP_SUBJECT_PREFIXES`, or an
  issuer's own `requiredClaims`/`allowedSubjects`/`subjectPrefixes`) is the
  per-principal control in jwt mode; scopes are not checked. Also restrict who
  can obtain such tokens at the issuer. Tokens are verified locally, so a token
  revoked at the issuer keeps working until its `exp`.
- *Google availability* (google mode). If tokeninfo is unreachable, slower
  than 5 seconds, answers `429`/`5xx` or a redirect, or sends a body over
  64 KiB, requests fail closed with `503` `temporarily_unavailable` and
  `Retry-After: 5`. They are never accepted.
  The server also refuses to start if it cannot fetch Google's discovery
  document, unless `STEAMPIPE_MCP_ALLOW_DEGRADED_START=true`. Then it starts
  anyway and retries discovery in the background; until that succeeds the
  Protected Resource Metadata answers `503` with `Retry-After: 5` and
  `/readyz` reports `"auth":"pending"`, while bearer tokens are still
  verified.

The unauthenticated endpoints that never touch the database are
`GET /healthz` (static `{"status":"ok"}`), `GET`/`DELETE /mcp` (always
`405`), and in google and jwt mode the public metadata under `/.well-known/`
(see below).

`GET /readyz` is also unauthenticated, and it **does** connect to the
database: its `db` check opens a dedicated, short-lived connection (never a
pooled one) and runs `select 1`. Like `/healthz` it is exempt from Host and
Origin validation, so Kubernetes probes work, and it is not rate limited.
Concurrent probes share one in-flight evaluation and its result is reused
for 1 s, so a flood of probes does not multiply database connections: a new
evaluation starts at most once per second after the previous one finishes.
Connect and query together are bounded by 2 s and cleanup by another 2 s,
and timeout parameters in the database URL cannot extend that.
The response carries check names and statuses only. If you do not want it
reachable from outside, block `/readyz` at your proxy and probe it from
inside the cluster.

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
does not reveal its content or length. In token mode a request with no
`Authorization: Bearer` header gets `401` with a bare `WWW-Authenticate: Bearer`
(RFC 6750 §3.1: no error code when no credentials were sent), and a wrong token
gets `WWW-Authenticate: Bearer error="invalid_token", error_description="Invalid token"`.
Neither carries `resource_metadata` or `scope`: there is no OAuth server to
discover, so the client simply needs the header above.

This is also the fallback if google mode does not work with your client (see
[Known unknown](#known-unknown-rfc-8707-resource-and-google) below).

## Option 2: Google OAuth

In this mode the server is an OAuth 2.0 *resource server*. Google is the
authorization server. The MCP client signs the user in with Google, gets a
Google access token, and sends it as a bearer token. The server checks each
token against Google's tokeninfo endpoint, then applies the email
allowlist, then the identity policy if one is configured.

Two Google constraints shape the setup:

- **No dynamic client registration.** MCP clients cannot register themselves
  with Google, so you create an OAuth client once and give its credentials to
  each user's MCP client.
- **Opaque access tokens and no custom scopes.** Tokens are validated online
  through tokeninfo. Authorization is by the email/domain allowlist plus,
  optionally, a declarative identity policy on the tokeninfo fields
  (`STEAMPIPE_MCP_REQUIRED_CLAIMS`, `STEAMPIPE_MCP_ALLOWED_SUBJECTS`,
  `STEAMPIPE_MCP_SUBJECT_PREFIXES`; see the README). There are no OAuth
  scopes to check.

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
`https://accounts.google.com/.well-known/openid-configuration`. With degraded
start disabled (the default, `STEAMPIPE_MCP_ALLOW_DEGRADED_START=false`) it
refuses to start if that fails or names any issuer other than
`https://accounts.google.com`. With degraded start enabled it starts anyway
and keeps retrying in the background; until a fetch succeeds, the metadata
below answers `503` with `Retry-After: 5` (see *Google availability* above).
Once running it serves:

- `GET /.well-known/oauth-protected-resource/mcp` (and `HEAD`): RFC 9728
  Protected Resource Metadata. `resource` is your `PUBLIC_URL` in canonical
  form (a bare origin gains a trailing `/`; see the README),
  `authorization_servers` is `["https://accounts.google.com"]`,
  `scopes_supported` is `["openid","email"]`, and `bearer_methods_supported`
  is `["header"]`. It is served with `Cache-Control: max-age=300`; any other
  method gets `405`.

The server does not mirror Google's metadata at
`/.well-known/oauth-authorization-server`: clients fetch it from Google, the
server named in `authorization_servers`.

This endpoint is public, but still subject to Host and Origin validation. An
unauthenticated `POST /mcp` gets:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="openid email"
```

A rejected token gets the same challenge with `error="invalid_token"` and an
`error_description` in front. Challenge values are reduced to the RFC 6750
character set (no quotes, backslashes, control characters or non-ASCII) and
`error_description` is capped at 200 characters.

How each token is validated:

1. POST `access_token=<token>` (form body) to
   `https://oauth2.googleapis.com/tokeninfo`, with a 5s timeout covering
   headers and body. Like the startup discovery fetch, this goes through a
   restricted fetch: https to `oauth2.googleapis.com` or `accounts.google.com`
   only, redirects never followed, bodies capped at 64 KiB. This restricts
   which URLs the identity-provider calls may reach; it is not general SSRF
   protection. Hostnames are not resolved and checked against private or
   internal address ranges (no DNS or private-address filtering), so if an
   allowlisted name resolved to an internal address, that address would be
   reached. Its trust boundary is the hostname allowlist and your DNS.
2. A network error, a timeout, a `429`/`5xx` answer, any redirect, or a body
   over 64 KiB → `503 temporarily_unavailable` with `Retry-After: 5`.
3. Any other non-200 response, a body that is not a JSON object, `aud`
   different from `GOOGLE_CLIENT_ID` (`azp` is not consulted), or `exp`
   missing or in the past → `401 invalid_token`.
4. `email_verified` not `"true"`, an email that is neither allowlisted nor in
   an allowlisted domain, or a domain-only match where `hd` is present and
   differs from the email's domain → `403 access_denied`, with no
   `WWW-Authenticate` challenge.
5. If an identity policy is configured (`REQUIRED_CLAIMS`, `ALLOWED_SUBJECTS`,
   `SUBJECT_PREFIXES`) and the tokeninfo fields do not satisfy it →
   `403 access_denied`, with no `WWW-Authenticate` challenge. The policy runs
   only after the allowlist has passed; both must pass.
6. Otherwise accept. The result is cached for at most 60 seconds, keyed by the
   token's sha256. Only accepted results are cached.

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
`/.well-known/oauth-authorization-server`, and this server no longer mirrors
it on the resource host. Spec-compliant clients try both on Google's host, but
an older client that only looks for `oauth-authorization-server` metadata (on
either host) will not find any.

**This has not been verified end-to-end with a real Google client.** Before you
roll google mode out, sign in once with Claude Code against a staging
deployment. If Google rejects the authorization or token request, use token
mode instead. Please report the result so this section can be updated.

## Option 3: JWT access tokens

For an OAuth 2.0 / OIDC issuer that signs access tokens as JWTs. Tokens follow
the RFC 9068 profile and are verified locally against the issuer's JWKS, with
no call to the issuer per request.

```sh
STEAMPIPE_MCP_AUTH_MODE=jwt
STEAMPIPE_MCP_PUBLIC_URL=https://mcp.example.com/mcp
STEAMPIPE_MCP_JWT_ISSUER=https://idp.example.com/realms/platform
# Optional:
# STEAMPIPE_MCP_JWT_AUDIENCES=https://mcp.example.com/mcp   # default: PUBLIC_URL
# STEAMPIPE_MCP_JWT_ALGORITHMS=RS256,ES256
# STEAMPIPE_MCP_JWT_ACCEPTED_TYP=at+jwt,application/at+jwt
# STEAMPIPE_MCP_JWT_CLOCK_SKEW_S=0          # 0 to 300
# STEAMPIPE_MCP_JWT_MAX_TOKEN_AGE_S=0
# STEAMPIPE_MCP_JWT_JWKS_COOLDOWN_S=30
# STEAMPIPE_MCP_JWT_SCOPES_SUPPORTED=      # advertised only, never required
# STEAMPIPE_MCP_JWT_CHALLENGE_SCOPE=        # advertised only, never required
# STEAMPIPE_MCP_JWT_ALLOWED_HOSTS=        # extra https hosts for the JWKS
```

At startup the server fetches the issuer's metadata from
`<issuer>/.well-known/openid-configuration`, then from the RFC 8414 location
(`https://idp.example.com/.well-known/oauth-authorization-server/realms/platform`).
The document's `issuer` must equal `STEAMPIPE_MCP_JWT_ISSUER` exactly, and its
`jwks_uri` must be on the issuer's host or in `STEAMPIPE_MCP_JWT_ALLOWED_HOSTS`
and use https. Plain http is accepted only when the issuer itself is a
loopback http URL (local development). Otherwise the server refuses to start. Only `issuer` and
`jwks_uri` are read, so machine-to-machine issuers work too. Discovery and JWKS
fetches use the same restricted fetch as Google mode: no redirects, 64 KiB
bodies, 5 s timeouts.

### Issuer requirements

The issuer must mint **RFC 9068 JWT access tokens**. Concretely, every access
token it issues for this server must have:

- header `typ` `at+jwt` (or `application/at+jwt`), unless
  `STEAMPIPE_MCP_JWT_ACCEPTED_TYP` widens it;
- the claims `iss`, `aud`, `exp`, `iat`, `sub`, `client_id` and `jti`.

This profile is strict and is not configurable per claim.
`STEAMPIPE_MCP_JWT_ACCEPTED_TYP` widens the `typ` check only: a token without
`client_id` or `jti` is rejected as `malformed` (`401`) whatever `typ` it
carries, including a token that names its client in another claim (such as
`azp`) or carries its ID under another name. ID tokens and other generic JWTs
are rejected too. This guide names no identity provider as compatible: check
your issuer's documented access-token header and claim set against the list
above before you rely on it, and test with a real token.

### Token checks

A token is accepted only if all of these hold:

- its header `typ` is in `STEAMPIPE_MCP_JWT_ACCEPTED_TYP` (case-insensitive).
  The default, `at+jwt`, keeps ID tokens and other generic JWTs out. Add `JWT`
  only for issuers that put `typ: "JWT"` on otherwise RFC 9068 access tokens:
  it widens the `typ` check only, and the claims below are still required.
  A token with no `typ` at all is always rejected.
- its `alg` is in `STEAMPIPE_MCP_JWT_ALGORITHMS`. `none` and `HS*` are refused
  at startup, so neither `alg:none` nor an HMAC key made from the public key
  works.
- the signature verifies against a key in the issuer's JWKS.
- `iss` equals the issuer and `aud` contains one of the audiences, both
  compared as exact strings.
- `exp` is in the future and `nbf`, if present, is not, each with
  `STEAMPIPE_MCP_JWT_CLOCK_SKEW_S` of leeway (0 to 300 s) and no more. `iat` is no older
  than `STEAMPIPE_MCP_JWT_MAX_TOKEN_AGE_S`, when that is set.
- the RFC 9068 §2.2 claims `exp`, `iat`, `jti`, `client_id` and `sub` are
  present, with `sub` a string of 1 to 256 characters.

A rejected token gets `401` with `error="invalid_token"`. If the JWKS cannot
be fetched, requests get `503` with `Retry-After: 5`. After a failed JWKS fetch
(a connection error, a timeout, a non-`200` answer, or a `200` that is not a
JSON key set) the server backs off for that issuer: for 1 s, doubling after each
further failure up to 60 s, requests that would need a JWKS fetch get `503` at
once without contacting the issuer, then the next such request tries again. A
successful fetch ends the backoff. Tokens whose key is cached are not affected
while the cached JWKS is fresh (10 minutes after the last successful fetch);
once it is stale, every request needs a refetch and gets `503` until the JWKS
is back. Each backoff window logs one warning with the issuer's origin (never
its path), the consecutive failure count, the next delay and the cause, and the
first successful fetch after failures logs one info line (see Logging in the
README).

**Key rotation.** The JWKS is cached. A token whose `kid` is not in the cache
triggers a refetch, at most once per `STEAMPIPE_MCP_JWT_JWKS_COOLDOWN_S`
(default 30 s). So a key your issuer starts signing with is accepted within
that time; until then its tokens get `401`. Publish new keys in the JWKS before
signing with them.

The server serves Protected Resource Metadata at
`/.well-known/oauth-protected-resource/<path>`, with `resource` set to the
canonical `STEAMPIPE_MCP_PUBLIC_URL` and `authorization_servers` set to
`[STEAMPIPE_MCP_JWT_ISSUER]` exactly as written. Audit lines carry the
token's `iss`, and the per-principal rate limit keys on `iss|sub`, so the same
`sub` from different issuers never shares a quota. An issuer identifier must
therefore not contain `|`; the server refuses to start if one does. An
`auth_reject` line carries `iss` (the configured issuer) once the token has been
routed to an issuer, and none when its `iss` is missing or unconfigured.

### Several issuers

To trust more than one issuer behind the same header, set
`STEAMPIPE_MCP_JWT_ISSUERS` instead of `STEAMPIPE_MCP_JWT_ISSUER`:

```sh
STEAMPIPE_MCP_JWT_ISSUERS='[
  {"issuer": "https://idp.example.com/realms/platform"},
  {"issuer": "https://login.example.net/tenant-1",
   "audiences": ["api://steampipe-mcp"], "advertise": false,
   "requiredClaims": {"client_id": ["reporting-job"]}}
]'
```

Each entry accepts `issuer` (required), `audiences`, `algorithms`,
`acceptedTyp`, `clockSkewS` (0 to 300), `maxTokenAgeS`, `advertise`,
`requiredClaims`, `allowedSubjects` and `subjectPrefixes`. A missing
`audiences`, `algorithms`, `acceptedTyp`, `clockSkewS` or `maxTokenAgeS` takes
the matching single-issuer variable, and `issuer` follows the
`STEAMPIPE_MCP_JWT_ISSUER` rules (`|` included). Every issuer must meet the
[issuer requirements](#issuer-requirements).

`requiredClaims`, `allowedSubjects` and `subjectPrefixes` take the same form
and limits as `STEAMPIPE_MCP_REQUIRED_CLAIMS`, `STEAMPIPE_MCP_ALLOWED_SUBJECTS`
and `STEAMPIPE_MCP_SUBJECT_PREFIXES`, and give that issuer its own identity
policy. It **replaces** the global policy for that issuer as a whole and is
never merged with it: a policy field the entry leaves out is empty, not
inherited from the global variables. In the example above, tokens from
`login.example.net/tenant-1` must have `client_id` `reporting-job` and are not
checked against the global policy at all, while the first issuer stays on the
global policy. An entry with none of the three fields uses the global policy.
An entry whose policy fields set no rules (for example `"requiredClaims": {}`)
is a startup error, since it would silently switch the global policy off for
that issuer; to leave an issuer unrestricted, leave the global policy empty
instead.

The server reads the token's `iss` without verifying it, only to pick the entry whose `issuer` matches exactly;
the token is then verified with that issuer's JWKS and settings alone, so a
token claiming one issuer but signed by another fails its signature check. A
token whose `iss` matches no entry is refused (`401`) without any network call.
Every issuer is discovered at startup, each with its own fetch policy (its own
host plus `STEAMPIPE_MCP_JWT_ALLOWED_HOSTS`), and the server refuses to start if
any discovery fails, unless `STEAMPIPE_MCP_ALLOW_DEGRADED_START=true`. Then it
starts anyway and retries each failed issuer's discovery in the background (1 s
doubling to 60 s, ±20% jitter). Until an issuer has been discovered, its tokens
get `503` with `Retry-After: 5`, it is left out of `authorization_servers` (the
metadata answers `503` while no advertised issuer has been discovered), and
`/readyz` reports `"auth:<n>":"pending"`; the other issuers are served
meanwhile. `<n>` is the issuer's 1-based position in the array (`auth:1` is the
first entry), never its URL, so the unauthenticated `/readyz` does not reveal
`"advertise": false` issuers. With the flag on, `/readyz` has one `auth:<n>`
entry per configured issuer instead of the single `auth` entry. `authorization_servers` lists the entries with
`"advertise": true` (the default), in array order, so an issuer used only by
machine clients can stay unlisted; at least one entry must be advertised.

### Identity policy (jwt mode)

Without a policy, every valid token for this server's audience is accepted. To
narrow that, set `STEAMPIPE_MCP_REQUIRED_CLAIMS`,
`STEAMPIPE_MCP_ALLOWED_SUBJECTS` and `STEAMPIPE_MCP_SUBJECT_PREFIXES` (see the
README for their form and limits). The policy is checked after every other
token check, against the verified token payload, with `sub` as the subject. A
token that fails it gets `403 access_denied` with no `WWW-Authenticate`
challenge. A `STEAMPIPE_MCP_JWT_ISSUERS` entry can replace it for one issuer
(see [Several issuers](#several-issuers)).

```sh
STEAMPIPE_MCP_REQUIRED_CLAIMS='{"client_id":["claude-code","reporting-job"]}'
STEAMPIPE_MCP_SUBJECT_PREFIXES='["svc-"]'
```

**Scopes are advertised only; a token is not required to carry them. Use the
identity policy to restrict who is accepted.** `STEAMPIPE_MCP_JWT_SCOPES_SUPPORTED`
only fills `scopes_supported` in the Protected Resource Metadata, and
`STEAMPIPE_MCP_JWT_CHALLENGE_SCOPE` only adds `scope` to `401` challenges. To
require a scope, use `REQUIRED_CLAIMS`, but note that it compares the token's
whole `scope` string: `{"scope":["mcp.read"]}` matches a token whose `scope` is
exactly `mcp.read`, not one with `mcp.read mcp.write`.
