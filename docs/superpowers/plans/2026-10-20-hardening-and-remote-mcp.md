# steampipe-mcp: Hardening + Remote MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the RafPe fork of steampipe-mcp safe on stdio and ship it as a Docker image (`ghcr.io/rafpe/steampipe-mcp`) that runs as an authenticated remote MCP server over Streamable HTTP, for a single trusted group (the platform team) against one Steampipe backend. **Definition of done:** the fork's `main` holds this work, and a tagged image is published to GHCR and smoke-tested as a remote MCP.

**Architecture:** Five stacked PRs. (1) The query path enforces read-only, bounded execution. (2) The SDK is bumped and server construction becomes a factory. (3) A stateless Streamable HTTP front end builds one `Server` per request, with Origin/Host checks. (4) An auth layer: a static bearer token, or Google OAuth access tokens verified through Google's tokeninfo endpoint, with an email/domain allowlist. Clients use a pre-registered Google OAuth client, because Google supports neither DCR nor custom scopes. (5) A Docker image plus a GHCR release workflow. (6) 2026-07-28 readiness, which waits on SDK support. The default transport stays `stdio`, so existing users see no change. Per-user/per-team data access is **out of scope** (see Deferred). Who may connect is controlled by the server's allowlist (`ALLOWED_EMAILS` / `ALLOWED_DOMAINS`) in Google mode, and by possession of the token in token mode. Nothing is ever sent to the upstream repo (turbot/steampipe-mcp). All PRs target `RafPe/steampipe-mcp` explicitly with `--repo RafPe/steampipe-mcp`.

**Tech Stack:** TypeScript (ESM), Node ≥18, `@modelcontextprotocol/sdk` 1.32.1 (brings `express` 5, `jose`, `express-rate-limit`), `pg` 8.23.1 + `pg-cursor` 2.22.1, `vitest` for tests, Postgres 16 in CI as a stand-in for Steampipe.

**Spec:** MCP 2025-11-25 (target; the latest SDK `LATEST_PROTOCOL_VERSION`) plus forward-compat notes from 2026-07-28:
- https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- Upstream issues turbot/steampipe-mcp#5 (Streamable HTTP) and #6 (multi-user).

## Global Constraints

- Pin every dependency to a full clean semver with no `^`/`~`, e.g. `"@modelcontextprotocol/sdk": "1.32.1"`.
- Defaults for existing stdio users stay the same, with one exception. `STEAMPIPE_MCP_TRANSPORT` defaults to `stdio`, `argv[2]` remains the connection string, the default DB is `postgresql://steampipe@localhost:9193/steampipe`, and stdio has no row cap (`maxRows` 0 means unlimited). The exception is TLS: certificates are now verified for non-loopback DBs that set no `sslmode`. This is a security-default change and must be recorded in CHANGELOG under **Breaking / security defaults** (Task 2).
- All config is env vars prefixed `STEAMPIPE_MCP_`, parsed in one place (`src/config.ts`).
- Logs go to stderr only (existing `logger`). Never log access tokens, DB passwords, or full connection strings.
- The HTTP server binds to `127.0.0.1` by default. Startup refuses a non-loopback bind with `auth.mode=none` unless `STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE=true`.
- An invalid `Origin` gets **403**. A missing/invalid token gets **401** with `WWW-Authenticate: Bearer resource_metadata="…"`. Insufficient scope gets **403** with `error="insufficient_scope"`.
- No token passthrough: client tokens are never forwarded to Postgres/Steampipe/Pipes. DB credentials come only from server config.
- There are no custom scopes, because Google cannot issue them. Every allowlisted principal gets full access to all tools. PRM `scopes_supported` is `["openid","email"]`.
- Image tags and release tags are clean semver without a `v` prefix (`0.2.0`). The base image and every GitHub Action are pinned to an exact version.

## Review Focus

1. **JSON-RPC batch (array) body over HTTP.** The request must get `400`. Test is in Task 7.
2. **`Origin: null`** (sandboxed iframe, `file://`). It must get `403` unless `null` is explicitly in the allowlist. Test is in Task 5.
3. **Valid Google access token issued to a different OAuth client** (`aud`/`azp` ≠ our `GOOGLE_CLIENT_ID`). It must get `401 invalid_token`, never be accepted. Test is in Task 6.
4. **Valid token for our client, but the email is not allowlisted or `email_verified` is false.** It must get `403` and never reach the tools. Test is in Task 6.
5. **Steampipe restarted mid-session** (backends terminated). The next call must reconnect and succeed, and the refactors must not break this. Test is in Task 1.

## Stacked PR / branch layout

| PR | Branch | Tasks | Closes |
|---|---|---|---|
| 0 | `chore/test-harness` | 0 | — |
| 1 | `fix/query-safety` | 1, 2 | — |
| 2 | `chore/sdk-1.32` | 3 | supersedes dependabot #11–#14 |
| 3 | `feat/http-transport` | 4, 5 | #5 |
| 4 | `feat/auth` | 6, 7 | — |
| 5 | `feat/docker-release` | 9 | — |
| — | `feat/spec-2026-07-28` | 8 (gated, not in this run) | — |

---

### Task 0: Fork wiring, test harness, CI

**Files:**
- Modify: `package.json` (scripts `test`, `test:db`; devDeps `vitest` 5.0.5 pinned)
- Create: `vitest.config.ts`, `test/helpers/db.ts`, `test/smoke.test.ts`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `testDbUrl(): string | undefined` (reads `TEST_DATABASE_URL`). `describeDb` is a `describe.skipIf(!testDbUrl())` alias that every later DB test uses.

- [ ] **Step 1:** Run `git remote rename origin upstream && git remote add origin https://github.com/RafPe/steampipe-mcp.git && git fetch --all`. Expected: `git remote -v` lists `origin` = RafPe and `upstream` = turbot.
- [ ] **Step 2:** Add vitest and `test/smoke.test.ts` asserting `1 + 1 === 2`. Run `npm test`. Expected: 1 passed.
- [ ] **Step 3:** Add CI using marketplace actions only: `actions/checkout@v4`, `actions/setup-node@v4` (node 20, npm cache), and a `services: postgres:16` container with `TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres`. The job runs `npm ci && npm run build && npm test` plus an `npm audit --omit=dev --audit-level=high` step that may fail until PR 2 (`continue-on-error: true`, removed in Task 3).
- [ ] **Step 4:** Commit with `chore: add vitest harness and CI`.

### Task 1: Read-only, bounded query execution

**Files:**
- Modify: `src/services/database.ts` (constructor, pool config, `executeQuery`, new `executeUserQuery`)
- Modify: `src/tools/steampipe_query.ts` (use `executeUserQuery`, return `truncated`)
- Modify: `src/index.ts` (construct `DatabaseService` instead of `getInstance()`)
- Modify: `package.json` (`pg` 8.23.1, add `pg-cursor` 2.22.1 + `@types/pg-cursor` 2.7.2)
- Test: `test/database.test.ts`

**Interfaces:**
- Produces:
  - `interface DatabaseOptions { connectionString: string; maxRows: number; statementTimeoutMs: number; poolMax: number; exposeConnectionDetails: boolean }`
  - `new DatabaseService(opts: DatabaseOptions)`. `getInstance()` and `setConfig()` are removed.
  - `executeQuery(sql: string, params: unknown[]): Promise<any[]>` is unchanged for internal parameterised queries.
  - `executeUserQuery(sql: string): Promise<{ rows: any[]; truncated: boolean }>`
  - `get safeConnectionString(): string` (password masked).
  - `steampipe_query` result text is `JSON.stringify({ rows, truncated })` when truncated. Otherwise it stays `JSON.stringify(rows)`, so existing clients keep working.
  - Defaults: `maxRows` 0 = unlimited on stdio and 10000 on HTTP (`STEAMPIPE_MCP_MAX_ROWS`), `statementTimeoutMs` 120000, `poolMax` 20.

- [ ] **Step 1: Write the failing tests** in `test/database.test.ts`, under `describeDb`, with `poolMax: 1` so state leaks would show:
  - `rejects multi-statement escape`: `executeUserQuery("COMMIT; CREATE TABLE pwned(x int)")` rejects with `/multiple commands/`, and afterwards `executeQuery("select to_regclass('pwned') as t", [])` returns `[{ t: null }]`.
  - `rejects writes`: `executeUserQuery("CREATE TABLE pwned2(x int)")` rejects with `/read-only transaction/`.
  - `does not leak session state`: `executeUserQuery("select set_config('search_path','evil',false)")`, then `executeUserQuery("show search_path")`. `rows[0].search_path` is not `'evil'`.
  - `applies statement timeout on every pooled connection`: build with `statementTimeoutMs: 200, poolMax: 3`. Three concurrent `executeUserQuery("select pg_sleep(1)")` calls all reject with `/statement timeout/`.
  - `caps rows`: `maxRows: 10`. `executeUserQuery("select generate_series(1,50) g")` returns 10 rows with `truncated: true`. `generate_series(1,5)` returns `truncated: false`.
  - `reconnects after backend termination` (Review Focus 5): a second superuser client runs `select pg_terminate_backend(pid) from pg_stat_activity where application_name='steampipe-mcp'`. The next `executeUserQuery("select 1 as x")` resolves `[{x:1}]`.
- [ ] **Step 2:** Run `TEST_DATABASE_URL=… npx vitest run test/database.test.ts`. Expected: FAIL (constructor is private / `executeUserQuery` is not a function).
- [ ] **Step 3: Implement.**
  - The pool config sets `statement_timeout: opts.statementTimeoutMs`, `idle_in_transaction_session_timeout: opts.statementTimeoutMs`, `application_name: 'steampipe-mcp'` and `max: opts.poolMax`. Delete the one-off `SET statement_timeout`.
  - `executeUserQuery` uses `pg-cursor` (extended protocol, so multi-statement is rejected) inside `BEGIN TRANSACTION READ ONLY` and reads `maxRows + 1` rows to compute `truncated`.
  - Both execute paths run `DISCARD ALL` after `COMMIT`/`ROLLBACK` and before `release()`. If `DISCARD ALL` throws, release with `client.release(err)` so the connection is destroyed.
  - Error messages include `safeConnectionString` only when `exposeConnectionDetails` is true. Otherwise they say `the configured Steampipe database`.
- [ ] **Step 4:** Run the same command. Expected: all PASS. Run `npm run build` too. Expected: exit 0.
- [ ] **Step 5: Manual check against real Steampipe**, because CI uses plain Postgres. Run `steampipe service start` with any plugin (e.g. `net`). Build a `DatabaseService` with `poolMax: 1`. Run an unqualified `select * from net_dns_record where domain='example.com' limit 1` twice in a row. Expected: both succeed, which shows the role's `search_path` survives `DISCARD ALL` and `pg-cursor` works over the FDW.
- [ ] **Step 6:** Commit with `fix: enforce read-only single-statement queries, per-connection timeout, row cap`.

### Task 2: TLS defaults and status redaction

**Files:**
- Create: `src/services/ssl.ts`
- Modify: `src/services/database.ts` (use `buildPoolConfig`), `src/resources/status.ts`, `CHANGELOG.md`
- Test: `test/ssl.test.ts`, `test/status.test.ts`

**Interfaces:**
- Produces:
  - `resolveSsl(url: URL): false | undefined | { rejectUnauthorized: boolean }`
  - `buildPoolConfig(opts: DatabaseOptions): PoolConfig`. It strips `sslmode` from the connection string it passes on. node-postgres lets a URL `sslmode` override the `ssl` object, so leaving it in would bypass `resolveSsl`.

- [ ] **Step 1: Write failing tests.** Table test for `resolveSsl`:

  | URL | Expected |
  |---|---|
  | `postgresql://u@localhost:9193/d` | `{rejectUnauthorized:false}` |
  | `…@127.0.0.1…` | `{rejectUnauthorized:false}` |
  | `…@db.example.com…` (no sslmode) | `{rejectUnauthorized:true}` |
  | `?sslmode=disable` | `false` |
  | `?sslmode=no-verify` | `{rejectUnauthorized:false}` |
  | `?sslmode=require` / `verify-ca` / `verify-full` | `{rejectUnauthorized:true}` |
  | `?sslmode=prefer` / `allow` | `undefined` |

  `buildPoolConfig` test: for `…@db.example.com/d?sslmode=no-verify`, `cfg.connectionString` has no `sslmode` and `cfg.ssl` is `{rejectUnauthorized:false}`.
  `status.test.ts`: the handler with a db whose connection string is `postgresql://u:s3cret@h/d` returns text that does not contain `s3cret`.
- [ ] **Step 2:** Run `npx vitest run test/ssl.test.ts test/status.test.ts`. Expected: FAIL.
- [ ] **Step 3:** Implement `resolveSsl`, where loopback means `localhost`, `127.0.0.0/8` or `::1`. `status.ts` returns `connection_string: db.safeConnectionString` when `exposeConnectionDetails`, and omits the field otherwise.
- [ ] **Step 4:** Rerun the tests. Expected: PASS.
- [ ] **Step 5:** Add a CHANGELOG entry under **Breaking / security defaults**: remote DBs without `sslmode` now verify certificates, and `?sslmode=no-verify` restores the old behaviour. Commit with `fix: verify TLS for remote databases by default, redact status`.

### Task 3: SDK 1.32.1 + server factory

**Files:**
- Modify: `package.json`, `package-lock.json`
- Create: `src/server.ts`
- Modify: `src/index.ts` (stdio path only calls `createServer`), `src/tools/index.ts` (compile Ajv validators once at module load)
- Test: `test/server.test.ts`

**Interfaces:**
- Produces: `createServer(db: DatabaseService): Server`. It registers tools/prompts/resources/templates with capabilities `{ tools: {}, prompts: {}, resources: {} }`, which is spec-shaped. That replaces the current handler-carrying `tools` map and the non-spec `resourceTemplates` key.

- [ ] **Step 1:** `test/server.test.ts`: link `createServer(fakeDb)` to a `Client` via `InMemoryTransport.createLinkedPair()`. `client.listTools()` returns the 5 tool names. `client.getServerCapabilities()` has keys `tools,prompts,resources` only.
- [ ] **Step 2:** Run it. Expected: FAIL (`createServer` not found).
- [ ] **Step 3:** Pin `@modelcontextprotocol/sdk` 1.32.1 and `ajv` 8.18.0, then run `npm install`. Move the server construction out of `startServer` into `createServer`.
- [ ] **Step 4:** Run `npm run build && npm test && npm audit --omit=dev --audit-level=high`. Expected: all exit 0. Remove `continue-on-error` from CI.
- [ ] **Step 5:** Smoke-test stdio: `printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' | node dist/index.js` prints a result with `"protocolVersion":"2025-11-25"`.
- [ ] **Step 6:** Commit with `chore: bump MCP SDK to 1.32.1, spec-shaped capabilities, server factory`. Close dependabot #11–#14 on the fork with a link to the commit.

### Task 4: Central config

**Files:**
- Create: `src/config.ts`
- Test: `test/config.test.ts`

**Interfaces:**
- Produces: `loadConfig(env: NodeJS.ProcessEnv, argv: string[]): ServerConfig` (throws `ConfigError`) and:
  ```ts
  interface ServerConfig {
    transport: 'stdio' | 'http';
    db: Omit<DatabaseOptions, 'connectionString' | 'exposeConnectionDetails'> & { connectionString: string };
    http: { host: string; port: number; path: string; publicUrl?: URL;
            allowedOrigins: string[]; allowedHosts: string[]; maxBodyBytes: number; rateLimitPerMin: number };
    auth: { mode: 'none' | 'token' | 'google'; token?: string; googleClientId?: string; allowedEmails: string[]; allowedDomains: string[] };
    allowInsecureRemote: boolean;
  }
  ```
  Env names and defaults:

  | Env var | Default |
  |---|---|
  | `TRANSPORT` | `stdio` |
  | `HTTP_HOST` | `127.0.0.1` |
  | `HTTP_PORT` | `27123` |
  | `HTTP_PATH` | `/mcp` |
  | `PUBLIC_URL` | — |
  | `ALLOWED_ORIGINS` | csv, empty |
  | `ALLOWED_HOSTS` | csv, empty |
  | `MAX_BODY_BYTES` | `1048576` |
  | `RATE_LIMIT_PER_MIN` | `60` |
  | `AUTH_MODE` | `none` |
  | `AUTH_TOKEN` | — |
  | `GOOGLE_CLIENT_ID` | — |
  | `ALLOWED_EMAILS` | csv, empty, lower-cased |
  | `ALLOWED_DOMAINS` | csv, empty, lower-cased |
  | `MAX_ROWS` | `0` (unlimited) on stdio, `10000` on http |
  | `STATEMENT_TIMEOUT_MS` | `120000` |
  | `ALLOW_INSECURE_REMOTE` | `false` |
  | `TRUST_PROXY` | unset |

  All of these carry the `STEAMPIPE_MCP_` prefix. The connection string comes from `argv[2]`, then `STEAMPIPE_MCP_WORKSPACE_DATABASE`, then the default.

- [ ] **Step 1: Failing tests:**
  - empty env gives `transport:'stdio'` and the default connection string;
  - `HTTP_HOST=0.0.0.0` + `AUTH_MODE=none` throws `/ALLOW_INSECURE_REMOTE/`;
  - `AUTH_MODE=token` with a token shorter than 32 chars throws;
  - `AUTH_MODE=google` without `PUBLIC_URL` or `GOOGLE_CLIENT_ID` throws, and also throws when both `ALLOWED_EMAILS` and `ALLOWED_DOMAINS` are empty;
  - `PUBLIC_URL=http://mcp.example.com` (non-loopback http) throws `/https/`;
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement `loadConfig`. Wire `index.ts` to it.
- [ ] **Step 4:** Rerun the tests. Expected: PASS.
- [ ] **Step 5:** Commit with `feat: centralised env config with safe-by-default validation`.

### Task 5: Stateless Streamable HTTP transport

**Files:**
- Create: `src/http/app.ts`, `src/http/origin.ts`
- Modify: `src/index.ts` (branch on `config.transport`)
- Test: `test/http.test.ts`

**Interfaces:**
- Consumes: `createServer(db)`, `ServerConfig`.
- Produces:
  - `originValidation(allowed: string[]): RequestHandler`. An `Origin` header that is present and not exactly in `allowed` gets `403` with body `{"jsonrpc":"2.0","error":{"code":-32000,"message":"Forbidden origin"}}`. A missing `Origin` passes.
  - `buildHttpApp(cfg: ServerConfig, db: DatabaseService, extraMiddleware?: RequestHandler[]): Express`. Task 6 hooks in through `extraMiddleware`. The single `db` is constructed with `exposeConnectionDetails: false` in HTTP mode, and the status resource omits `connection_string`.
  - Routes:
    - `POST {path}`: a new `Server` + `StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true })` per request, closed on `res.on('close')`.
    - `GET`/`DELETE {path}`: `405` with `Allow: POST`.
    - `GET /healthz`: `200 {"status":"ok"}`, no DB call.
  - App base: plain `express()`, then `localhostHostValidation()` on a loopback bind or `hostHeaderValidation(allowedHosts)` otherwise (both from `@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js`), then `express.json({ limit: maxBodyBytes })`. Do **not** use `createMcpExpressApp`: it mounts its own `express.json()`, which would make `MAX_BODY_BYTES` do nothing.

- [ ] **Step 1: Failing tests** (`app.listen(0)` + `fetch`):
  - POST `initialize` then POST `tools/list`, without a session header, returns 5 tools (stateless);
  - `Origin: https://evil.example` gives 403;
  - `Origin: null` gives 403 (Review Focus 2);
  - allowed origin gives 200;
  - a `Host: evil.example` header on a loopback bind gives 403;
  - GET `/mcp` gives 405;
  - with `MAX_BODY_BYTES=2048`, a 4 KB body gives 413 (proves the knob works, not express's 100 kb default);
  - the response never includes an `mcp-session-id` header.
- [ ] **Step 2:** Run `npx vitest run test/http.test.ts`. Expected: FAIL.
- [ ] **Step 3:** Implement. Shutdown closes the HTTP server, then the DB.
- [ ] **Step 4:** Rerun the tests. Expected: PASS. Manual check: run `STEAMPIPE_MCP_TRANSPORT=http node dist/index.js`, then `npx @modelcontextprotocol/inspector` connects to `http://127.0.0.1:27123/mcp` and lists tools. The Inspector in direct browser mode sends an `Origin` header, so either set `STEAMPIPE_MCP_ALLOWED_ORIGINS` to the Inspector's origin or use its proxy mode.
- [ ] **Step 5:** Update the README (HTTP section, env table). Commit with `feat: stateless Streamable HTTP transport with Origin/Host validation (#5)`.

### Task 6: Auth: static token + Google OAuth (token validation, PRM, allowlist)

**Files:**
- Create: `src/auth/verifiers.ts`, `src/auth/google.ts`, `src/auth/index.ts`
- Modify: `src/index.ts` (HTTP startup wires `authMiddleware`)
- Test: `test/auth.test.ts`. It uses an in-test HTTP server that fakes Google's tokeninfo and the discovery document. No real Google calls are made in tests.
- Docs: `docs/remote-deployment.md`, covering:
  - the threat model;
  - Google Cloud setup: OAuth consent screen (Internal if on Workspace), an OAuth client of type *Web application* with the MCP client's loopback redirect URI(s), and the server env;
  - Claude Code client config using pre-registered client credentials;
  - the static-token alternative (`--header "Authorization: Bearer …"`);
  - the warning that every allowlisted principal can query every Steampipe connection;
  - a **known unknown**: whether Google tolerates the RFC 8707 `resource` parameter that MCP clients send. It must be verified manually, and token mode is the fallback.

**Interfaces:**
- Consumes: `buildHttpApp(..., extraMiddleware)` from Task 5, and `ServerConfig.auth` from Task 4.
- Produces:
  - `createStaticTokenVerifier(token: string): OAuthTokenVerifier`. It compares with `crypto.timingSafeEqual` over sha256 digests, so length is not leaked. It returns `{ token, clientId: 'static', scopes: [], extra: { sub: 'static' } }`.
  - `createGoogleVerifier(o: { clientId: string; allowedEmails: string[]; allowedDomains: string[]; publicUrl: URL; tokeninfoUrl?: string; now?: () => number }): OAuthTokenVerifier`.
    - It POSTs `application/x-www-form-urlencoded` `access_token=<token>` to `tokeninfoUrl`, default `https://oauth2.googleapis.com/tokeninfo`. The token never goes in a URL.
    - A non-200 response, `aud !== clientId && azp !== clientId`, or `exp*1000 <= now()` throws `InvalidTokenError`, which gives 401.
    - `email_verified !== 'true'`, or an email that is neither in `allowedEmails` nor has its domain (after the last `@`) in `allowedDomains` (case-insensitive), throws `InsufficientScopeError('principal not allowed')`, which gives 403.
    - It returns `{ token, clientId: azp ?? aud, scopes: (scope ?? '').split(' ').filter(Boolean), expiresAt: Number(exp), resource: publicUrl, extra: { sub, email } }`.
    - It caches positive results keyed by the sha256 hex of the token, for `min(60s, exp - now)`, with a max of 1000 entries (FIFO eviction). Negative results are never cached.
  - `fetchGoogleMetadata(discoveryUrl = 'https://accounts.google.com/.well-known/openid-configuration'): Promise<OAuthMetadata>`. It requires `issuer === 'https://accounts.google.com'`.
  - `authMiddleware(cfg: ServerConfig): Promise<RequestHandler[]>`.
    - `none` returns `[]`.
    - `token` returns `[requireBearerAuth({ verifier: createStaticTokenVerifier(token) })]`.
    - `google` returns `[mcpAuthMetadataRouter({ oauthMetadata, resourceServerUrl: publicUrl, scopesSupported: ['openid','email'], resourceName: 'Steampipe MCP' }), requireBearerAuth({ verifier, expectedResource: publicUrl, resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(publicUrl) })]`.
    - Startup fails fast if metadata fetch fails.

- [ ] **Step 1: Failing tests:**
  - token mode:
    - no `Authorization` gives 401;
    - wrong token gives 401;
    - right token gives 200;
    - `?access_token=<right token>` in the query string with no header gives 401.
  - google mode:
    - no `Authorization` gives 401, with `WWW-Authenticate` containing `resource_metadata="…/.well-known/oauth-protected-resource/mcp"`;
    - GET that PRM URL returns `resource` = publicUrl and `authorization_servers` = `["https://accounts.google.com"]`;
    - fake tokeninfo `{aud: CLIENT, azp: CLIENT, email: 'a@corp.com', email_verified: 'true', exp: now+3600}` with `ALLOWED_DOMAINS=corp.com` gives 200;
    - `aud`/`azp` = other client gives 401 (Review Focus 3);
    - expired gives 401;
    - tokeninfo 400 gives 401;
    - `email: 'x@evil.com'` gives 403 (Review Focus 4);
    - `email_verified: 'false'` gives 403;
    - two calls with the same token hit fake tokeninfo once (cache);
    - the fake tokeninfo server never sees the token in its request URL.
- [ ] **Step 2:** Run `npx vitest run test/auth.test.ts`. Expected: FAIL.
- [ ] **Step 3:** Implement, and write `docs/remote-deployment.md`.
- [ ] **Step 4:** Rerun the tests. Expected: PASS. Run `npm run build`. Expected: exit 0.
- [ ] **Step 5:** Commit with `feat: static-token and Google OAuth auth with allowlist and protected resource metadata`.

### Task 7: Batch rejection, rate limit, audit log

**Files:**
- Create: `src/http/guards.ts`, `src/http/audit.ts`
- Modify: `src/http/app.ts`, `src/config.ts` (`TRUST_PROXY`)
- Test: `test/guards.test.ts`

**Interfaces:**
- Consumes: `req.auth?: AuthInfo` (from Task 6; undefined in `none` mode).
- Produces:
  - `rejectBatch(): RequestHandler`. An array body gives `400` with `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Batch requests are not supported"}}`.
  - `auditLog(e: { sub: string; clientId: string; method: string; tool?: string; durationMs: number; status: number })` writes one JSON line at info level. For `steampipe_query` it adds `sqlSha256` (first 16 hex chars). The SQL text is logged at debug only. It never logs the token.
  - Rate limit: `express-rate-limit` 8.7.1 (pinned), `limit: rateLimitPerMin`, `windowMs: 60000`, `keyGenerator: req => (req.auth?.extra?.sub as string | undefined) ?? ipKeyGenerator(req.ip)`.
  - Config `STEAMPIPE_MCP_TRUST_PROXY` (default unset) is passed to `app.set('trust proxy', …)`. Accepted values are a hop count or `true`.
  - Middleware order: origin → host → json → bearer (Task 6) → rateLimit → rejectBatch → audit → transport.

- [ ] **Step 1: Failing tests:**
  - a batch array body gets 400 (Review Focus 1);
  - 61 requests within a minute with `RATE_LIMIT_PER_MIN=60` give 429 on the 61st;
  - after a `tools/call` of `steampipe_query` in token mode, captured logger output contains `"tool":"steampipe_query"` and a `sqlSha256`, and does not contain the bearer token string or the SQL text at info level.
- [ ] **Step 2:** Run `npx vitest run test/guards.test.ts`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Rerun the tests. Expected: PASS.
- [ ] **Step 5:** Commit with `feat: reject batches, per-principal rate limit, audit log`.

### Task 8 (gated): 2026-07-28 readiness (design point: spec revision)

**Gate:** start only when `npm view @modelcontextprotocol/sdk` ships a release whose `SUPPORTED_PROTOCOL_VERSIONS` includes `2026-07-28`. Check with `npm pack` + `grep SUPPORTED_PROTOCOL_VERSIONS dist/esm/types.js`. Task 5 already lines up with 2026-07-28: stateless, no session IDs, 405 on GET/DELETE.

**Files:**
- Modify: `package.json` (SDK pin), `src/server.ts` (any new handler signatures)
- Test: `test/spec-2026-07-28.test.ts`

- [ ] **Step 1: Failing conformance tests** against the HTTP app:
  - `MCP-Protocol-Version` header ≠ body `_meta["io.modelcontextprotocol/protocolVersion"]` gives 400 with error code `-32020`;
  - missing `Mcp-Method` gives 400 with `-32020`;
  - `tools/call` with `Mcp-Name: steampipe_table_list` but body name `steampipe_query` gives 400 with `-32020`. The audit log in Task 7 must read the **body**, never the header;
  - `Mcp-Name: =?base64?c3RlYW1waXBlX3F1ZXJ5?=` matching body `steampipe_query` gets 200;
  - unsupported version `1999-01-01` gives 400 with `UnsupportedProtocolVersionError` listing the supported versions;
  - an unknown method gives 404 with `-32601`;
  - a request carrying `Mcp-Session-Id` succeeds, and the response has no session header.
- [ ] **Step 2:** Run the tests. Expected: FAIL on the current SDK.
- [ ] **Step 3:** Bump the SDK and adapt `createServer`. Keep 2025-11-25 clients working through the SDK's era fallback.
- [ ] **Step 4:** Run `npm test`. Expected: PASS, including every earlier HTTP/auth test unchanged.
- [ ] **Step 5:** Commit with `feat: support MCP 2026-07-28 per-request metadata and header validation`.

---

### Task 9: Docker image, compose example, GHCR release

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `docker-compose.example.yml`, `.github/workflows/release.yml`, `test/docker-smoke.sh`
- Modify: `package.json` (`version` 0.2.0), `CHANGELOG.md` (0.2.0 entry), `README.md` (Docker / remote section linking `docs/remote-deployment.md`)

**Interfaces:**
- Consumes: env config from Task 4, auth from Task 6, `/healthz` from Task 5.
- Produces:
  - Image `ghcr.io/rafpe/steampipe-mcp:<semver>` plus `:sha-<short>`. It is multi-arch `linux/amd64,linux/arm64`.
  - Image defaults:
    - `ENV STEAMPIPE_MCP_TRANSPORT=http STEAMPIPE_MCP_HTTP_HOST=0.0.0.0 STEAMPIPE_MCP_HTTP_PORT=27123`;
    - `EXPOSE 27123`;
    - runs as the non-root `node` user;
    - `HEALTHCHECK` uses `node -e "fetch('http://127.0.0.1:27123/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"`;
    - `ENTRYPOINT ["node","dist/index.js"]`.
    - Because of the Task 4 bind guard, the image refuses to start without `AUTH_MODE` set to `token`/`google`, or `ALLOW_INSECURE_REMOTE=true`. This is intended.
  - Build: multi-stage. The builder runs `npm ci && npm run build`. The runtime stage runs `npm ci --omit=dev --ignore-scripts` and copies `dist/` and `package.json`. Base `node:22-alpine` pinned to an exact patch tag that exists, checked with `docker manifest inspect node:<tag>`.
  - `docker-compose.example.yml` has two services:
    - `steampipe`: the official Turbot Steampipe image pinned to an exact version, checked with `docker manifest inspect`; if no official image exists, document an external Steampipe instead. It runs `steampipe service start --foreground`, with plugin config mounted from `./steampipe-config`.
    - `mcp`: this image, with `STEAMPIPE_MCP_WORKSPACE_DATABASE` pointing at the steampipe service and `AUTH_MODE=token`.
  - `release.yml` triggers on push of a tag matching `[0-9]+.[0-9]+.[0-9]+` and on `workflow_dispatch`, with `permissions: packages: write, contents: read`. It uses only marketplace actions pinned to exact versions: `docker/setup-qemu-action`, `docker/setup-buildx-action`, `docker/login-action` (GITHUB_TOKEN), `docker/metadata-action` (tags `type=semver,pattern={{version}}` and `type=sha`), `docker/build-push-action` with GHA cache, and `aquasecurity/trivy-action`. Trivy fails on `CRITICAL` vulnerabilities in the image that have a fix (`ignore-unfixed: true`).
  - CI (`ci.yml`) also runs `docker build` (no push) on PRs.

- [ ] **Step 1: Failing smoke test.** Write `test/docker-smoke.sh`. It:
  1. builds the image;
  2. starts `postgres:16` and the image on a user-defined docker network with `AUTH_MODE=token` and a 40-char token;
  3. waits for healthy;
  4. POSTs `initialize` then `tools/list` with the bearer token, and asserts 5 tools;
  5. asserts the same POST without the token returns 401;
  6. asserts that starting the image with `AUTH_MODE` unset exits non-zero with a message containing `ALLOW_INSECURE_REMOTE`;
  7. cleans up the containers in a `trap`.

  Run `bash test/docker-smoke.sh`. Expected: FAIL (no Dockerfile).
- [ ] **Step 2:** Implement the Dockerfile, .dockerignore, compose example, release workflow, CI docker build, version and CHANGELOG.
- [ ] **Step 3:** Run `bash test/docker-smoke.sh`. Expected: PASS. Also run `docker run --rm --entrypoint id <image>`. Expected: uid ≠ 0.
- [ ] **Step 4:** Validate the workflows: `actionlint` if available, else `npx --yes @action-validator/cli` on both workflow files. Expected: no errors.
- [ ] **Step 5:** Commit with `feat: Docker image, compose example and GHCR release workflow`.

## Release (controller, after the final review)

1. Push the stacked branches to `origin` (RafPe), never to `upstream`.
2. Open the stacked PRs with `--repo RafPe/steampipe-mcp`.
3. Wait for CI green and merge them in order into the fork's `main`.
4. Push the tag `0.2.0` to `origin`.
5. Wait for `release.yml` to go green, then `docker pull ghcr.io/rafpe/steampipe-mcp:0.2.0` and rerun the smoke test against the pulled image.

## Decisions (made by the user, 2026-10-21)

1. **Authorization server: Google.** Consequences, ruled by the controller:
   - Google issues opaque access tokens, so they are validated through tokeninfo, not as JWTs.
   - There are no custom scopes, so there is no per-tool scope guard.
   - There is no DCR/CIMD, so clients need a pre-registered OAuth client.
   - Group membership is not available without Admin SDK, so access is controlled by the email/domain allowlist.
   - The static-token mode is kept as the guaranteed-compatible path.
2. **Fork-only.** Nothing goes to turbot/steampipe-mcp.

## Deferred (YAGNI until a non-platform user needs access)

**Per-user data access (upstream #6).** When someone outside the platform team needs access, the fence must be enforced where the SQL runs, never by the MCP server parsing SQL. Leading option: one Steampipe instance (or Pipes workspace) per access profile, containing only that profile's connections. A verified token claim (group) selects the profile's backend, through a registry that replaces the single `db`. The building blocks are already in place: `DatabaseService` is constructed per backend (Task 1), and `buildHttpApp` takes the DB in one place (Task 5). Open question for then: is the slice a set of cloud accounts (maps to Steampipe connections) or finer (resource types within an account)?
