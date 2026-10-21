# syntax=docker/dockerfile:1
#
# Multi-stage build for the steampipe-mcp Streamable HTTP server (Task 9).
# Base image is pinned to an exact patch tag, verified with
# `docker manifest inspect node:22.22.0-alpine3.22`.

FROM node:22.22.0-alpine3.22 AS builder

WORKDIR /app

# package.json's "prepare" script runs "npm run build" during "npm ci", so
# src/ and tsconfig.json must be present before that install runs.
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
RUN npm ci && npm run build

FROM node:22.22.0-alpine3.22 AS runtime

ENV NODE_ENV=production

WORKDIR /app

# --ignore-scripts: this package's "prepare" script runs "npm run build",
# which needs typescript (a devDependency) that --omit=dev does not install.
# The compiled dist/ below already came from the builder stage.
#
# After installing, the base image's Alpine packages and bundled package
# managers are patched/removed in the same layer, as root (USER node is
# still below):
#   - A full `apk upgrade` (every installed package, not just
#     libcrypto3/libssl3) fixes CVE-2026-31789 and also happens to clear the
#     other fixed-version CVEs already present in the base image (musl,
#     zlib) at no extra cost; scoping it down would leave those in place for
#     no real auditability gain, since apk's own changelog already states
#     exactly which packages moved.
#   - npm, corepack, npx and yarn are never invoked at runtime (ENTRYPOINT
#     runs "node" directly) and npm's own install here is already done, so
#     removing them drops the bundled, vulnerable node-tar copies
#     (CVE-2026-59873) entirely instead of patching a tool nothing uses.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
  && npm cache clean --force \
  && apk upgrade --no-cache \
  && rm -rf \
    /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack \
    /opt/yarn-* \
    /usr/local/bin/yarn \
    /usr/local/bin/yarnpkg

COPY --from=builder /app/dist ./dist

# Defaults for running as a remote MCP server. AUTH_MODE is intentionally
# left unset: the Task 4 bind guard in src/config.ts refuses to start a
# non-loopback HTTP_HOST with AUTH_MODE=none unless ALLOW_INSECURE_REMOTE is
# also set, so the container will not run without AUTH_MODE=token/google (or
# that explicit override). This is intended, not a bug.
ENV STEAMPIPE_MCP_TRANSPORT=http \
    STEAMPIPE_MCP_HTTP_HOST=0.0.0.0 \
    STEAMPIPE_MCP_HTTP_PORT=27123

EXPOSE 27123

# node:22-alpine ships a built-in, unprivileged "node" user (uid 1000).
USER node

# Follows STEAMPIPE_MCP_HTTP_PORT so overriding the port at run time keeps the
# container healthy. 127.0.0.1 is fine whatever the bind: /healthz bypasses
# the Host and Origin checks.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.STEAMPIPE_MCP_HTTP_PORT||27123)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "dist/index.js"]
