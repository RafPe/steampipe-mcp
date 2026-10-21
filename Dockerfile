# syntax=docker/dockerfile:1
#
# Multi-stage build for the steampipe-mcp Streamable HTTP server (Task 9).
# Base image is pinned to an exact patch tag, verified with
# `docker manifest inspect node:22.22.0-alpine3.22`.

# Node never runs under emulation (0.3.1). The 0.3.0 release failed because
# `npm ci && npm run build` died with SIGILL (exit 132) in the linux/arm64
# builder stage under QEMU. The builder and deps stages therefore run on the
# build host's own platform ($BUILDPLATFORM): the TypeScript output and the
# production node_modules are plain JS, the same for every architecture. The
# target-platform runtime stage only runs apk/rm and copies files in.

FROM --platform=$BUILDPLATFORM node:22.22.0-alpine3.22 AS builder

WORKDIR /app

# package.json's "prepare" script runs "npm run build" during "npm ci", so
# src/ and tsconfig.json must be present before that install runs.
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
RUN npm ci && npm run build

FROM --platform=$BUILDPLATFORM node:22.22.0-alpine3.22 AS deps

WORKDIR /app

COPY package.json package-lock.json ./

# Guard: production dependencies must stay platform-independent. They are
# installed here, on $BUILDPLATFORM, and copied into the runtime image of every
# target platform, so a production package that compiles native code
# (hasInstallScript, gypfile) or ships a per-platform prebuilt binary (cpu, os,
# libc) would end up in the image built for the wrong architecture, or not
# built at all because of --ignore-scripts below. Such a dependency needs a
# per-architecture install instead, so fail the build rather than ship a broken
# image. Every lockfile entry not marked "dev" is a production package
# (--omit=dev still installs optional and devOptional entries).
RUN node -e ' \
  const lock = require("./package-lock.json"); \
  if (!(lock.lockfileVersion >= 2) || !lock.packages) { \
    console.error("platform guard: package-lock.json must be lockfileVersion >= 2 with a packages map"); \
    process.exit(1); \
  } \
  const bad = Object.entries(lock.packages) \
    .filter(([name, pkg]) => name !== "" && !pkg.dev) \
    .filter(([, pkg]) => pkg.hasInstallScript || pkg.gypfile || pkg.cpu || pkg.os || pkg.libc) \
    .map(([name]) => name); \
  if (bad.length) { \
    console.error("platform guard: production dependencies with install scripts, gyp files or cpu/os/libc restrictions: " + bad.join(", ")); \
    process.exit(1); \
  }'

# --ignore-scripts: this package's "prepare" script runs "npm run build",
# which needs typescript (a devDependency) that --omit=dev does not install.
# The compiled dist/ comes from the builder stage. Kept as its own RUN so a
# guard failure above is reported as such, not as an install failure.
# hadolint ignore=DL3059
RUN npm ci --omit=dev --ignore-scripts

FROM node:22.22.0-alpine3.22 AS runtime

ENV NODE_ENV=production

WORKDIR /app

# The base image's Alpine packages and bundled package managers are
# patched/removed in one layer, as root (USER node is still below):
#   - A full `apk upgrade` (every installed package, not just
#     libcrypto3/libssl3) fixes CVE-2026-31789 and also happens to clear the
#     other fixed-version CVEs already present in the base image (musl,
#     zlib) at no extra cost; scoping it down would leave those in place for
#     no real auditability gain, since apk's own changelog already states
#     exactly which packages moved.
#   - npm, corepack, npx and yarn are never invoked at runtime (ENTRYPOINT
#     runs "node" directly) and dependencies are installed in the deps stage,
#     so removing them drops the bundled, vulnerable node-tar copies
#     (CVE-2026-59873) entirely instead of patching a tool nothing uses.
# hadolint ignore=DL3017
RUN apk upgrade --no-cache \
  && rm -rf \
    /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack \
    /opt/yarn-* \
    /usr/local/bin/yarn \
    /usr/local/bin/yarnpkg

# Root-owned on purpose: the node user below can read but not modify the app.
COPY package.json ./
COPY --from=deps /app/node_modules ./node_modules
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
