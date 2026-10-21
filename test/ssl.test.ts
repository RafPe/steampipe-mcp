import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveSsl } from "../src/services/ssl.js";
import { buildPoolConfig } from "../src/services/database.js";
import type { DatabaseOptions } from "../src/services/database.js";

function makeOpts(connectionString: string): DatabaseOptions {
  return {
    connectionString,
    maxRows: 0,
    statementTimeoutMs: 120000,
    poolMax: 20,
    exposeConnectionDetails: true,
  };
}

describe("resolveSsl", () => {
  const cases: Array<[string, false | undefined | { rejectUnauthorized: boolean }]> = [
    ["postgresql://u@localhost:9193/d", { rejectUnauthorized: false }],
    ["postgresql://u@127.0.0.1:9193/d", { rejectUnauthorized: false }],
    ["postgresql://u@127.1.2.3:9193/d", { rejectUnauthorized: false }],
    ["postgresql://u@[::1]:9193/d", { rejectUnauthorized: false }],
    ["postgresql://u@db.example.com:9193/d", { rejectUnauthorized: true }],
    ["postgresql://u@db.example.com:9193/d?sslmode=disable", false],
    ["postgresql://u@db.example.com:9193/d?sslmode=no-verify", { rejectUnauthorized: false }],
    ["postgresql://u@db.example.com:9193/d?sslmode=require", { rejectUnauthorized: true }],
    ["postgresql://u@db.example.com:9193/d?sslmode=verify-ca", { rejectUnauthorized: true }],
    ["postgresql://u@db.example.com:9193/d?sslmode=verify-full", { rejectUnauthorized: true }],
    // prefer/allow resolve exactly like no sslmode at all (host-based
    // default), never to undefined/plaintext.
    ["postgresql://u@db.example.com:9193/d?sslmode=prefer", { rejectUnauthorized: true }],
    ["postgresql://u@db.example.com:9193/d?sslmode=allow", { rejectUnauthorized: true }],
    ["postgresql://u@localhost:9193/d?sslmode=prefer", { rejectUnauthorized: false }],
    ["postgresql://u@localhost:9193/d?sslmode=allow", { rejectUnauthorized: false }],
  ];

  it.each(cases)("%s -> %j", (raw, expected) => {
    expect(resolveSsl(new URL(raw))).toEqual(expected);
  });
});

describe("buildPoolConfig", () => {
  it("strips sslmode from the connection string and applies the resolved ssl config", () => {
    const cfg = buildPoolConfig(makeOpts("postgresql://u@db.example.com/d?sslmode=no-verify"));
    expect(cfg.connectionString).not.toContain("sslmode");
    expect(cfg.ssl).toEqual({ rejectUnauthorized: false });
  });

  it("strips sslmode=disable but keeps ssl:false explicit, not omitted", () => {
    const cfg = buildPoolConfig(makeOpts("postgresql://u@db.example.com/d?sslmode=disable"));
    expect(cfg.connectionString).not.toContain("sslmode");
    expect(cfg.ssl).toBe(false);
    expect("ssl" in cfg).toBe(true);
  });

  it("does not let a ssl query param override the resolved TLS mode or survive into the connection string", () => {
    const cfg = buildPoolConfig(makeOpts("postgresql://u@db.example.com/d?ssl=0"));
    expect(cfg.connectionString).not.toContain("ssl=0");
    expect(cfg.ssl).toEqual({ rejectUnauthorized: true });
  });

  it("rejects a connection string that overrides the host via a host= query parameter", () => {
    expect(() => buildPoolConfig(makeOpts("postgresql://u:s3cret@localhost/d?host=db.example.com"))).toThrow(
      /must not override the host/,
    );
  });

  it("rejects a connection string that overrides the host via a hostaddr= query parameter", () => {
    expect(() => buildPoolConfig(makeOpts("postgresql://u:s3cret@localhost/d?hostaddr=203.0.113.5"))).toThrow(
      /must not override the host/,
    );
  });

  it("never includes the connection string in the host-override error", () => {
    try {
      buildPoolConfig(makeOpts("postgresql://u:s3cret@localhost/d?host=db.example.com"));
      expect.fail("expected buildPoolConfig to throw");
    } catch (error) {
      expect(String(error)).not.toContain("s3cret");
      expect(String(error)).not.toContain("localhost");
    }
  });

  it("reads sslrootcert/sslcert/sslkey files and merges them into the ssl object, stripping them from the string", () => {
    const dir = mkdtempSync(join(tmpdir(), "ssl-test-"));
    const rootCertPath = join(dir, "root.crt");
    const certPath = join(dir, "client.crt");
    const keyPath = join(dir, "client.key");
    writeFileSync(rootCertPath, "ROOT-CERT-CONTENTS");
    writeFileSync(certPath, "CLIENT-CERT-CONTENTS");
    writeFileSync(keyPath, "CLIENT-KEY-CONTENTS");

    const url = new URL("postgresql://u@db.example.com/d");
    url.searchParams.set("sslrootcert", rootCertPath);
    url.searchParams.set("sslcert", certPath);
    url.searchParams.set("sslkey", keyPath);

    const cfg = buildPoolConfig(makeOpts(url.toString()));
    expect(cfg.connectionString).not.toContain("sslrootcert");
    expect(cfg.connectionString).not.toContain("sslcert");
    expect(cfg.connectionString).not.toContain("sslkey");
    expect(cfg.ssl).toMatchObject({
      rejectUnauthorized: true,
      ca: "ROOT-CERT-CONTENTS",
      cert: "CLIENT-CERT-CONTENTS",
      key: "CLIENT-KEY-CONTENTS",
    });
  });

  it("ignores sslrootcert/sslcert/sslkey when sslmode=disable resolves ssl to false", () => {
    const cfg = buildPoolConfig(makeOpts("postgresql://u@db.example.com/d?sslmode=disable&sslrootcert=/does/not/exist"));
    expect(cfg.ssl).toBe(false);
  });
});
