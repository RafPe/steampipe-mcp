import { describe, expect, it } from "vitest";
import { resolveSsl } from "../src/services/ssl.js";
import { buildPoolConfig } from "../src/services/database.js";
import type { DatabaseOptions } from "../src/services/database.js";

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
    ["postgresql://u@db.example.com:9193/d?sslmode=prefer", undefined],
    ["postgresql://u@db.example.com:9193/d?sslmode=allow", undefined],
  ];

  it.each(cases)("%s -> %j", (raw, expected) => {
    expect(resolveSsl(new URL(raw))).toEqual(expected);
  });
});

describe("buildPoolConfig", () => {
  it("strips sslmode from the connection string and applies the resolved ssl config", () => {
    const opts: DatabaseOptions = {
      connectionString: "postgresql://u@db.example.com/d?sslmode=no-verify",
      maxRows: 0,
      statementTimeoutMs: 120000,
      poolMax: 20,
      exposeConnectionDetails: true,
    };
    const cfg = buildPoolConfig(opts);
    expect(cfg.connectionString).not.toContain("sslmode");
    expect(cfg.ssl).toEqual({ rejectUnauthorized: false });
  });
});
