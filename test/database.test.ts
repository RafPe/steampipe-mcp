import { afterEach, expect, it } from "vitest";
import { Client } from "pg";
import { DatabaseService, type DatabaseOptions } from "../src/services/database.js";
import { describeDb, testDbUrl } from "./helpers/db.js";

// The local test Postgres has no TLS. resolveSsl() defaults loopback hosts
// (127.0.0.1 here) to attempting TLS with certificate verification skipped,
// not to plaintext - and node-postgres does not fall back to plaintext the
// way libpq's `sslmode=prefer` does: it fails the connection outright with
// "The server does not support SSL connections" when the server refuses the
// SSL negotiation. So these tests force sslmode=disable explicitly.
function noTlsUrl(): string {
  const url = new URL(testDbUrl()!);
  if (!url.searchParams.has("sslmode")) {
    url.searchParams.set("sslmode", "disable");
  }
  return url.toString();
}

describeDb("DatabaseService", () => {
  const services: DatabaseService[] = [];

  function makeDb(overrides: Partial<DatabaseOptions> = {}): DatabaseService {
    const db = new DatabaseService({
      connectionString: noTlsUrl(),
      maxRows: 0,
      statementTimeoutMs: 120000,
      poolMax: 1,
      exposeConnectionDetails: true,
      ...overrides,
    });
    services.push(db);
    return db;
  }

  afterEach(async () => {
    await Promise.all(services.splice(0).map((db) => db.close()));
  });

  it("rejects multi-statement escape", async () => {
    const db = makeDb();
    await expect(db.executeUserQuery("COMMIT; CREATE TABLE pwned(x int)")).rejects.toThrow(/multiple commands/);
    await expect(db.executeQuery("select to_regclass('pwned') as t", [])).resolves.toEqual([{ t: null }]);
  });

  it("rejects writes", async () => {
    const db = makeDb();
    await expect(db.executeUserQuery("CREATE TABLE pwned2(x int)")).rejects.toThrow(/read-only transaction/);
  });

  it("rejects writes from a DO block that tries to switch to read-write", async () => {
    const db = makeDb();
    await expect(
      db.executeUserQuery("DO $$ BEGIN SET TRANSACTION READ WRITE; CREATE TABLE pwned3(x int); END $$"),
    ).rejects.toThrow(/read-write|read-only/);
    await expect(db.executeQuery("select to_regclass('pwned3') as t", [])).resolves.toEqual([{ t: null }]);
  });

  it("keeps the statement timeout on a reused connection after DISCARD ALL", async () => {
    const db = makeDb({ statementTimeoutMs: 200, poolMax: 1 });
    await db.executeUserQuery("set statement_timeout = 0");
    await expect(db.executeUserQuery("select pg_sleep(1)")).rejects.toThrow(/statement timeout/);
  });

  it("does not leak session state", async () => {
    const db = makeDb();
    await db.executeUserQuery("select set_config('search_path','evil',false)");
    const { rows } = await db.executeUserQuery("show search_path");
    expect(rows[0].search_path).not.toBe("evil");
  });

  it("applies statement timeout on every pooled connection", async () => {
    const db = makeDb({ statementTimeoutMs: 200, poolMax: 3 });
    const results = await Promise.allSettled([
      db.executeUserQuery("select pg_sleep(1)"),
      db.executeUserQuery("select pg_sleep(1)"),
      db.executeUserQuery("select pg_sleep(1)"),
    ]);
    for (const result of results) {
      expect(result.status).toBe("rejected");
      expect(String((result as PromiseRejectedResult).reason)).toMatch(/statement timeout/);
    }
  });

  it("caps rows", async () => {
    const db = makeDb({ maxRows: 10 });
    const capped = await db.executeUserQuery("select generate_series(1,50) g");
    expect(capped.rows).toHaveLength(10);
    expect(capped.truncated).toBe(true);
    const small = await db.executeUserQuery("select generate_series(1,5) g");
    expect(small.rows).toHaveLength(5);
    expect(small.truncated).toBe(false);
  });

  it("treats maxRows 0 as unlimited", async () => {
    const db = makeDb({ maxRows: 0 });
    const result = await db.executeUserQuery("select generate_series(1,50) g");
    expect(result.rows).toHaveLength(50);
    expect(result.truncated).toBe(false);
  });

  it("reconnects after backend termination", async () => {
    const db = makeDb();
    await expect(db.executeUserQuery("select 1 as x")).resolves.toEqual({ rows: [{ x: 1 }], truncated: false });

    const admin = new Client({ connectionString: testDbUrl(), connectionTimeoutMillis: 5000 });
    await admin.connect();
    try {
      const killed = await admin.query(
        "select pg_terminate_backend(pid) from pg_stat_activity where application_name='steampipe-mcp'",
      );
      expect(killed.rowCount).toBeGreaterThan(0);
    } finally {
      await admin.end();
    }

    await expect(db.executeUserQuery("select 1 as x")).resolves.toEqual({ rows: [{ x: 1 }], truncated: false });
  });

  it("masks the password in safeConnectionString", () => {
    const db = makeDb({ connectionString: "postgresql://u:s3cret@127.0.0.1:1/d?sslmode=disable" });
    expect(db.safeConnectionString).not.toContain("s3cret");
  });

  it("hides connection details in errors unless exposed", async () => {
    const hidden = makeDb({ connectionString: "postgresql://u:s3cret@127.0.0.1:1/d?sslmode=disable", exposeConnectionDetails: false });
    const err = await hidden.executeUserQuery("select 1").catch((e: Error) => e);
    expect(String(err)).toMatch(/the configured Steampipe database/);
    expect(String(err)).not.toContain("127.0.0.1");

    const unresolvable = makeDb({
      connectionString: "postgresql://u:s3cret@nohost.invalid/d?sslmode=disable",
      exposeConnectionDetails: false,
    });
    const err3 = await unresolvable.executeUserQuery("select 1").catch((e: Error) => e);
    expect(String(err3)).toMatch(/the configured Steampipe database/);
    expect(String(err3)).not.toContain("nohost");

    const shown = makeDb({ connectionString: "postgresql://u:s3cret@127.0.0.1:1/d?sslmode=disable", exposeConnectionDetails: true });
    const err2 = await shown.executeUserQuery("select 1").catch((e: Error) => e);
    expect(String(err2)).toContain("127.0.0.1");
    expect(String(err2)).not.toContain("s3cret");
  });
});
