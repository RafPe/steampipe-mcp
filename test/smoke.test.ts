import { describe, expect, it } from "vitest";
import { Client } from "pg";
import { describeDb, testDbUrl } from "./helpers/db.js";

describe("smoke", () => {
  it("1 + 1 equals 2", () => {
    expect(1 + 1).toBe(2);
  });
});

describeDb("database connectivity", () => {
  it("connects to the test database and runs a trivial query", async () => {
    const client = new Client({
      connectionString: testDbUrl(),
      connectionTimeoutMillis: 5000,
    });
    await client.connect();
    try {
      const result = await client.query("select 1 as value");
      expect(result.rows[0].value).toBe(1);
    } finally {
      await client.end();
    }
  });
});
