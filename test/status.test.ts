import { describe, expect, it } from "vitest";
import { DatabaseService } from "../src/services/database.js";
import { resource } from "../src/resources/status.js";

describe("status resource", () => {
  it("never leaks the password, regardless of exposeConnectionDetails", async () => {
    for (const exposeConnectionDetails of [true, false]) {
      const db = new DatabaseService({
        connectionString: "postgresql://u:s3cret@h/d",
        maxRows: 0,
        statementTimeoutMs: 120000,
        poolMax: 1,
        exposeConnectionDetails,
      });
      const result = await resource.handler(db);
      expect(result.contents[0].text).not.toContain("s3cret");
    }
  });

  it("includes the masked connection string when exposeConnectionDetails is true", async () => {
    const db = new DatabaseService({
      connectionString: "postgresql://u:s3cret@h/d",
      maxRows: 0,
      statementTimeoutMs: 120000,
      poolMax: 1,
      exposeConnectionDetails: true,
    });
    const result = await resource.handler(db);
    const parsed = JSON.parse(result.contents[0].text);
    expect(parsed.connection_string).toBe(db.safeConnectionString);
  });

  it("omits the connection string entirely when exposeConnectionDetails is false", async () => {
    const db = new DatabaseService({
      connectionString: "postgresql://u:s3cret@h/d",
      maxRows: 0,
      statementTimeoutMs: 120000,
      poolMax: 1,
      exposeConnectionDetails: false,
    });
    const result = await resource.handler(db);
    const parsed = JSON.parse(result.contents[0].text);
    expect(parsed.connection_string).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(parsed, "connection_string")).toBe(false);
  });
});
