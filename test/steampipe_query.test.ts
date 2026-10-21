import { describe, expect, it } from "vitest";
import { tool } from "../src/tools/steampipe_query.js";
import type { DatabaseService } from "../src/services/database.js";

function fakeDb(rows: any[], truncated: boolean): DatabaseService {
  return { executeUserQuery: async () => ({ rows, truncated }) } as unknown as DatabaseService;
}

describe("steampipe_query tool", () => {
  it("returns the plain rows array when not truncated", async () => {
    const result = await (tool as any).handler(fakeDb([{ x: 1 }], false), { sql: "select 1 as x" });
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.content[0].text)).toEqual([{ x: 1 }]);
  });

  it("wraps rows with truncated: true when the row cap was hit", async () => {
    const result = await (tool as any).handler(fakeDb([{ g: 1 }], true), { sql: "select g" });
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.content[0].text)).toEqual({ rows: [{ g: 1 }], truncated: true });
  });
});
