import { describe, expect, it } from "vitest";
import { z } from "zod/v4";
import { CompleteResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { safeParse } from "@modelcontextprotocol/sdk/server/zod-compat.js";

// GHSA-mrhx-c7xc-m3w5: zod < 4.6.6 parses every element of an oversized
// array before reporting that the array is too long, raising one issue per
// failing element (unbounded memory). The 4.6.6 fix fails a size-constrained
// array (leading .max/.length check) on its size BEFORE any element is
// parsed, so exactly one `too_big` issue is raised.
//
// Note: the fix applies only to arrays/maps/sets with an upper size bound.
// An unconstrained z.array() still yields one issue per failing element on
// 4.6.7 — that is expected and NOT asserted here.
const N = 100_000;
const oversized = (): number[] => new Array<number>(N).fill(1);

describe("zod GHSA-mrhx-c7xc-m3w5 (oversized constrained arrays)", () => {
  it("zod/v4 (the entry point the MCP SDK imports) fails a .max() array on size alone", () => {
    const schema = z.array(z.string()).max(100);
    const result = schema.safeParse(oversized());

    expect(result.success).toBe(false);
    expect(result.error!.issues).toHaveLength(1);
    expect(result.error!.issues[0].code).toBe("too_big");
  });

  it("the SDK's own CompleteResultSchema (values: z.array(z.string()).max(100)) yields one bounded issue via the SDK's parse helper", () => {
    const result = safeParse(CompleteResultSchema, {
      completion: { values: oversized() },
    });

    expect(result.success).toBe(false);
    expect(result.error!.issues).toHaveLength(1);
    expect(result.error!.issues[0].code).toBe("too_big");
    expect(result.error!.issues[0].path).toEqual(["completion", "values"]);
  });
});
