import { describe, expect, it } from "vitest";
import { isDeepStrictEqual } from "node:util";
import { JsonValueLimitError, MAX_JSON_VALUES, valueCountingReviver } from "../src/http/json-limit.js";

describe("valueCountingReviver", () => {
  it("caps a body at MAX_JSON_VALUES = 10000", () => {
    expect(MAX_JSON_VALUES).toBe(10_000);
  });

  it("counts every value, the root included, and throws on the one past the limit", () => {
    // root object, 1 (a), the array (b), 1 and 2 inside it = 5 values
    const text = '{"a":1,"b":[1,2]}';
    expect(() => JSON.parse(text, valueCountingReviver(5))).not.toThrow();
    expect(() => JSON.parse(text, valueCountingReviver(4))).toThrow(JsonValueLimitError);
  });

  it("keeps a separate count per reviver, so one parse cannot use up another's budget", () => {
    const first = valueCountingReviver(3);
    const second = valueCountingReviver(3);
    expect(() => JSON.parse("[1,2]", first)).not.toThrow();
    expect(() => JSON.parse("[1,2]", second)).not.toThrow();
  });

  it("returns every value unchanged, __proto__ keys included", () => {
    const text =
      '{"__proto__":{"polluted":true},"n":[1,2.5,-0,null,true,"s"],"o":{"constructor":{"prototype":{"x":1}},"":{}}}';
    const plain = JSON.parse(text);
    const revived = JSON.parse(text, valueCountingReviver(1000));
    // node:util rather than toStrictEqual: vitest's strict equality reads
    // `.constructor`, so an own "constructor" key fails it even for two
    // plain parses of the same text.
    expect(isDeepStrictEqual(revived, plain)).toBe(true);
    expect(JSON.stringify(revived)).toBe(JSON.stringify(plain));
    expect(Object.getPrototypeOf(revived)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(revived, "__proto__")).toBe(true);
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
    expect(Object.is(revived.n[2], -0)).toBe(true);
  });

  it("names the limit in its message and carries no body content", () => {
    const err = new JsonValueLimitError(10_000);
    expect(err.message).toBe("Request body too large: more than 10000 JSON values");
  });
});
