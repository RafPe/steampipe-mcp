/**
 * Maximum number of JSON values (R38) in one request body, counted the way
 * `JSON.parse` calls a reviver: once per value, the root and every nested
 * value included. A body over the limit gets `413`.
 *
 * Why a count and not only a byte cap: the MCP SDK validates requests with
 * zod, which reports one issue per invalid element of an unconstrained
 * array, and the JSON-RPC error lists them all. A ~1 MiB `initialize` with a
 * 520k-element `clientInfo.icons` array answered with a ~127 MB error and
 * peaked at ~1.36 GB RSS. Capping one array is not enough (many medium
 * arrays fit in 1 MiB), so the bound is on the total. No request this server
 * handles comes close: `initialize` and `tools/call` bodies are tens of
 * values. Not configurable on purpose.
 */
export const MAX_JSON_VALUES = 10_000;

/**
 * Thrown by `valueCountingReviver` once the limit is passed. body-parser
 * strips every own property except `message` and `stack` from an error
 * thrown while parsing, then hands the same object on as a 400
 * `entity.parse.failed`, so the error handler must match it with
 * `instanceof`. The message names only the limit, never body content.
 */
export class JsonValueLimitError extends Error {
  constructor(limit: number) {
    super(`Request body too large: more than ${limit} JSON values`);
    this.name = "JsonValueLimitError";
  }
}

/**
 * A `JSON.parse` reviver that counts the values it sees and throws
 * `JsonValueLimitError` on value `max + 1`. It returns every value
 * unchanged, so the parsed result is the same as plain `JSON.parse`
 * (`__proto__` stays an own data property). Each reviver has its own
 * counter: build a new one for every parse.
 */
export function valueCountingReviver(max: number = MAX_JSON_VALUES): (key: string, value: unknown) => unknown {
  let count = 0;
  return (_key, value) => {
    count += 1;
    if (count > max) {
      throw new JsonValueLimitError(max);
    }
    return value;
  };
}
