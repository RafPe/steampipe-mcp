/**
 * C0 controls, DEL, C1 controls, the line/paragraph separators, and the
 * bidi embedding/override and isolate characters. Any of these in a log
 * line can forge a new line or visually reorder what an operator reads.
 */
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/**
 * `String(value)`, falling back to `Object.prototype.toString` (e.g. for a
 * null-prototype object) and then to a constant (e.g. for a revoked Proxy,
 * on which both throw).
 */
function toText(value: unknown): string {
  try {
    return String(value);
  } catch {
    try {
      return Object.prototype.toString.call(value);
    } catch {
      return "[unprintable]";
    }
  }
}

/**
 * Make untrusted text safe to put in a log line: non-strings go through
 * `String()`, unsafe characters are stripped, and the result is cut to `max`
 * code points (so a surrogate pair is never split), with `…(+N)` appended
 * naming how many were dropped. Stripping happens before the bound, so
 * stripped characters never count towards it. Never throws: this runs
 * inside error handlers.
 */
export function boundForLog(value: unknown, max = 256): string {
  const chars = Array.from(toText(value).replace(UNSAFE_CHARS, ""));
  if (chars.length <= max) {
    return chars.join("");
  }
  return `${chars.slice(0, max).join("")}…(+${chars.length - max})`;
}
