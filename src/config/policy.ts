import type { IdentityPolicy } from "../auth/policy.js";
import { ConfigError } from "../config.js";

export type PolicyConfig = IdentityPolicy;

const PREFIX = "STEAMPIPE_MCP_";
const MAX_ENTRY_LENGTH = 256;
const MAX_ALLOWED_SUBJECTS = 1024;
const MAX_SUBJECT_PREFIXES = 64;

/**
 * Parse a policy variable as JSON. Errors name the variable but never quote
 * the value or `JSON.parse`'s message, which embeds a snippet of the input.
 */
function parseJson(env: NodeJS.ProcessEnv, name: string): unknown {
  const value = env[`${PREFIX}${name}`];
  if (value === undefined || value === "") {
    return undefined;
  }
  try {
    return JSON.parse(value);
  } catch {
    throw new ConfigError(`${PREFIX}${name} must be valid JSON`);
  }
}

/**
 * An entry is a non-empty string of at most MAX_ENTRY_LENGTH characters. Empty
 * is refused because an empty prefix matches every subject. `where` locates
 * the entry by position, since claim keys are part of the value too.
 */
function assertEntry(name: string, where: string, entry: unknown): asserts entry is string {
  if (typeof entry !== "string" || entry.length === 0 || entry.length > MAX_ENTRY_LENGTH) {
    throw new ConfigError(
      `${PREFIX}${name} ${where} must be a non-empty string of at most ${MAX_ENTRY_LENGTH} characters`,
    );
  }
}

function parseStringArray(env: NodeJS.ProcessEnv, name: string, maxEntries: number): string[] {
  const parsed = parseJson(env, name);
  if (parsed === undefined) {
    return [];
  }
  if (!Array.isArray(parsed)) {
    throw new ConfigError(`${PREFIX}${name} must be a JSON array of strings`);
  }
  if (parsed.length > maxEntries) {
    throw new ConfigError(`${PREFIX}${name} must have at most ${maxEntries} entries, got ${parsed.length}`);
  }
  parsed.forEach((entry, i) => assertEntry(name, `entry ${i}`, entry));
  return parsed as string[];
}

function parseRequiredClaims(env: NodeJS.ProcessEnv): Record<string, string[]> {
  const name = "REQUIRED_CLAIMS";
  const parsed = parseJson(env, name);
  // A null-prototype record, so a "__proto__" claim key stays an ordinary
  // own key instead of rewriting the prototype.
  const claims: Record<string, string[]> = Object.create(null);
  if (parsed === undefined) {
    return claims;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ConfigError(`${PREFIX}${name} must be a JSON object mapping claim names to arrays of strings`);
  }
  Object.entries(parsed).forEach(([key, values], i) => {
    assertEntry(name, `claim name ${i}`, key);
    // An empty list can only ever reject, but reads as "any value will do".
    if (!Array.isArray(values) || values.length === 0) {
      throw new ConfigError(`${PREFIX}${name} claim ${i} must map to a non-empty JSON array of strings`);
    }
    values.forEach((v, j) => assertEntry(name, `claim ${i} value ${j}`, v));
    claims[key] = values as string[];
  });
  return claims;
}

/**
 * Parse the identity policy variables. All three default to empty, which
 * means no policy. Throws `ConfigError` naming the variable, never echoing
 * its value.
 */
export function parsePolicyConfig(env: NodeJS.ProcessEnv): PolicyConfig {
  return {
    requiredClaims: parseRequiredClaims(env),
    allowedSubjects: new Set(parseStringArray(env, "ALLOWED_SUBJECTS", MAX_ALLOWED_SUBJECTS)),
    subjectPrefixes: parseStringArray(env, "SUBJECT_PREFIXES", MAX_SUBJECT_PREFIXES),
  };
}
