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
function assertEntry(label: string, where: string, entry: unknown): asserts entry is string {
  if (typeof entry !== "string" || entry.length === 0 || entry.length > MAX_ENTRY_LENGTH) {
    throw new ConfigError(`${label} ${where} must be a non-empty string of at most ${MAX_ENTRY_LENGTH} characters`);
  }
}

function stringArray(value: unknown, label: string, maxEntries: number): string[] {
  if (!Array.isArray(value)) {
    throw new ConfigError(`${label} must be a JSON array of strings`);
  }
  if (value.length > maxEntries) {
    throw new ConfigError(`${label} must have at most ${maxEntries} entries, got ${value.length}`);
  }
  value.forEach((entry, i) => assertEntry(label, `entry ${i}`, entry));
  return value as string[];
}

function requiredClaims(value: unknown, label: string): Record<string, string[]> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConfigError(`${label} must be a JSON object mapping claim names to arrays of strings`);
  }
  // A null-prototype record, so a "__proto__" claim key stays an ordinary
  // own key instead of rewriting the prototype.
  const claims: Record<string, string[]> = Object.create(null);
  Object.entries(value).forEach(([key, values], i) => {
    assertEntry(label, `claim name ${i}`, key);
    // An empty list can only ever reject, but reads as "any value will do".
    if (!Array.isArray(values) || values.length === 0) {
      throw new ConfigError(`${label} claim ${i} must map to a non-empty JSON array of strings`);
    }
    values.forEach((v, j) => assertEntry(label, `claim ${i} value ${j}`, v));
    claims[key] = values as string[];
  });
  return claims;
}

/** Already-parsed policy values; `undefined` means unset. */
export interface PolicyValues {
  requiredClaims?: unknown;
  allowedSubjects?: unknown;
  subjectPrefixes?: unknown;
}

/**
 * Validate policy values from any source (env JSON or a `JWT_ISSUERS`
 * entry) with one set of limits. `label` names each field in errors, which
 * never echo a value. Unset fields are empty.
 */
export function policyFromValues(values: PolicyValues, label: (field: keyof PolicyValues) => string): PolicyConfig {
  const { requiredClaims: rc, allowedSubjects: as, subjectPrefixes: sp } = values;
  return {
    requiredClaims: rc === undefined ? Object.create(null) : requiredClaims(rc, label("requiredClaims")),
    allowedSubjects: new Set(as === undefined ? [] : stringArray(as, label("allowedSubjects"), MAX_ALLOWED_SUBJECTS)),
    subjectPrefixes: sp === undefined ? [] : stringArray(sp, label("subjectPrefixes"), MAX_SUBJECT_PREFIXES),
  };
}

const ENV_NAMES: Record<keyof PolicyValues, string> = {
  requiredClaims: "REQUIRED_CLAIMS",
  allowedSubjects: "ALLOWED_SUBJECTS",
  subjectPrefixes: "SUBJECT_PREFIXES",
};

/**
 * Parse the identity policy variables. All three default to empty, which
 * means no policy. Throws `ConfigError` naming the variable, never echoing
 * its value.
 */
export function parsePolicyConfig(env: NodeJS.ProcessEnv): PolicyConfig {
  return policyFromValues(
    {
      requiredClaims: parseJson(env, ENV_NAMES.requiredClaims),
      allowedSubjects: parseJson(env, ENV_NAMES.allowedSubjects),
      subjectPrefixes: parseJson(env, ENV_NAMES.subjectPrefixes),
    },
    (field) => `${PREFIX}${ENV_NAMES[field]}`,
  );
}
