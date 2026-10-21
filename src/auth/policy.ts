/**
 * Thrown by `checkPolicy` when a verified identity does not satisfy the
 * configured policy. The message names the rule and, for a required claim,
 * the claim KEY only: claim values and the subject come from a token the
 * caller chose, so echoing one back would log attacker-controlled text and
 * tell a prober what the server compares against. Verifier adapters catch it
 * and rethrow as their own `not_allowed` error.
 */
export class PolicyViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyViolation";
  }
}

/**
 * Declarative rules about WHO may connect, evaluated after a token has been
 * verified. There is deliberately no regex: JavaScript regex can backtrack
 * catastrophically on attacker-chosen subjects, and RE2 is a native addon.
 */
export interface IdentityPolicy {
  /** Claim name -> allowed values; every listed claim must match one. */
  requiredClaims: Record<string, string[]>;
  /** Exact subjects allowed. */
  allowedSubjects: Set<string>;
  /** Subject prefixes allowed. */
  subjectPrefixes: string[];
}

/** True when the policy has no rules, so verifiers can skip the step. */
export function isEmptyPolicy(p: IdentityPolicy): boolean {
  return Object.keys(p.requiredClaims).length === 0 && p.allowedSubjects.size === 0 && p.subjectPrefixes.length === 0;
}

/**
 * The strings a claim value asserts: a string is itself, an array is its
 * string elements (other elements are ignored), and a boolean or number is
 * its `String(v)`. Anything else (absent, null, object) asserts nothing and
 * so can never satisfy a rule.
 */
function claimStrings(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (typeof value === "boolean" || typeof value === "number") {
    return [String(value)];
  }
  if (Array.isArray(value)) {
    return value.filter((v): v is string => typeof v === "string");
  }
  return [];
}

/**
 * Throws `PolicyViolation` unless `claims` and `subject` satisfy `p`.
 *
 * Order: required claims by sorted key (so two failing claims always report
 * the same one, whatever the config's key order), then the subject. A subject
 * passes when both subject lists are empty, when it is on the allowlist, or
 * when it starts with a listed prefix. Claims are read as own properties
 * only, so nothing inherited from a prototype can satisfy a rule.
 */
export function checkPolicy(p: IdentityPolicy, claims: Record<string, unknown>, subject: string): void {
  for (const key of Object.keys(p.requiredClaims).sort()) {
    const allowed = p.requiredClaims[key];
    const values = Object.hasOwn(claims, key) ? claimStrings(claims[key]) : [];
    if (!values.some((v) => allowed.includes(v))) {
      throw new PolicyViolation(`required claim ${JSON.stringify(key)} not satisfied`);
    }
  }

  if (p.allowedSubjects.size === 0 && p.subjectPrefixes.length === 0) {
    return;
  }
  if (p.allowedSubjects.has(subject) || p.subjectPrefixes.some((prefix) => subject.startsWith(prefix))) {
    return;
  }
  throw new PolicyViolation("subject not allowed");
}
