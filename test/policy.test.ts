import { describe, expect, it } from "vitest";
import { checkPolicy, isEmptyPolicy, PolicyViolation, type IdentityPolicy } from "../src/auth/policy.js";
import { ConfigError, loadConfig } from "../src/config.js";
import { parsePolicyConfig } from "../src/config/policy.js";

const EMPTY_ARGV: string[] = ["node", "index.js"];

function policy(p: Partial<IdentityPolicy> = {}): IdentityPolicy {
  return {
    requiredClaims: p.requiredClaims ?? {},
    allowedSubjects: p.allowedSubjects ?? new Set(),
    subjectPrefixes: p.subjectPrefixes ?? [],
  };
}

/** Runs checkPolicy and returns the PolicyViolation message, or undefined when it passes. */
function violation(p: IdentityPolicy, claims: Record<string, unknown>, subject = "user-1"): string | undefined {
  try {
    checkPolicy(p, claims, subject);
    return undefined;
  } catch (e) {
    expect(e).toBeInstanceOf(PolicyViolation);
    return (e as Error).message;
  }
}

const HD = policy({ requiredClaims: { hd: ["corp.com", "other.com"] } });
const HD_DENIED = 'required claim "hd" not satisfied';

describe("checkPolicy: required claims", () => {
  it.each<[string, IdentityPolicy, Record<string, unknown>, string | undefined]>([
    ["string equal to an allowed value passes", HD, { hd: "corp.com" }, undefined],
    ["string equal to the second allowed value passes", HD, { hd: "other.com" }, undefined],
    ["string not in the allowed values fails", HD, { hd: "evil.com" }, HD_DENIED],
    ["string match is exact (case-sensitive)", HD, { hd: "CORP.com" }, HD_DENIED],
    ["array intersecting the allowed values passes", HD, { hd: ["x", "corp.com"] }, undefined],
    ["array with no allowed value fails", HD, { hd: ["x", "y"] }, HD_DENIED],
    ["empty array fails", HD, { hd: [] }, HD_DENIED],
    ["array ignores non-string elements but still matches a string", HD, { hd: [1, null, "corp.com"] }, undefined],
    ["array whose only match is a non-string element fails", policy({ requiredClaims: { n: ["1"] } }), { n: [1] }, 'required claim "n" not satisfied'],
    ["boolean true matches \"true\"", policy({ requiredClaims: { email_verified: ["true"] } }), { email_verified: true }, undefined],
    ["boolean false does not match \"true\"", policy({ requiredClaims: { email_verified: ["true"] } }), { email_verified: false }, 'required claim "email_verified" not satisfied'],
    ["number matches its String()", policy({ requiredClaims: { level: ["3"] } }), { level: 3 }, undefined],
    ["absent claim fails", HD, {}, HD_DENIED],
    ["null claim fails", HD, { hd: null }, HD_DENIED],
    ["object claim fails", HD, { hd: { value: "corp.com" } }, HD_DENIED],
    ["object whose String() would match fails", policy({ requiredClaims: { o: ["[object Object]"] } }), { o: {} }, 'required claim "o" not satisfied'],
    ["undefined claim fails", HD, { hd: undefined }, HD_DENIED],
  ])("%s", (_name, p, claims, want) => {
    expect(violation(p, claims)).toBe(want);
  });

  it("every required claim must be satisfied", () => {
    const p = policy({ requiredClaims: { hd: ["corp.com"], groups: ["platform"] } });
    expect(violation(p, { hd: "corp.com", groups: ["platform"] })).toBeUndefined();
    expect(violation(p, { hd: "corp.com", groups: ["sales"] })).toBe('required claim "groups" not satisfied');
  });

  it("evaluates required claims in sorted key order", () => {
    const p = policy({ requiredClaims: { zeta: ["ok"], alpha: ["ok"], mid: ["ok"] } });
    expect(violation(p, {})).toBe('required claim "alpha" not satisfied');
    expect(violation(p, { alpha: "ok" })).toBe('required claim "mid" not satisfied');
  });

  it("does not read claims from the prototype chain", () => {
    const p = policy({ requiredClaims: { polluted: ["yes"] } });
    const claims = Object.create({ polluted: "yes" }) as Record<string, unknown>;
    expect(violation(p, claims)).toBe('required claim "polluted" not satisfied');
  });
});

describe("checkPolicy: subjects", () => {
  const SUBJECT_DENIED = "subject not allowed";

  it.each<[string, IdentityPolicy, string, string | undefined]>([
    ["subject on the allowlist passes", policy({ allowedSubjects: new Set(["alice", "bob"]) }), "bob", undefined],
    ["subject not on the allowlist fails", policy({ allowedSubjects: new Set(["alice"]) }), "mallory", SUBJECT_DENIED],
    ["allowlist match is exact, not a prefix", policy({ allowedSubjects: new Set(["alice"]) }), "alice2", SUBJECT_DENIED],
    ["subject starting with a prefix passes", policy({ subjectPrefixes: ["platform-"] }), "platform-ci", undefined],
    ["\"platform\" does not match prefix \"platform-\"", policy({ subjectPrefixes: ["platform-"] }), "platform", SUBJECT_DENIED],
    ["subject with no matching prefix fails", policy({ subjectPrefixes: ["platform-", "ops-"] }), "sales-1", SUBJECT_DENIED],
    ["second prefix matches", policy({ subjectPrefixes: ["platform-", "ops-"] }), "ops-1", undefined],
    [
      "with both lists set, an allowlisted subject passes",
      policy({ allowedSubjects: new Set(["alice"]), subjectPrefixes: ["platform-"] }),
      "alice",
      undefined,
    ],
    [
      "with both lists set, a prefixed subject passes",
      policy({ allowedSubjects: new Set(["alice"]), subjectPrefixes: ["platform-"] }),
      "platform-x",
      undefined,
    ],
    [
      "with both lists set, a subject in neither fails",
      policy({ allowedSubjects: new Set(["alice"]), subjectPrefixes: ["platform-"] }),
      "mallory",
      SUBJECT_DENIED,
    ],
    ["empty subject lists allow any subject", policy({ requiredClaims: { hd: ["corp.com"] } }), "anyone", undefined],
  ])("%s", (_name, p, subject, want) => {
    expect(violation(p, { hd: "corp.com" }, subject)).toBe(want);
  });

  it("checks required claims before subjects", () => {
    const p = policy({ requiredClaims: { hd: ["corp.com"] }, allowedSubjects: new Set(["alice"]) });
    expect(violation(p, { hd: "evil.com" }, "mallory")).toBe(HD_DENIED);
  });
});

describe("empty policy", () => {
  it("isEmptyPolicy is true for a policy with no rules", () => {
    expect(isEmptyPolicy(policy())).toBe(true);
  });

  it.each<[string, IdentityPolicy]>([
    ["a required claim", policy({ requiredClaims: { hd: ["corp.com"] } })],
    ["an allowed subject", policy({ allowedSubjects: new Set(["alice"]) })],
    ["a subject prefix", policy({ subjectPrefixes: ["platform-"] })],
  ])("isEmptyPolicy is false with %s", (_name, p) => {
    expect(isEmptyPolicy(p)).toBe(false);
  });

  it.each<[Record<string, unknown>, string]>([
    [{}, ""],
    [{ hd: null }, "anyone"],
    [{ groups: { nested: true } }, "platform"],
  ])("passes everything (%j, %j)", (claims, subject) => {
    expect(violation(policy(), claims, subject)).toBeUndefined();
  });
});

describe("violation messages never include claim values or the subject", () => {
  const SECRET = "s3cr3t-value-zz9";

  it.each<[string, IdentityPolicy, Record<string, unknown>, string]>([
    ["string claim", policy({ requiredClaims: { hd: ["corp.com"] } }), { hd: SECRET }, "x"],
    ["array claim", policy({ requiredClaims: { hd: ["corp.com"] } }), { hd: [SECRET] }, "x"],
    ["object claim", policy({ requiredClaims: { hd: ["corp.com"] } }), { hd: { v: SECRET } }, "x"],
    ["subject", policy({ allowedSubjects: new Set(["alice"]) }), {}, SECRET],
    ["prefix subject", policy({ subjectPrefixes: ["platform-"] }), {}, SECRET],
  ])("%s", (_name, p, claims, subject) => {
    const msg = violation(p, claims, subject);
    expect(msg).toBeDefined();
    expect(msg).not.toContain(SECRET);
    expect(msg).not.toContain("corp.com");
    expect(msg).not.toContain("alice");
    expect(msg).not.toContain("platform-");
  });
});

describe("parsePolicyConfig", () => {
  const RC = "STEAMPIPE_MCP_REQUIRED_CLAIMS";
  const AS = "STEAMPIPE_MCP_ALLOWED_SUBJECTS";
  const SP = "STEAMPIPE_MCP_SUBJECT_PREFIXES";
  const SENTINEL = "sentinel-do-not-echo";

  function parseError(env: Record<string, string>): ConfigError {
    try {
      parsePolicyConfig(env);
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      return e as ConfigError;
    }
    throw new Error("expected parsePolicyConfig to throw");
  }

  it("defaults to an empty policy", () => {
    const p = parsePolicyConfig({});
    expect(isEmptyPolicy(p)).toBe(true);
    expect(p.allowedSubjects).toBeInstanceOf(Set);
    expect(p.subjectPrefixes).toEqual([]);
    expect(Object.keys(p.requiredClaims)).toEqual([]);
  });

  it("treats empty-string variables as unset", () => {
    expect(isEmptyPolicy(parsePolicyConfig({ [RC]: "", [AS]: "", [SP]: "" }))).toBe(true);
  });

  it("parses all three variables", () => {
    const p = parsePolicyConfig({
      [RC]: '{"hd":["corp.com"],"groups":["platform","ops"]}',
      [AS]: '["alice","bob"]',
      [SP]: '["platform-"]',
    });
    expect(p.requiredClaims).toEqual({ hd: ["corp.com"], groups: ["platform", "ops"] });
    expect([...p.allowedSubjects].sort()).toEqual(["alice", "bob"]);
    expect(p.allowedSubjects).toBeInstanceOf(Set);
    expect(p.subjectPrefixes).toEqual(["platform-"]);
  });

  it("a parsed policy is enforced by checkPolicy", () => {
    const p = parsePolicyConfig({ [RC]: '{"hd":["corp.com"]}', [SP]: '["platform-"]' });
    expect(violation(p, { hd: "corp.com" }, "platform-ci")).toBeUndefined();
    expect(violation(p, { hd: "corp.com" }, "platform")).toBe("subject not allowed");
  });

  it("a __proto__ claim key stays an own key and does not change the prototype", () => {
    const p = parsePolicyConfig({ [RC]: '{"__proto__":["x"]}' });
    expect(Object.hasOwn(p.requiredClaims, "__proto__")).toBe(true);
    expect(isEmptyPolicy(p)).toBe(false);
    const claims = JSON.parse('{"__proto__":"x"}') as Record<string, unknown>;
    expect(violation(p, claims)).toBeUndefined();
    expect(violation(p, {})).toBe('required claim "__proto__" not satisfied');
  });

  it.each<[string, string, string]>([
    ["non-array ALLOWED_SUBJECTS (string)", AS, `"${SENTINEL}"`],
    ["non-array ALLOWED_SUBJECTS (object)", AS, `{"${SENTINEL}":1}`],
    ["non-array SUBJECT_PREFIXES", SP, `{"${SENTINEL}":1}`],
    ["REQUIRED_CLAIMS as an array", RC, `["${SENTINEL}"]`],
    ["REQUIRED_CLAIMS as null", RC, "null"],
    ["REQUIRED_CLAIMS as a string", RC, `"${SENTINEL}"`],
    ["REQUIRED_CLAIMS value not an array", RC, `{"${SENTINEL}":"corp.com"}`],
    ["REQUIRED_CLAIMS value with a non-string element", RC, `{"${SENTINEL}":["a",1]}`],
    ["REQUIRED_CLAIMS value as an empty array", RC, `{"${SENTINEL}":[]}`],
    ["REQUIRED_CLAIMS value with an empty string", RC, `{"${SENTINEL}":[""]}`],
    ["REQUIRED_CLAIMS empty key", RC, `{"":["${SENTINEL}"]}`],
    ["ALLOWED_SUBJECTS non-string element", AS, `["${SENTINEL}",1]`],
    ["ALLOWED_SUBJECTS empty string", AS, `["${SENTINEL}",""]`],
    ["SUBJECT_PREFIXES non-string element", SP, `[null,"${SENTINEL}"]`],
    ["SUBJECT_PREFIXES empty string (would match every subject)", SP, `["${SENTINEL}",""]`],
  ])("%s throws naming the variable without echoing the value", (_name, name, value) => {
    const err = parseError({ [name]: value });
    expect(err.message).toContain(name);
    expect(err.message).not.toContain(SENTINEL);
  });

  // V8's JSON.parse message quotes only the first few characters of the
  // input, so the sentinel here is short enough to appear in full if the
  // parser's message were ever echoed.
  it.each<[string, string, string]>([
    ["REQUIRED_CLAIMS", RC, "{\"a\":ZQX}"],
    ["ALLOWED_SUBJECTS", AS, "[ZQX"],
    ["SUBJECT_PREFIXES", SP, "ZQX]"],
  ])("invalid JSON in %s throws naming the variable without echoing the value", (_name, name, value) => {
    const err = parseError({ [name]: value });
    expect(err.message).toContain(name);
    expect(err.message).not.toContain("ZQX");
  });

  describe("length and count limits", () => {
    const at = (n: number) => "a".repeat(n);
    const many = (n: number) => JSON.stringify(Array.from({ length: n }, (_, i) => `s${i}`));

    it.each<[string, string, string]>([
      ["a 256-character subject", AS, JSON.stringify([at(256)])],
      ["a 256-character prefix", SP, JSON.stringify([at(256)])],
      ["a 256-character claim value", RC, JSON.stringify({ hd: [at(256)] })],
      ["a 256-character claim key", RC, JSON.stringify({ [at(256)]: ["x"] })],
      ["1024 subjects", AS, many(1024)],
      ["64 prefixes", SP, many(64)],
    ])("accepts %s", (_name, name, value) => {
      expect(() => parsePolicyConfig({ [name]: value })).not.toThrow();
    });

    it.each<[string, string, string]>([
      ["a 257-character subject", AS, JSON.stringify([`${SENTINEL}${at(257 - SENTINEL.length)}`])],
      ["a 257-character prefix", SP, JSON.stringify([`${SENTINEL}${at(257 - SENTINEL.length)}`])],
      ["a 257-character claim value", RC, JSON.stringify({ hd: [`${SENTINEL}${at(257 - SENTINEL.length)}`] })],
      ["a 257-character claim key", RC, JSON.stringify({ [`${SENTINEL}${at(257 - SENTINEL.length)}`]: ["x"] })],
      ["1025 subjects", AS, many(1025)],
      ["65 prefixes", SP, many(65)],
    ])("rejects %s, naming the variable", (_name, name, value) => {
      const err = parseError({ [name]: value });
      expect(err.message).toContain(name);
      expect(err.message).not.toContain(SENTINEL);
    });
  });
});

describe("loadConfig wiring", () => {
  const HTTP = { STEAMPIPE_MCP_TRANSPORT: "http" };

  it("exposes the parsed policy on ServerConfig in http mode", () => {
    const cfg = loadConfig(
      { ...HTTP, STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"hd":["corp.com"]}', STEAMPIPE_MCP_SUBJECT_PREFIXES: '["platform-"]' },
      EMPTY_ARGV,
    );
    expect(cfg.policy).toBeDefined();
    expect(cfg.policy?.requiredClaims).toEqual({ hd: ["corp.com"] });
    expect(cfg.policy?.subjectPrefixes).toEqual(["platform-"]);
  });

  it("defaults to an empty policy in http mode", () => {
    const cfg = loadConfig(HTTP, EMPTY_ARGV);
    expect(cfg.policy).toBeDefined();
    expect(isEmptyPolicy(cfg.policy!)).toBe(true);
  });

  it("rejects an invalid policy variable in http mode with ConfigError", () => {
    expect(() => loadConfig({ ...HTTP, STEAMPIPE_MCP_ALLOWED_SUBJECTS: '"alice"' }, EMPTY_ARGV)).toThrow(ConfigError);
    expect(() => loadConfig({ ...HTTP, STEAMPIPE_MCP_ALLOWED_SUBJECTS: '"alice"' }, EMPTY_ARGV)).toThrow(
      /STEAMPIPE_MCP_ALLOWED_SUBJECTS/,
    );
  });

  it("ignores policy variables in stdio mode, like every other auth setting", () => {
    const cfg = loadConfig({ STEAMPIPE_MCP_ALLOWED_SUBJECTS: "not json" }, EMPTY_ARGV);
    expect(cfg.policy).toBeUndefined();
  });
});
