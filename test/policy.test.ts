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

const EV = policy({ requiredClaims: { email_verified: ["true"] } });
const EV_DENIED = 'required claim "email_verified" not satisfied';

// Every row pairs a claim set that must pass with one that must be denied,
// so neither a no-op nor an always-deny evaluator can satisfy any row.
describe("checkPolicy: required claims", () => {
  it.each<[string, IdentityPolicy, Record<string, unknown>, Record<string, unknown>, string]>([
    ["string equal to an allowed value passes, any other string fails", HD, { hd: "corp.com" }, { hd: "evil.com" }, HD_DENIED],
    ["string equal to the second allowed value passes", HD, { hd: "other.com" }, { hd: "another.com" }, HD_DENIED],
    ["string match is exact (case-sensitive)", HD, { hd: "corp.com" }, { hd: "CORP.com" }, HD_DENIED],
    ["array intersecting the allowed values passes, one with no allowed value fails", HD, { hd: ["x", "corp.com"] }, { hd: ["x", "y"] }, HD_DENIED],
    ["empty array fails", HD, { hd: ["corp.com"] }, { hd: [] }, HD_DENIED],
    ["array ignores non-string elements but still matches a string", HD, { hd: [1, null, "corp.com"] }, { hd: [1, null, {}] }, HD_DENIED],
    ["array whose only match is a non-string element fails", policy({ requiredClaims: { n: ["1"] } }), { n: ["1"] }, { n: [1] }, 'required claim "n" not satisfied'],
    ["boolean true matches \"true\"", EV, { email_verified: true }, { email_verified: false }, EV_DENIED],
    ["boolean false does not match \"true\"", EV, { email_verified: "true" }, { email_verified: false }, EV_DENIED],
    ["number matches its String()", policy({ requiredClaims: { level: ["3"] } }), { level: 3 }, { level: 4 }, 'required claim "level" not satisfied'],
    ["absent claim fails", HD, { hd: "corp.com" }, {}, HD_DENIED],
    ["null claim fails", HD, { hd: "corp.com" }, { hd: null }, HD_DENIED],
    ["object claim fails", HD, { hd: "corp.com" }, { hd: { value: "corp.com" } }, HD_DENIED],
    ["object whose String() would match fails", policy({ requiredClaims: { o: ["[object Object]"] } }), { o: "[object Object]" }, { o: {} }, 'required claim "o" not satisfied'],
    ["undefined claim fails", HD, { hd: "corp.com" }, { hd: undefined }, HD_DENIED],
  ])("%s", (_name, p, passing, failing, denied) => {
    expect(violation(p, passing)).toBeUndefined();
    expect(violation(p, failing)).toBe(denied);
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
    expect(violation(p, { polluted: "yes" })).toBeUndefined();
  });
});

describe("checkPolicy: subjects", () => {
  const SUBJECT_DENIED = "subject not allowed";

  const BOTH = policy({ allowedSubjects: new Set(["alice"]), subjectPrefixes: ["platform-"] });

  // Every row pairs a subject that must pass with one that must be denied.
  it.each<[string, IdentityPolicy, string, string]>([
    ["subject on the allowlist passes, one off it fails", policy({ allowedSubjects: new Set(["alice", "bob"]) }), "bob", "mallory"],
    ["allowlist match is exact, not a prefix", policy({ allowedSubjects: new Set(["alice"]) }), "alice", "alice2"],
    ["subject starting with a prefix passes", policy({ subjectPrefixes: ["platform-"] }), "platform-ci", "sales-1"],
    ["\"platform\" does not match prefix \"platform-\"", policy({ subjectPrefixes: ["platform-"] }), "platform-", "platform"],
    ["second prefix matches", policy({ subjectPrefixes: ["platform-", "ops-"] }), "ops-1", "sales-1"],
    ["with both lists set, an allowlisted subject passes", BOTH, "alice", "mallory"],
    ["with both lists set, a prefixed subject passes", BOTH, "platform-x", "platform"],
  ])("%s", (_name, p, passing, failing) => {
    expect(violation(p, { hd: "corp.com" }, passing)).toBeUndefined();
    expect(violation(p, { hd: "corp.com" }, failing)).toBe(SUBJECT_DENIED);
  });

  it("empty subject lists allow any subject; required claims still apply", () => {
    const p = policy({ requiredClaims: { hd: ["corp.com"] } });
    expect(violation(p, { hd: "corp.com" }, "anyone")).toBeUndefined();
    expect(violation(p, { hd: "corp.com" }, "")).toBeUndefined();
    expect(violation(p, { hd: "evil.com" }, "anyone")).toBe(HD_DENIED);
  });

  it("checks required claims before subjects", () => {
    const p = policy({ requiredClaims: { hd: ["corp.com"] }, allowedSubjects: new Set(["alice"]) });
    expect(violation(p, { hd: "evil.com" }, "mallory")).toBe(HD_DENIED);
    expect(violation(p, { hd: "corp.com" }, "mallory")).toBe("subject not allowed");
    expect(violation(p, { hd: "corp.com" }, "alice")).toBeUndefined();
  });
});

describe("empty policy", () => {
  it("isEmptyPolicy is true for a policy with no rules", () => {
    expect(isEmptyPolicy(policy())).toBe(true);
    expect(isEmptyPolicy(policy({ subjectPrefixes: ["platform-"] }))).toBe(false);
  });

  it.each<[string, IdentityPolicy]>([
    ["a required claim", policy({ requiredClaims: { hd: ["corp.com"] } })],
    ["an allowed subject", policy({ allowedSubjects: new Set(["alice"]) })],
    ["a subject prefix", policy({ subjectPrefixes: ["platform-"] })],
  ])("isEmptyPolicy is false with %s", (_name, p) => {
    expect(isEmptyPolicy(p)).toBe(false);
    expect(isEmptyPolicy(policy())).toBe(true);
  });

  it.each<[Record<string, unknown>, string]>([
    [{}, ""],
    [{ hd: null }, "anyone"],
    [{ groups: { nested: true } }, "platform"],
  ])("passes everything (%j, %j)", (claims, subject) => {
    expect(violation(policy(), claims, subject)).toBeUndefined();
    // Control: the same identity is denied once any rule exists.
    expect(violation(policy({ requiredClaims: { hd: ["corp.com"] } }), claims, subject)).toBe(HD_DENIED);
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
    // Control: the same parser returns a non-empty policy when configured.
    expect(isEmptyPolicy(parsePolicyConfig({ [SP]: '["platform-"]' }))).toBe(false);
  });

  it("treats empty-string variables as unset", () => {
    expect(isEmptyPolicy(parsePolicyConfig({ [RC]: "", [AS]: "", [SP]: "" }))).toBe(true);
    expect(isEmptyPolicy(parsePolicyConfig({ [RC]: "", [AS]: '["alice"]', [SP]: "" }))).toBe(false);
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

    it("accepts a 256-character subject and keeps it", () => {
      const p = parsePolicyConfig({ [AS]: JSON.stringify([at(256)]) });
      expect(p.allowedSubjects.has(at(256))).toBe(true);
      expect(p.allowedSubjects.size).toBe(1);
    });

    it("accepts a 256-character prefix and keeps it", () => {
      expect(parsePolicyConfig({ [SP]: JSON.stringify([at(256)]) }).subjectPrefixes).toEqual([at(256)]);
    });

    it("accepts a 256-character claim value and keeps it", () => {
      const p = parsePolicyConfig({ [RC]: JSON.stringify({ hd: [at(256)] }) });
      expect(p.requiredClaims).toEqual({ hd: [at(256)] });
    });

    it("accepts a 256-character claim key and keeps it", () => {
      const p = parsePolicyConfig({ [RC]: JSON.stringify({ [at(256)]: ["x"] }) });
      expect(p.requiredClaims).toEqual({ [at(256)]: ["x"] });
    });

    it("accepts 1024 subjects and keeps them all", () => {
      const p = parsePolicyConfig({ [AS]: many(1024) });
      expect(p.allowedSubjects.size).toBe(1024);
      expect(p.allowedSubjects.has("s0")).toBe(true);
      expect(p.allowedSubjects.has("s1023")).toBe(true);
    });

    it("accepts 64 prefixes and keeps them all", () => {
      const p = parsePolicyConfig({ [SP]: many(64) });
      expect(p.subjectPrefixes).toHaveLength(64);
      expect(p.subjectPrefixes[63]).toBe("s63");
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
  // A complete google config: the only mode that enforces a policy (R6).
  const GOOGLE = {
    ...HTTP,
    STEAMPIPE_MCP_AUTH_MODE: "google",
    STEAMPIPE_MCP_PUBLIC_URL: "https://mcp.example.com",
    STEAMPIPE_MCP_GOOGLE_CLIENT_ID: "client-id",
    STEAMPIPE_MCP_ALLOWED_DOMAINS: "corp.com",
  };
  const TOKEN = { ...HTTP, STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_AUTH_TOKEN: "t".repeat(40) };

  it("exposes the parsed policy on ServerConfig in http mode", () => {
    const cfg = loadConfig(
      { ...GOOGLE, STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"hd":["corp.com"]}', STEAMPIPE_MCP_SUBJECT_PREFIXES: '["platform-"]' },
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
    // Control: a configured variable makes it non-empty.
    const configured = loadConfig({ ...GOOGLE, STEAMPIPE_MCP_ALLOWED_SUBJECTS: '["alice"]' }, EMPTY_ARGV);
    expect(configured.policy?.allowedSubjects.has("alice")).toBe(true);
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
    // Control: the same value is parsed, and rejected, in http mode.
    expect(() => loadConfig({ ...HTTP, STEAMPIPE_MCP_ALLOWED_SUBJECTS: "not json" }, EMPTY_ARGV)).toThrow(ConfigError);
  });

  describe("refuses a policy the auth mode cannot enforce (R6)", () => {
    /** The ConfigError loadConfig throws; fails the test if it does not throw one. */
    function configError(env: NodeJS.ProcessEnv): ConfigError {
      try {
        loadConfig(env, EMPTY_ARGV);
      } catch (error) {
        expect(error).toBeInstanceOf(ConfigError);
        return error as ConfigError;
      }
      throw new Error("expected loadConfig to throw");
    }

    it("throws for AUTH_MODE=token with REQUIRED_CLAIMS, naming the variable but not its value", () => {
      const err = configError({ ...TOKEN, STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"hd":["sentinel-corp.com"]}' });
      expect(err.message).toContain("STEAMPIPE_MCP_REQUIRED_CLAIMS");
      expect(err.message).toContain("STEAMPIPE_MCP_AUTH_MODE");
      expect(err.message).not.toContain("sentinel-corp.com");
      expect(err.message).not.toContain("STEAMPIPE_MCP_SUBJECT_PREFIXES");
    });

    it("throws for AUTH_MODE=none with SUBJECT_PREFIXES, naming the variable", () => {
      const err = configError({ ...HTTP, STEAMPIPE_MCP_SUBJECT_PREFIXES: '["platform-"]' });
      expect(err.message).toContain("STEAMPIPE_MCP_SUBJECT_PREFIXES");
      expect(err.message).not.toContain("platform-");
    });

    it("throws for AUTH_MODE=none with ALLOWED_SUBJECTS, naming every variable that is set", () => {
      const err = configError({
        ...HTTP,
        STEAMPIPE_MCP_AUTH_MODE: "none",
        STEAMPIPE_MCP_ALLOWED_SUBJECTS: '["alice"]',
        STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"hd":["corp.com"]}',
      });
      expect(err.message).toContain("STEAMPIPE_MCP_ALLOWED_SUBJECTS");
      expect(err.message).toContain("STEAMPIPE_MCP_REQUIRED_CLAIMS");
    });

    it("loads a google config with a policy", () => {
      const cfg = loadConfig(
        {
          ...GOOGLE,
          STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"hd":["corp.com"]}',
          STEAMPIPE_MCP_ALLOWED_SUBJECTS: '["alice"]',
          STEAMPIPE_MCP_SUBJECT_PREFIXES: '["platform-"]',
        },
        EMPTY_ARGV,
      );
      expect(cfg.auth.mode).toBe("google");
      expect(isEmptyPolicy(cfg.policy!)).toBe(false);
    });

    it("loads token and none modes with no policy set", () => {
      expect(loadConfig(TOKEN, EMPTY_ARGV).auth.mode).toBe("token");
      expect(loadConfig(HTTP, EMPTY_ARGV).auth.mode).toBe("none");
    });

    it("ignores policy variables on stdio, even with AUTH_MODE=token", () => {
      const env = { STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_REQUIRED_CLAIMS: '{"hd":["corp.com"]}' };
      const cfg = loadConfig(env, EMPTY_ARGV);
      expect(cfg.policy).toBeUndefined();
      // Control: the same policy with a valid token config is refused in http mode.
      expect(() => loadConfig({ ...TOKEN, ...env }, EMPTY_ARGV)).toThrow(ConfigError);
    });
  });
});
