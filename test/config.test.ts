import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../src/config.js";

const EMPTY_ENV: NodeJS.ProcessEnv = {};
const EMPTY_ARGV: string[] = ["node", "index.js"];

function envWith(vars: Record<string, string>): NodeJS.ProcessEnv {
  return { ...vars };
}

describe("loadConfig", () => {
  describe("defaults (empty env)", () => {
    const cfg = loadConfig(EMPTY_ENV, EMPTY_ARGV);

    it("defaults to stdio transport", () => {
      expect(cfg.transport).toBe("stdio");
    });

    it("defaults the connection string", () => {
      expect(cfg.db.connectionString).toBe("postgresql://steampipe@localhost:9193/steampipe");
    });

    it("defaults maxRows to 0 (unlimited) on stdio", () => {
      expect(cfg.db.maxRows).toBe(0);
    });

    it("defaults statementTimeoutMs and poolMax", () => {
      expect(cfg.db.statementTimeoutMs).toBe(120000);
      expect(cfg.db.poolMax).toBe(20);
    });

    it("defaults http settings", () => {
      expect(cfg.http.host).toBe("127.0.0.1");
      expect(cfg.http.port).toBe(27123);
      expect(cfg.http.path).toBe("/mcp");
      expect(cfg.http.publicUrl).toBeUndefined();
      expect(cfg.http.allowedOrigins).toEqual([]);
      expect(cfg.http.allowedHosts).toEqual([]);
      expect(cfg.http.maxBodyBytes).toBe(1048576);
      expect(cfg.http.rateLimitPerMin).toBe(60);
      expect(cfg.http.trustProxy).toBeUndefined();
    });

    it("defaults auth to none", () => {
      expect(cfg.auth.mode).toBe("none");
      expect(cfg.auth.token).toBeUndefined();
      expect(cfg.auth.googleClientId).toBeUndefined();
      expect(cfg.auth.allowedEmails).toEqual([]);
      expect(cfg.auth.allowedDomains).toEqual([]);
    });

    it("defaults allowInsecureRemote to false", () => {
      expect(cfg.allowInsecureRemote).toBe(false);
    });
  });

  describe("connection string resolution", () => {
    it("prefers argv[2] over the env var", () => {
      const cfg = loadConfig(
        envWith({ STEAMPIPE_MCP_WORKSPACE_DATABASE: "postgresql://env@h/d" }),
        ["node", "index.js", "postgresql://argv@h/d"],
      );
      expect(cfg.db.connectionString).toBe("postgresql://argv@h/d");
    });

    it("falls back to the env var when argv[2] is an empty string", () => {
      const cfg = loadConfig(
        envWith({ STEAMPIPE_MCP_WORKSPACE_DATABASE: "postgresql://env@h/d" }),
        ["node", "index.js", ""],
      );
      expect(cfg.db.connectionString).toBe("postgresql://env@h/d");
    });

    it("falls back to the default when both argv[2] and the env var are empty", () => {
      const cfg = loadConfig(envWith({ STEAMPIPE_MCP_WORKSPACE_DATABASE: "" }), ["node", "index.js", ""]);
      expect(cfg.db.connectionString).toBe("postgresql://steampipe@localhost:9193/steampipe");
    });
  });

  describe("MAX_ROWS (R1)", () => {
    it("defaults to 0 (unlimited) on stdio", () => {
      const cfg = loadConfig(envWith({ STEAMPIPE_MCP_TRANSPORT: "stdio" }), EMPTY_ARGV);
      expect(cfg.db.maxRows).toBe(0);
    });

    it("defaults to 10000 on http", () => {
      const cfg = loadConfig(
        envWith({ STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE: "true" }),
        EMPTY_ARGV,
      );
      expect(cfg.db.maxRows).toBe(10000);
    });

    it("an explicit MAX_ROWS overrides the default on stdio", () => {
      const cfg = loadConfig(envWith({ STEAMPIPE_MCP_MAX_ROWS: "5" }), EMPTY_ARGV);
      expect(cfg.db.maxRows).toBe(5);
    });

    it("an explicit MAX_ROWS overrides the default on http", () => {
      const cfg = loadConfig(
        envWith({
          STEAMPIPE_MCP_TRANSPORT: "http",
          STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE: "true",
          STEAMPIPE_MCP_MAX_ROWS: "5",
        }),
        EMPTY_ARGV,
      );
      expect(cfg.db.maxRows).toBe(5);
    });

    it("rejects a negative MAX_ROWS", () => {
      expect(() => loadConfig(envWith({ STEAMPIPE_MCP_MAX_ROWS: "-1" }), EMPTY_ARGV)).toThrow(ConfigError);
      expect(() => loadConfig(envWith({ STEAMPIPE_MCP_MAX_ROWS: "-1" }), EMPTY_ARGV)).toThrow(/MAX_ROWS/);
    });

    it("rejects a non-integer MAX_ROWS", () => {
      expect(() => loadConfig(envWith({ STEAMPIPE_MCP_MAX_ROWS: "3.5" }), EMPTY_ARGV)).toThrow(/MAX_ROWS/);
    });
  });

  describe("numeric validation (ports, timeouts, limits)", () => {
    it.each([
      ["STEAMPIPE_MCP_HTTP_PORT", "-1"],
      ["STEAMPIPE_MCP_HTTP_PORT", "0"],
      ["STEAMPIPE_MCP_HTTP_PORT", "65536"],
      ["STEAMPIPE_MCP_HTTP_PORT", "notanumber"],
      ["STEAMPIPE_MCP_MAX_BODY_BYTES", "-1"],
      ["STEAMPIPE_MCP_RATE_LIMIT_PER_MIN", "-1"],
      ["STEAMPIPE_MCP_STATEMENT_TIMEOUT_MS", "-1"],
      // R12: MAX_BODY_BYTES, RATE_LIMIT_PER_MIN, STATEMENT_TIMEOUT_MS must
      // each be >= 1 (0 is no longer accepted). MAX_ROWS is unaffected (it
      // still allows 0 - see the "MAX_ROWS (R1)" describe block).
      ["STEAMPIPE_MCP_MAX_BODY_BYTES", "0"],
      ["STEAMPIPE_MCP_RATE_LIMIT_PER_MIN", "0"],
      ["STEAMPIPE_MCP_STATEMENT_TIMEOUT_MS", "0"],
    ])("rejects %s=%s", (name, value) => {
      expect(() => loadConfig(envWith({ [name]: value }), EMPTY_ARGV)).toThrow(ConfigError);
      expect(() => loadConfig(envWith({ [name]: value }), EMPTY_ARGV)).toThrow(
        new RegExp(name.replace("STEAMPIPE_MCP_", "")),
      );
    });

    it("accepts a valid port", () => {
      const cfg = loadConfig(envWith({ STEAMPIPE_MCP_HTTP_PORT: "8080" }), EMPTY_ARGV);
      expect(cfg.http.port).toBe(8080);
    });

    it("accepts 1 for MAX_BODY_BYTES/RATE_LIMIT_PER_MIN/STATEMENT_TIMEOUT_MS (R12 minimum)", () => {
      const cfg = loadConfig(
        envWith({
          STEAMPIPE_MCP_MAX_BODY_BYTES: "1",
          STEAMPIPE_MCP_RATE_LIMIT_PER_MIN: "1",
          STEAMPIPE_MCP_STATEMENT_TIMEOUT_MS: "1",
        }),
        EMPTY_ARGV,
      );
      expect(cfg.http.maxBodyBytes).toBe(1);
      expect(cfg.http.rateLimitPerMin).toBe(1);
      expect(cfg.db.statementTimeoutMs).toBe(1);
    });
  });

  describe("non-loopback HTTP bind (ALLOW_INSECURE_REMOTE)", () => {
    it("throws when HTTP_HOST is non-loopback and AUTH_MODE is none, in http mode", () => {
      expect(() =>
        loadConfig(
          envWith({
            STEAMPIPE_MCP_TRANSPORT: "http",
            STEAMPIPE_MCP_HTTP_HOST: "0.0.0.0",
            STEAMPIPE_MCP_AUTH_MODE: "none",
          }),
          EMPTY_ARGV,
        ),
      ).toThrow(/ALLOW_INSECURE_REMOTE/);
    });

    it("does not throw when ALLOW_INSECURE_REMOTE is true, in http mode", () => {
      expect(() =>
        loadConfig(
          envWith({
            STEAMPIPE_MCP_TRANSPORT: "http",
            STEAMPIPE_MCP_HTTP_HOST: "0.0.0.0",
            STEAMPIPE_MCP_AUTH_MODE: "none",
            STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE: "true",
          }),
          EMPTY_ARGV,
        ),
      ).not.toThrow();
    });

    it("does not throw for a non-loopback bind when auth is enabled, in http mode", () => {
      expect(() =>
        loadConfig(
          envWith({
            STEAMPIPE_MCP_TRANSPORT: "http",
            STEAMPIPE_MCP_HTTP_HOST: "0.0.0.0",
            STEAMPIPE_MCP_AUTH_MODE: "token",
            STEAMPIPE_MCP_AUTH_TOKEN: "a".repeat(32),
          }),
          EMPTY_ARGV,
        ),
      ).not.toThrow();
    });

    it("does not throw for the default loopback bind", () => {
      expect(() => loadConfig(EMPTY_ENV, EMPTY_ARGV)).not.toThrow();
    });

    // R11: the bind guard is HTTP-only. A stdio user is never affected by a
    // stray HTTP_HOST/AUTH_MODE left over in their env, since stdio never
    // binds a port or serves auth at all.
    it("does not throw on stdio even with a non-loopback HTTP_HOST and AUTH_MODE=none", () => {
      expect(() =>
        loadConfig(
          envWith({ STEAMPIPE_MCP_HTTP_HOST: "0.0.0.0", STEAMPIPE_MCP_AUTH_MODE: "none" }),
          EMPTY_ARGV,
        ),
      ).not.toThrow();
    });
  });

  describe("AUTH_MODE=token", () => {
    it("throws when the token is shorter than 32 chars, in http mode", () => {
      expect(() =>
        loadConfig(
          envWith({
            STEAMPIPE_MCP_TRANSPORT: "http",
            STEAMPIPE_MCP_AUTH_MODE: "token",
            STEAMPIPE_MCP_AUTH_TOKEN: "short",
          }),
          EMPTY_ARGV,
        ),
      ).toThrow(ConfigError);
    });

    it("throws when no token is set, in http mode", () => {
      expect(() =>
        loadConfig(
          envWith({ STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_AUTH_MODE: "token" }),
          EMPTY_ARGV,
        ),
      ).toThrow(/AUTH_TOKEN/);
    });

    it("never echoes the token value in the error message", () => {
      const secret = "s3cr3t-tok"; // deliberately < 32 chars, so this throws
      let message = "";
      try {
        loadConfig(
          envWith({
            STEAMPIPE_MCP_TRANSPORT: "http",
            STEAMPIPE_MCP_AUTH_MODE: "token",
            STEAMPIPE_MCP_AUTH_TOKEN: secret,
          }),
          EMPTY_ARGV,
        );
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toMatch(/AUTH_TOKEN/);
      expect(message).not.toContain(secret);
    });

    it("accepts a 32+ char token, in http mode", () => {
      const token = "a".repeat(32);
      const cfg = loadConfig(
        envWith({ STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_AUTH_TOKEN: token }),
        EMPTY_ARGV,
      );
      expect(cfg.auth.mode).toBe("token");
      expect(cfg.auth.token).toBe(token);
    });

    // R11: auth requirements are HTTP-only. stdio never serves auth, so a
    // short/missing token must not block stdio startup.
    it("loads fine on stdio with AUTH_MODE=token and a short token", () => {
      expect(() =>
        loadConfig(
          envWith({ STEAMPIPE_MCP_AUTH_MODE: "token", STEAMPIPE_MCP_AUTH_TOKEN: "short" }),
          EMPTY_ARGV,
        ),
      ).not.toThrow();
    });
  });

  describe("AUTH_MODE=google", () => {
    const validGoogleEnv = {
      STEAMPIPE_MCP_TRANSPORT: "http",
      STEAMPIPE_MCP_AUTH_MODE: "google",
      STEAMPIPE_MCP_PUBLIC_URL: "https://mcp.example.com",
      STEAMPIPE_MCP_GOOGLE_CLIENT_ID: "client-id",
      STEAMPIPE_MCP_ALLOWED_DOMAINS: "example.com",
    };

    it("throws without PUBLIC_URL", () => {
      const { STEAMPIPE_MCP_PUBLIC_URL, ...rest } = validGoogleEnv;
      expect(() => loadConfig(envWith(rest), EMPTY_ARGV)).toThrow(/PUBLIC_URL/);
    });

    it("throws without GOOGLE_CLIENT_ID", () => {
      const { STEAMPIPE_MCP_GOOGLE_CLIENT_ID, ...rest } = validGoogleEnv;
      expect(() => loadConfig(envWith(rest), EMPTY_ARGV)).toThrow(/GOOGLE_CLIENT_ID/);
    });

    it("throws when both ALLOWED_EMAILS and ALLOWED_DOMAINS are empty", () => {
      const { STEAMPIPE_MCP_ALLOWED_DOMAINS, ...rest } = validGoogleEnv;
      expect(() => loadConfig(envWith(rest), EMPTY_ARGV)).toThrow(/ALLOWED_EMAILS|ALLOWED_DOMAINS/);
    });

    it("accepts a fully specified google config", () => {
      const cfg = loadConfig(envWith(validGoogleEnv), EMPTY_ARGV);
      expect(cfg.auth.mode).toBe("google");
      expect(cfg.auth.googleClientId).toBe("client-id");
      expect(cfg.auth.allowedDomains).toEqual(["example.com"]);
    });
  });

  describe("PUBLIC_URL", () => {
    it("throws for a non-loopback http URL, in http mode", () => {
      expect(() =>
        loadConfig(
          envWith({ STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_PUBLIC_URL: "http://mcp.example.com" }),
          EMPTY_ARGV,
        ),
      ).toThrow(/https/);
    });

    it("allows http for a loopback host, in http mode", () => {
      expect(() =>
        loadConfig(
          envWith({ STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_PUBLIC_URL: "http://localhost:3000" }),
          EMPTY_ARGV,
        ),
      ).not.toThrow();
    });

    it("allows https for a non-loopback host and parses it as a URL", () => {
      const cfg = loadConfig(
        envWith({ STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_PUBLIC_URL: "https://mcp.example.com" }),
        EMPTY_ARGV,
      );
      expect(cfg.http.publicUrl).toBeInstanceOf(URL);
      expect(cfg.http.publicUrl?.href).toBe("https://mcp.example.com/");
    });

    it("never echoes userinfo (e.g. a password) from an invalid PUBLIC_URL, in http mode", () => {
      let message = "";
      try {
        loadConfig(
          envWith({
            STEAMPIPE_MCP_TRANSPORT: "http",
            STEAMPIPE_MCP_PUBLIC_URL: "http://user:pass@mcp.example.com",
          }),
          EMPTY_ARGV,
        );
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toMatch(/https/);
      expect(message).not.toContain("pass");
    });

    // R11: the https-required check is HTTP-only. stdio never serves
    // publicUrl, so a non-loopback http:// value must not block startup.
    it("does not throw for a non-loopback http URL on stdio", () => {
      expect(() =>
        loadConfig(envWith({ STEAMPIPE_MCP_PUBLIC_URL: "http://mcp.example.com" }), EMPTY_ARGV),
      ).not.toThrow();
    });
  });

  describe("ALLOWED_EMAILS / ALLOWED_DOMAINS", () => {
    it("lower-cases, trims, and drops empty entries", () => {
      const cfg = loadConfig(
        envWith({ STEAMPIPE_MCP_ALLOWED_EMAILS: " Foo@Bar.com, , BAZ@Example.com " }),
        EMPTY_ARGV,
      );
      expect(cfg.auth.allowedEmails).toEqual(["foo@bar.com", "baz@example.com"]);
    });
  });

  describe("ALLOWED_ORIGINS / ALLOWED_HOSTS", () => {
    it("normalises origin entries to the exact form a browser sends", () => {
      const cfg = loadConfig(
        envWith({
          STEAMPIPE_MCP_ALLOWED_ORIGINS: "https://App.example.com/, https://b.example:443, http://c.example:8080/x",
        }),
        EMPTY_ARGV,
      );
      expect(cfg.http.allowedOrigins).toEqual(["https://app.example.com", "https://b.example", "http://c.example:8080"]);
    });

    it("keeps the literal null origin as-is", () => {
      const cfg = loadConfig(envWith({ STEAMPIPE_MCP_ALLOWED_ORIGINS: "null" }), EMPTY_ARGV);
      expect(cfg.http.allowedOrigins).toEqual(["null"]);
    });

    it("throws for an unparsable origin entry, naming the variable", () => {
      const env = envWith({ STEAMPIPE_MCP_ALLOWED_ORIGINS: "app.example.com" });
      expect(() => loadConfig(env, EMPTY_ARGV)).toThrow(ConfigError);
      expect(() => loadConfig(env, EMPTY_ARGV)).toThrow(/STEAMPIPE_MCP_ALLOWED_ORIGINS/);
    });

    it("throws for an entry with an opaque origin rather than silently allowlisting null", () => {
      // new URL("app.example.com:443").origin is "null" (non-special scheme).
      for (const entry of ["app.example.com:443", "file:///tmp/x"]) {
        expect(() => loadConfig(envWith({ STEAMPIPE_MCP_ALLOWED_ORIGINS: entry }), EMPTY_ARGV)).toThrow(
          /STEAMPIPE_MCP_ALLOWED_ORIGINS/,
        );
      }
    });

    it("accepts host entries with or without a port", () => {
      const cfg = loadConfig(
        envWith({ STEAMPIPE_MCP_ALLOWED_HOSTS: "mcp.example.com, MCP.example.com:443" }),
        EMPTY_ARGV,
      );
      expect(cfg.http.allowedHosts).toEqual(["mcp.example.com", "MCP.example.com:443"]);
    });

    it("throws for a host entry that is a URL or contains a path, naming the variable", () => {
      for (const entry of ["https://x", "mcp.example.com/mcp"]) {
        const env = envWith({ STEAMPIPE_MCP_ALLOWED_HOSTS: entry });
        expect(() => loadConfig(env, EMPTY_ARGV)).toThrow(ConfigError);
        expect(() => loadConfig(env, EMPTY_ARGV)).toThrow(/STEAMPIPE_MCP_ALLOWED_HOSTS/);
      }
    });
  });

  describe("TRUST_PROXY", () => {
    it("is undefined when unset", () => {
      expect(loadConfig(EMPTY_ENV, EMPTY_ARGV).http.trustProxy).toBeUndefined();
    });

    it("parses true/false", () => {
      expect(loadConfig(envWith({ STEAMPIPE_MCP_TRUST_PROXY: "true" }), EMPTY_ARGV).http.trustProxy).toBe(true);
      expect(loadConfig(envWith({ STEAMPIPE_MCP_TRUST_PROXY: "false" }), EMPTY_ARGV).http.trustProxy).toBe(false);
    });

    it("parses a non-negative integer hop count", () => {
      expect(loadConfig(envWith({ STEAMPIPE_MCP_TRUST_PROXY: "2" }), EMPTY_ARGV).http.trustProxy).toBe(2);
    });

    it("throws for anything else", () => {
      expect(() => loadConfig(envWith({ STEAMPIPE_MCP_TRUST_PROXY: "maybe" }), EMPTY_ARGV)).toThrow(
        /TRUST_PROXY/,
      );
      expect(() => loadConfig(envWith({ STEAMPIPE_MCP_TRUST_PROXY: "-1" }), EMPTY_ARGV)).toThrow(/TRUST_PROXY/);
    });
  });

  describe("TRANSPORT", () => {
    it("rejects an invalid value", () => {
      expect(() => loadConfig(envWith({ STEAMPIPE_MCP_TRANSPORT: "carrier-pigeon" }), EMPTY_ARGV)).toThrow(
        /TRANSPORT/,
      );
    });

    it("accepts http", () => {
      const cfg = loadConfig(
        envWith({ STEAMPIPE_MCP_TRANSPORT: "http", STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE: "true" }),
        EMPTY_ARGV,
      );
      expect(cfg.transport).toBe("http");
    });
  });
});
