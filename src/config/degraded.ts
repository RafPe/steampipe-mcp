import { ConfigError } from "../config.js";

export interface DegradedConfig {
  allowDegradedStart: boolean;
}

const NAME = "STEAMPIPE_MCP_ALLOW_DEGRADED_START";

/**
 * Parse `STEAMPIPE_MCP_ALLOW_DEGRADED_START` (`true` or `false`, default
 * `false`). Throws `ConfigError` naming the variable, never echoing its value.
 */
export function parseDegradedConfig(env: NodeJS.ProcessEnv): DegradedConfig {
  const value = env[NAME];
  if (value === undefined || value === "") {
    return { allowDegradedStart: false };
  }
  const normalized = value.trim().toLowerCase();
  if (normalized !== "true" && normalized !== "false") {
    throw new ConfigError(`${NAME} must be "true" or "false"`);
  }
  return { allowDegradedStart: normalized === "true" };
}
