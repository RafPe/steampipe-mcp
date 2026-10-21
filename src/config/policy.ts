import type { IdentityPolicy } from "../auth/policy.js";

export type PolicyConfig = IdentityPolicy;

export function parsePolicyConfig(_env: NodeJS.ProcessEnv): PolicyConfig {
  return { requiredClaims: {}, allowedSubjects: new Set(), subjectPrefixes: [] };
}
