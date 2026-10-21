export class PolicyViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyViolation";
  }
}

export interface IdentityPolicy {
  requiredClaims: Record<string, string[]>;
  allowedSubjects: Set<string>;
  subjectPrefixes: string[];
}

export function isEmptyPolicy(_p: IdentityPolicy): boolean {
  return false;
}

export function checkPolicy(_p: IdentityPolicy, _claims: Record<string, unknown>, _subject: string): void {}
