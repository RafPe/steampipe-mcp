// RED-phase stub: real signatures, no enforcement.
export interface FetchPolicy {
  allowedHosts: string[];
  insecureAuthorities: string[];
  timeoutMs: number;
  maxBytes: number;
}

export type FetchRefusedCause = "policy" | "redirect" | "timeout" | "too_large" | "network";

export class FetchRefused extends Error {
  constructor(
    readonly cause_: FetchRefusedCause,
    message: string,
  ) {
    super(message);
    this.name = "FetchRefused";
  }
}

export const DEFAULT_TIMEOUT_MS = 5000;
export const DEFAULT_MAX_BYTES = 65536;

export const GOOGLE_FETCH_POLICY: FetchPolicy = {
  allowedHosts: [],
  insecureAuthorities: [],
  timeoutMs: DEFAULT_TIMEOUT_MS,
  maxBytes: DEFAULT_MAX_BYTES,
};

export function assertAllowedUrl(_url: URL, _policy: FetchPolicy): void {}

export function guardedFetch(_policy: FetchPolicy): typeof fetch {
  return fetch;
}
