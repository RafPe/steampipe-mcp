import type { RequestHandler } from "express";
import { logger } from "../services/logger.js";

export type CheckStatus = "ready" | "pending" | "failing";

export interface ReadinessCheck {
  name: string;
  check(signal: AbortSignal): Promise<CheckStatus>;
}

export interface ReadinessResult {
  ready: boolean;
  checks: Record<string, CheckStatus>;
}

const STATUSES: ReadonlySet<string> = new Set<CheckStatus>(["ready", "pending", "failing"]);

/**
 * Bounded, coalesced readiness evaluation for `GET /readyz`.
 *
 * Concurrent `evaluate()` calls share one in-flight evaluation and a settled
 * result is reused for `cacheMs`, so a burst of probes runs each check at most
 * once. Each check gets an `AbortSignal` that fires at `timeoutMs`; a check
 * that has not settled by then counts as `failing`, so an evaluation never
 * takes much longer than `timeoutMs` however wedged a dependency is.
 */
export class Readiness {
  private readonly timeoutMs: number;
  private readonly cacheMs: number;
  private readonly now: () => number;
  private readonly checks: ReadinessCheck[] = [];
  private inFlight: Promise<ReadinessResult> | undefined;
  private cached: { at: number; result: ReadinessResult } | undefined;

  constructor(opts: { timeoutMs?: number; cacheMs?: number; now?: () => number } = {}) {
    this.timeoutMs = opts.timeoutMs ?? 2000;
    this.cacheMs = opts.cacheMs ?? 1000;
    this.now = opts.now ?? Date.now;
  }

  register(c: ReadinessCheck): void {
    this.checks.push(c);
  }

  evaluate(): Promise<ReadinessResult> {
    if (this.cached && this.now() - this.cached.at < this.cacheMs) {
      return Promise.resolve(this.cached.result);
    }
    if (!this.inFlight) {
      this.inFlight = this.run()
        .then((result) => {
          this.cached = { at: this.now(), result };
          return result;
        })
        .finally(() => {
          this.inFlight = undefined;
        });
    }
    return this.inFlight;
  }

  private async run(): Promise<ReadinessResult> {
    const statuses = await Promise.all(this.checks.map((c) => this.runCheck(c)));
    const checks: Record<string, CheckStatus> = {};
    this.checks.forEach((c, i) => {
      checks[c.name] = statuses[i];
    });
    return { ready: statuses.every((s) => s === "ready"), checks };
  }

  private async runCheck(c: ReadinessCheck): Promise<CheckStatus> {
    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const timedOut = new Promise<CheckStatus>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve("failing");
      }, this.timeoutMs);
    });
    // Promise.resolve().then() also turns a synchronous throw into a rejection.
    const outcome = Promise.resolve()
      .then(() => c.check(controller.signal))
      .then(
        (status): CheckStatus => (STATUSES.has(status) ? status : "failing"),
        (error): CheckStatus => {
          logger.debug(`Readiness check ${c.name} failed:`, error instanceof Error ? error.message : String(error));
          return "failing";
        },
      );
    try {
      return await Promise.race([outcome, timedOut]);
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * `GET /readyz`: 200 `{"status":"ready","checks":{...}}` or 503
 * `{"status":"not_ready","checks":{...}}`. Only check names and statuses are
 * reported, never error details.
 */
export function readyHandler(r: Readiness): RequestHandler {
  return async (_req, res) => {
    let result: ReadinessResult;
    try {
      result = await r.evaluate();
    } catch {
      result = { ready: false, checks: {} };
    }
    res.set("Cache-Control", "no-store");
    res.status(result.ready ? 200 : 503).json({ status: result.ready ? "ready" : "not_ready", checks: result.checks });
  };
}
