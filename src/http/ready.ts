import type { RequestHandler } from "express";
import type { DatabaseService } from "../services/database.js";
import { boundForLog } from "../services/logbound.js";
import { logger } from "../services/logger.js";

export type CheckStatus = "ready" | "pending" | "failing";

export interface ReadinessCheck {
  name: string;
  /**
   * Checks sharing a group are alternatives: the group needs only one
   * `ready` member. A check without a group must itself be `ready`.
   */
  group?: string;
  check(signal: AbortSignal): Promise<CheckStatus>;
}

export interface ReadinessResult {
  ready: boolean;
  /** Present (and true) only when ready while some check is not `ready`. */
  degraded?: true;
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
 *
 * Ready means every ungrouped check is `ready` and every group has at least
 * one `ready` member; ready with any check not `ready` is `degraded`.
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
    const groups = new Map<string, boolean>();
    let ready = true;
    this.checks.forEach((c, i) => {
      checks[c.name] = statuses[i];
      if (c.group === undefined) ready &&= statuses[i] === "ready";
      else groups.set(c.group, (groups.get(c.group) ?? false) || statuses[i] === "ready");
    });
    ready &&= [...groups.values()].every(Boolean);
    const degraded = ready && statuses.some((s) => s !== "ready");
    return { ready, ...(degraded && { degraded: true as const }), checks };
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
          logger.debug(`Readiness check ${boundForLog(c.name)} failed:`, boundForLog(error instanceof Error ? error.message : error));
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
 * The production readiness checks: `db` runs `select 1` on a dedicated
 * short-lived client (see `DatabaseService.ping`), never the pool. A
 * rejection counts as `failing`. `extra` checks (e.g. auth's) are
 * registered after it; `opts` is passed to `Readiness`.
 */
export function buildReadiness(
  db: Pick<DatabaseService, "ping">,
  extra: ReadinessCheck[] = [],
  opts?: ConstructorParameters<typeof Readiness>[0],
): Readiness {
  const readiness = new Readiness(opts);
  readiness.register({ name: "db", check: async () => (await db.ping(2000), "ready") });
  for (const c of extra) readiness.register(c);
  return readiness;
}

/**
 * `GET /readyz`: 200 `{"status":"ready","checks":{...}}` (plus
 * `"degraded":true` when a grouped check is not ready) or 503
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
    res.status(result.ready ? 200 : 503).json({
      status: result.ready ? "ready" : "not_ready",
      ...(result.degraded && { degraded: true }),
      checks: result.checks,
    });
  };
}
