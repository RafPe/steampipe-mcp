import type { CheckStatus } from "../http/ready.js";
import { boundForLog } from "../services/logbound.js";
import { logger } from "../services/logger.js";

export interface RetryLoaderOptions {
  /** First retry delay; doubles after every failure. Default 1000. */
  initialDelayMs?: number;
  /** Cap on the delay before jitter. Default 60000. */
  maxDelayMs?: number;
  /** Each delay is scaled by a random factor in [1 - jitter, 1 + jitter]. Default 0.2. */
  jitter?: number;
  /** Test seam. The default is an unref'd timer that ends early on abort. */
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  /** What is being loaded, for log lines. */
  name?: string;
}

export interface RetryLoader<T> {
  /** The loaded value, or `undefined` until a fetch has succeeded. */
  current(): T | undefined;
  /** `ready` once loaded, `pending` until then. */
  status(): CheckStatus;
  /** Abort any in-flight fetch and stop the retry schedule. */
  dispose(): void;
}

function defaultSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    // Unref'd, so a pending retry never keeps the process alive on its own.
    const timer = setTimeout(done, ms);
    timer.unref?.();
    signal.addEventListener("abort", done, { once: true });
  });
}

/**
 * Call `fetcher` in the background until it succeeds. Fetching starts at
 * once; after a failure (a synchronous throw included) it waits
 * `initialDelayMs`, doubling after every further failure up to `maxDelayMs`,
 * each wait jittered by ±`jitter`. The jitter applies after the cap, so a
 * capped wait is `maxDelayMs` ±20% by default and clients that started
 * together do not stay in step.
 *
 * `dispose()` aborts the signal handed to the in-flight fetch and to the
 * pending sleep. A result or failure that lands afterwards is ignored and
 * nothing more is scheduled, even if `sleep` ignores the abort.
 */
export function createRetryLoader<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  opts: RetryLoaderOptions = {},
): RetryLoader<T> {
  const maxDelayMs = opts.maxDelayMs ?? 60000;
  const jitter = opts.jitter ?? 0.2;
  const sleep = opts.sleep ?? defaultSleep;
  const name = opts.name ?? "Background load";
  const controller = new AbortController();
  const { signal } = controller;
  let value: T | undefined;

  const run = async () => {
    let delay = Math.min(opts.initialDelayMs ?? 1000, maxDelayMs);
    for (let attempt = 1; !signal.aborted; attempt++) {
      try {
        const result = await fetcher(signal);
        if (signal.aborted) return;
        value = result;
        logger.info(`${name} succeeded after ${attempt} attempt${attempt === 1 ? "" : "s"}`);
        return;
      } catch (error) {
        if (signal.aborted) return;
        const wait = Math.round(delay * (1 + jitter * (2 * Math.random() - 1)));
        logger.warn(
          `${name} failed (attempt ${attempt}); retrying in ${wait}ms`,
          boundForLog(error instanceof Error ? error.message : error),
        );
        delay = Math.min(delay * 2, maxDelayMs);
        await sleep(wait, signal).catch(() => {});
      }
    }
  };
  void run();

  return {
    current: () => value,
    status: () => (value === undefined ? "pending" : "ready"),
    dispose: () => controller.abort(),
  };
}
