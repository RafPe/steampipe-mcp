import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { closeHttpServerGracefully, type ClosableHttpServer } from "../src/shutdown.js";

/**
 * A fake httpServer whose `close()` only calls back once `resolveClose()` is
 * invoked (or never, simulating a connection that never drains), and whose
 * `closeAllConnections()` records that it was called - and, like the real
 * Node implementation, makes the pending `close()` callback fire.
 */
function fakeServer(): {
  server: ClosableHttpServer;
  forced: () => boolean;
  resolveClose: () => void;
} {
  let pendingCallback: ((err?: Error) => void) | undefined;
  let forced = false;
  const server: ClosableHttpServer = {
    close(callback) {
      pendingCallback = callback;
    },
    closeAllConnections() {
      forced = true;
      pendingCallback?.();
    },
  };
  return {
    server,
    forced: () => forced,
    resolveClose: () => pendingCallback?.(),
  };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("closeHttpServerGracefully", () => {
  it("resolves as soon as close() finishes, without forcing connections closed", async () => {
    const { server, resolveClose, forced } = fakeServer();
    const closed = closeHttpServerGracefully(server, 10000);

    resolveClose();
    await closed;

    expect(forced()).toBe(false);
  });

  it("forces remaining connections closed after the timeout elapses", async () => {
    const { server, forced } = fakeServer();
    const closed = closeHttpServerGracefully(server, 10000);

    // close() never completes on its own (a connection never drains).
    await vi.advanceTimersByTimeAsync(9999);
    expect(forced()).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    expect(forced()).toBe(true);

    // closeAllConnections() makes close()'s callback fire in the real
    // implementation; the fake models that, so the promise now resolves.
    await closed;
  });

  it("does not force connections closed once close() has already finished", async () => {
    const { server, resolveClose, forced } = fakeServer();
    const closed = closeHttpServerGracefully(server, 10000);

    resolveClose();
    await closed;

    await vi.advanceTimersByTimeAsync(10000);
    expect(forced()).toBe(false);
  });
});
