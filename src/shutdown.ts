/**
 * Close an HTTP server during graceful shutdown, with a forced-close
 * timeout (Task 9 / carried from the Task 5 review). `httpServer.close()`
 * waits for in-flight connections to finish and never completes while a
 * client keeps a connection open; `closeAllConnections()` forces those
 * sockets shut so shutdown cannot hang indefinitely (e.g. docker stop's
 * default grace period, or an orchestrator's termination deadline).
 */
export interface ClosableHttpServer {
  close(callback: (err?: Error) => void): void;
  closeAllConnections(): void;
}

export function closeHttpServerGracefully(
  httpServer: ClosableHttpServer,
  timeoutMs = 10000,
): Promise<void> {
  return new Promise<void>((resolve) => {
    let closed = false;
    const timer = setTimeout(() => {
      if (!closed) {
        httpServer.closeAllConnections();
      }
    }, timeoutMs);
    // Node's net.Server#close types its callback as `(err?: Error) => void`;
    // any error (e.g. "server is not running") is not actionable during
    // shutdown, so it is intentionally ignored here.
    httpServer.close(() => {
      closed = true;
      clearTimeout(timer);
      resolve();
    });
  });
}

export interface ShutdownDeps {
  httpServer?: ClosableHttpServer;
  auth?: { dispose(): void };
  db?: { close(): Promise<void> };
}

/**
 * The graceful shutdown sequence, returning the process exit code. Auth's
 * background work (the degraded-start discovery retry) is disposed first,
 * then HTTP stops accepting requests, then the database pool closes. A
 * failing step never stops the later ones, but any failure (a throwing
 * `dispose()` or a failed `db.close()`) makes the exit code 1.
 */
export async function gracefulShutdown(deps: ShutdownDeps): Promise<number> {
  let code = 0;
  try {
    deps.auth?.dispose();
  } catch {
    code = 1;
  }
  if (deps.httpServer) {
    await closeHttpServerGracefully(deps.httpServer);
  }
  if (deps.db) {
    try {
      await deps.db.close();
    } catch {
      code = 1;
    }
  }
  return code;
}

/** The slice of `process` that `setupShutdownHandlers` uses (a test seam). */
export interface SignalTarget {
  on(event: "SIGTERM" | "SIGINT", listener: () => void): unknown;
  exit(code: number): void;
}

/**
 * Run `gracefulShutdown` on SIGTERM and SIGINT, then exit with its code.
 * No logging: during shutdown it may interfere with the MCP protocol.
 */
export function setupShutdownHandlers(
  db: ShutdownDeps["db"],
  httpServer?: ClosableHttpServer,
  auth?: ShutdownDeps["auth"],
  proc: SignalTarget = process,
): void {
  const shutdown = async () => {
    proc.exit(await gracefulShutdown({ httpServer, auth, db }));
  };
  proc.on("SIGTERM", shutdown);
  proc.on("SIGINT", shutdown);
}
