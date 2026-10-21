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
 * then HTTP stops accepting requests, then the database pool closes. Only a
 * failed `db.close()` gives exit code 1; a throwing `dispose()` is ignored
 * so the rest of the sequence still runs.
 */
export async function gracefulShutdown(deps: ShutdownDeps): Promise<number> {
  try {
    deps.auth?.dispose();
  } catch {
    // Not actionable during shutdown.
  }
  if (deps.httpServer) {
    await closeHttpServerGracefully(deps.httpServer);
  }
  if (deps.db) {
    try {
      await deps.db.close();
    } catch {
      return 1;
    }
  }
  return 0;
}
