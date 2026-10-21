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
