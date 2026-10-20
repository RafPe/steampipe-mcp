/**
 * The TLS behaviour node-postgres should apply for a given connection URL, in
 * the same shape `pg.Pool`/`pg.Client` accept as their `ssl` option:
 *  - `false` disables TLS entirely.
 *  - `{ rejectUnauthorized }` enables TLS, optionally skipping certificate
 *    verification.
 *  - `undefined` leaves TLS negotiation to node-postgres/libpq defaults
 *    (used for `sslmode=prefer`/`allow`, where the driver decides).
 */
export type SslConfig = false | undefined | { rejectUnauthorized: boolean };

// 127.0.0.0/8 per RFC 5735; `::1` is the IPv6 loopback address. The WHATWG
// URL parser returns IPv6 hosts bracketed (e.g. "[::1]"), so strip brackets
// before comparing.
function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host === "::1") {
    return true;
  }
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Resolve the `ssl` option for a Postgres connection URL.
 *
 * Loopback targets (localhost, 127.0.0.0/8, ::1) default to TLS with
 * certificate verification skipped, since a local Steampipe/Postgres
 * typically runs with a self-signed cert or no TLS at all. Every other host
 * defaults to full certificate verification unless `sslmode` says otherwise.
 * An explicit `sslmode` always wins, loopback or not.
 */
export function resolveSsl(url: URL): SslConfig {
  const sslmode = url.searchParams.get("sslmode");
  switch (sslmode) {
    case "disable":
      return false;
    case "no-verify":
      return { rejectUnauthorized: false };
    case "require":
    case "verify-ca":
    case "verify-full":
      return { rejectUnauthorized: true };
    case "prefer":
    case "allow":
      return undefined;
    case null:
      break;
    default:
      // Unknown sslmode value: fall through to host-based defaults rather
      // than silently disabling verification.
      break;
  }

  return isLoopback(url.hostname) ? { rejectUnauthorized: false } : { rejectUnauthorized: true };
}
