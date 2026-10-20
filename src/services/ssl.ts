/**
 * The TLS behaviour node-postgres should apply for a given connection URL, in
 * the same shape `pg.Pool`/`pg.Client` accept as their `ssl` option:
 *  - `false` disables TLS entirely. Only `sslmode=disable` produces this -
 *    it is the explicit opt-out.
 *  - `{ rejectUnauthorized }` enables TLS, optionally skipping certificate
 *    verification.
 *  - `undefined` is part of the type for forward compatibility, but is never
 *    returned today. `sslmode=prefer`/`allow` resolve exactly like no
 *    `sslmode` at all (the same host-based default below) rather than being
 *    left to the driver: `buildPoolConfig` always strips `sslmode` from the
 *    connection string it passes to `pg.Pool`, so leaving these as "no ssl
 *    option" would silently resolve to plaintext for a remote host. TLS is
 *    on by default; nothing but `sslmode=disable` may resolve to plaintext.
 */
export type SslConfig = false | undefined | { rejectUnauthorized: boolean };

// 127.0.0.0/8 per RFC 5735; `::1` is the IPv6 loopback address. The WHATWG
// URL parser returns IPv6 hosts bracketed (e.g. "[::1]"), so strip brackets
// before comparing.
const OCTET = "(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)";
const LOOPBACK_V4 = new RegExp(`^127\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);

export function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host === "::1") {
    return true;
  }
  return LOOPBACK_V4.test(host);
}

/**
 * Resolve the `ssl` option for a Postgres connection URL.
 *
 * Loopback targets (localhost, 127.0.0.0/8, ::1) default to TLS with
 * certificate verification skipped, since a local Steampipe/Postgres
 * typically runs with a self-signed cert or no TLS at all. Every other host
 * defaults to full certificate verification unless `sslmode` says otherwise.
 * An explicit `sslmode` always wins, loopback or not - except `prefer`/
 * `allow`, which fall through to the same host-based default as no
 * `sslmode`, rather than being left unresolved. Only `sslmode=disable` opts
 * out of TLS.
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
    case null:
      break;
    default:
      // Unknown sslmode value: fall through to host-based defaults rather
      // than silently disabling verification.
      break;
  }

  return isLoopback(url.hostname) ? { rejectUnauthorized: false } : { rejectUnauthorized: true };
}
