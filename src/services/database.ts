import { boundForLog } from "./logbound.js";
import { logger } from "./logger.js";
import { resolveSsl } from "./ssl.js";
import { readFileSync } from 'fs';
import pkg from 'pg';
const { Pool } = pkg;
import type { Pool as PoolType, PoolClient, PoolConfig } from 'pg';
import Cursor from 'pg-cursor';

export interface DatabaseOptions {
  connectionString: string;
  // Maximum rows returned by executeUserQuery. 0 means unlimited.
  maxRows: number;
  statementTimeoutMs: number;
  poolMax: number;
  // Include the (password-masked) connection string in error messages.
  exposeConnectionDetails: boolean;
}

/**
 * Build the `pg.Pool` config for a given set of database options.
 *
 * TLS is resolved separately (see `resolveSsl`), and every query parameter
 * node-postgres itself inspects to affect TLS or the connection target is
 * either stripped from the connection string or rejected outright, so that
 * `resolveSsl`'s decision is the only thing that can apply:
 *  - `sslmode` and `ssl` are stripped: a URL `sslmode`/`ssl` would otherwise
 *    override the `ssl` object below.
 *  - `host`/`hostaddr` are rejected (not stripped): node-postgres lets
 *    either one silently redirect the actual TCP connection away from the
 *    URL's authority host, while `resolveSsl`'s loopback check only looks at
 *    that authority host - so a string like
 *    `postgresql://u@localhost/d?host=remote.example.com` would be judged
 *    loopback (TLS verification skipped) while actually connecting,
 *    unverified, to a remote host.
 *  - `sslrootcert`/`sslcert`/`sslkey` are stripped and, when TLS is enabled,
 *    read from disk here and merged into the `ssl` object as `ca`/`cert`/
 *    `key` - otherwise node-postgres would read them itself and could
 *    override the resolved ssl object's shape.
 */
export function buildPoolConfig(opts: DatabaseOptions): PoolConfig {
  const url = new URL(opts.connectionString);

  if (url.searchParams.has('host') || url.searchParams.has('hostaddr')) {
    throw new Error('connection string must not override the host via query parameters; put the host in the URL authority');
  }

  const ssl = resolveSsl(url);
  const sslRootCertPath = url.searchParams.get('sslrootcert');
  const sslCertPath = url.searchParams.get('sslcert');
  const sslKeyPath = url.searchParams.get('sslkey');

  for (const param of ['sslmode', 'ssl', 'sslrootcert', 'sslcert', 'sslkey']) {
    url.searchParams.delete(param);
  }

  const poolConfig: PoolConfig = {
    connectionString: url.toString(),
    max: opts.poolMax,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    maxLifetimeSeconds: 300,  // 5 minutes
    // Sent as startup parameters, so they apply to every pooled connection
    // and are restored by DISCARD ALL
    statement_timeout: opts.statementTimeoutMs,
    idle_in_transaction_session_timeout: opts.statementTimeoutMs,
    application_name: 'steampipe-mcp',
  };

  if (ssl === false) {
    // TLS is off: the cert/key files (if any) are irrelevant.
    poolConfig.ssl = false;
  } else {
    poolConfig.ssl = {
      ...ssl,
      ...(sslRootCertPath ? { ca: readFileSync(sslRootCertPath, 'utf8') } : {}),
      ...(sslCertPath ? { cert: readFileSync(sslCertPath, 'utf8') } : {}),
      ...(sslKeyPath ? { key: readFileSync(sslKeyPath, 'utf8') } : {}),
    };
  }

  return poolConfig;
}

export interface UserQueryResult {
  rows: any[];
  truncated: boolean;
}

// Rows fetched per cursor read when reading without a row cap
const CURSOR_BATCH_SIZE = 1000;

/** Driver error text can echo server- or query-supplied strings, so bound it before logging. */
function errorText(error: unknown): string {
  return boundForLog(error instanceof Error ? error.message : error);
}

export class DatabaseService {
  private pool: PoolType | null = null;
  private _isConnected = false;
  private readonly opts: DatabaseOptions;

  constructor(opts: DatabaseOptions) {
    this.opts = opts;
  }

  /**
   * Sanitize a connection string by removing sensitive information
   */
  private sanitizeConnectionString(connectionString: string): string {
    try {
      // Create URL object to parse connection string
      const url = new URL(connectionString);
      // Remove password if present
      url.password = url.password ? '****' : '';
      return url.toString();
    } catch (e) {
      // If URL parsing fails, do basic sanitization
      return connectionString.replace(/:[^:@]+@/, ':****@');
    }
  }

  get isConnected(): boolean {
    return this._isConnected;
  }

  get safeConnectionString(): string {
    return this.sanitizeConnectionString(this.opts.connectionString);
  }

  get exposeConnectionDetails(): boolean {
    return this.opts.exposeConnectionDetails;
  }

  /**
   * How the database is referred to in error messages
   */
  private get target(): string {
    return this.opts.exposeConnectionDetails ? this.safeConnectionString : 'the configured Steampipe database';
  }

  /**
   * Get the connection pool, creating it on first use
   */
  private getPool(): PoolType {
    if (this.pool) {
      return this.pool;
    }

    logger.debug('Creating database pool for:', this.target);

    this.pool = new Pool(buildPoolConfig(this.opts));

    // Errors on idle clients (e.g. backend terminated because Steampipe
    // restarted) are emitted here. The pool drops the broken client itself and
    // opens a fresh one on the next connect, so only record the state.
    this.pool.on('error', (err) => {
      logger.error('Unexpected pool error:', errorText(err));
      this._isConnected = false;
    });

    return this.pool;
  }

  /**
   * Translate a connection failure into a user-facing error
   */
  private connectionError(error: unknown): Error {
    // Log the raw error for debugging
    logger.debug('Database connection error:', errorText(error));

    const target = this.target;
    // Raw driver messages can name the host (e.g. "getaddrinfo ENOTFOUND
    // db.internal"), so only include them when connection details are exposed
    const detail = (raw: string) => this.opts.exposeConnectionDetails ? `: ${raw}` : '';
    if (!(error instanceof Error)) {
      return new Error(`Database connection failed for ${target}${detail(String(error))}`);
    }

    const msg = error.message.toLowerCase();
    const code = (error as any).code;

    // Handle termination errors
    if (code === '57P01' || msg.includes('terminating connection due to administrator command')) {
      return new Error(`Database connection terminated - Steampipe service may have been stopped. Please ensure Steampipe is running at ${target}`);
    }

    // Handle common postgres error codes
    if (code === 'ECONNREFUSED') {
      return new Error(`Cannot connect to Steampipe database at ${target}. Please ensure Steampipe is running (e.g. 'steampipe service start').`);
    }
    if (code === '28P01') {
      return new Error(`Database authentication failed for ${target}. Please check your credentials.`);
    }
    if (code === '3D000') {
      return new Error(`Database does not exist at ${target}. Please check your connection string.`);
    }
    if (code === '28000') {
      return new Error(`Database user/role does not exist for ${target}. Please check your credentials.`);
    }
    if (code === '57P03') {
      return new Error(`Database connection timed out for ${target}. The server might be overloaded or unreachable.`);
    }

    // Handle common error message patterns
    if (msg.includes('econnrefused') || msg.includes('connect refused')) {
      return new Error(`Cannot connect to Steampipe database at ${target}. Please ensure Steampipe is running (e.g. 'steampipe service start').`);
    }
    if (msg.includes('password authentication failed')) {
      return new Error(`Database authentication failed for ${target}. Please check your credentials.`);
    }
    if (msg.includes('database') && msg.includes('does not exist')) {
      return new Error(`Database does not exist at ${target}. Please check your connection string.`);
    }
    if (msg.includes('role') && msg.includes('does not exist')) {
      return new Error(`Database user/role does not exist for ${target}. Please check your credentials.`);
    }
    if (msg.includes('timeout')) {
      return new Error(`Database connection timed out for ${target}. The server might be overloaded or unreachable.`);
    }

    // For other errors, include the specific error message when allowed
    return new Error(`Database connection failed for ${target}${detail(error.message)}`);
  }

  /**
   * Run work inside a read-only transaction on a pooled client. The session is
   * reset with DISCARD ALL before the client goes back to the pool, so nothing
   * a query changes (search_path, timeouts, role, ...) leaks to the next one.
   */
  private async withReadOnlyTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.beginReadOnly();
    let releaseError: Error | undefined;
    try {
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      // Rollback on error
      await client.query('ROLLBACK').catch(rollbackError => {
        logger.error('Error rolling back transaction:', errorText(rollbackError));
      });
      throw error;
    } finally {
      try {
        await client.query('DISCARD ALL');
      } catch (discardError) {
        // Destroy the connection rather than return a dirty session to the pool
        logger.error('Error resetting session, discarding connection:', errorText(discardError));
        releaseError = discardError instanceof Error ? discardError : new Error(String(discardError));
      }
      client.release(releaseError);
    }
  }

  /**
   * Acquire a client and open a read-only transaction. A pooled client whose
   * backend has gone away (e.g. Steampipe restarted) fails on BEGIN before any
   * query has run, so it is destroyed and the acquire is retried once.
   */
  private async beginReadOnly(): Promise<PoolClient> {
    for (let attempt = 1; ; attempt++) {
      let client: PoolClient;
      try {
        client = await this.getPool().connect();
      } catch (error) {
        this._isConnected = false;
        throw this.connectionError(error);
      }

      try {
        await client.query('BEGIN TRANSACTION READ ONLY');
        this._isConnected = true;
        return client;
      } catch (error) {
        client.release(error instanceof Error ? error : new Error(String(error)));
        if (attempt >= 2) {
          this._isConnected = false;
          throw this.connectionError(error);
        }
        logger.debug('Stale database connection, retrying:', errorText(error));
      }
    }
  }

  /**
   * Enhance query error messages
   */
  private queryError(error: unknown): Error {
    if (error instanceof Error) {
      const msg = error.message.toLowerCase();
      if (msg.includes('syntax error')) {
        return new Error(`SQL syntax error: ${error.message}`);
      }
      if (msg.includes('permission denied')) {
        return new Error(`Permission denied: ${error.message}`);
      }
      if (msg.includes('relation') && msg.includes('does not exist')) {
        return new Error(`Table or view not found: ${error.message}`);
      }
      // Pass through the original error instead of masking it
      return error;
    }
    // If it's not an Error instance, convert to string but preserve the message
    return new Error(`Query execution failed: ${String(error)}`);
  }

  /**
   * Execute an internal, parameterised query in a read-only transaction.
   *
   * For internal static or parameterised SQL only - never pass user input.
   * With an empty `params` array pg uses the simple query protocol, which
   * accepts multiple semicolon-separated statements. User-supplied SQL must
   * go through executeUserQuery, which enforces a single statement.
   */
  async executeQuery(query: string, params: any[] = []): Promise<any[]> {
    try {
      return await this.withReadOnlyTransaction(async (client) => {
        const result = await client.query(query, params);
        return result.rows;
      });
    } catch (error) {
      throw this.queryError(error);
    }
  }

  /**
   * Execute user-supplied SQL. The query runs through a cursor (extended
   * protocol), so only a single statement is accepted, inside a read-only
   * transaction. At most maxRows rows are returned (0 means unlimited);
   * truncated is true when more rows were available.
   */
  async executeUserQuery(sql: string): Promise<UserQueryResult> {
    const maxRows = this.opts.maxRows;
    try {
      return await this.withReadOnlyTransaction(async (client) => {
        const cursor = client.query(new Cursor(sql));
        const rows: any[] = [];
        // Read one extra row when capped so truncation can be detected
        const limit = maxRows > 0 ? maxRows + 1 : Infinity;
        while (rows.length < limit) {
          const batch = await cursor.read(Math.min(CURSOR_BATCH_SIZE, limit - rows.length));
          if (batch.length === 0) {
            break;
          }
          rows.push(...batch);
        }
        await cursor.close();

        const truncated = maxRows > 0 && rows.length > maxRows;
        return { rows: truncated ? rows.slice(0, maxRows) : rows, truncated };
      });
    } catch (error) {
      throw this.queryError(error);
    }
  }

  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
    this._isConnected = false;
  }
}
