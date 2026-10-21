import { describe } from "vitest";

/**
 * Returns the connection string for the local test Postgres database, or
 * `undefined` when none is configured. Tests that need a real database use
 * `describeDb` (below) so they are skipped automatically when this is unset.
 */
export function testDbUrl(): string | undefined {
  return process.env.TEST_DATABASE_URL || undefined;
}

/**
 * `describe` alias that skips the whole suite when `TEST_DATABASE_URL` is not
 * set, so DB-dependent tests don't fail in environments without a database.
 */
export const describeDb = describe.skipIf(!testDbUrl());
