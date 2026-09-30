import pg from 'pg';
import { config } from './config.js';

export type Db = pg.PoolClient;

/** Runtime role: row-level security is enforced on every query made through this pool. */
export const appPool = new pg.Pool({ connectionString: config.DATABASE_URL, max: 10 });
/** BYPASSRLS role: reserved for cross-tenant flows (auth, invitations, Stripe webhooks). */
export const systemPool = new pg.Pool({ connectionString: config.SYSTEM_DATABASE_URL, max: 5 });

interface RequestContext {
  userId?: string | null;
  ip?: string | null;
}

async function run<T>(pool: pg.Pool, settings: Record<string, string>, fn: (db: Db) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // is_local = true: the setting dies with the transaction, so it can never leak to the next
    // request that borrows this pooled connection.
    for (const [key, value] of Object.entries(settings)) {
      await client.query('SELECT set_config($1, $2, true)', [key, value]);
    }
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

/** Run `fn` in a transaction where Postgres RLS restricts every query to `tenantId`. */
export function withTenant<T>(ctx: RequestContext & { tenantId: string }, fn: (db: Db) => Promise<T>): Promise<T> {
  return run(appPool, {
    'app.tenant_id': ctx.tenantId,
    'app.user_id': ctx.userId ?? '',
    'app.ip': ctx.ip ?? '',
  }, fn);
}

/** Cross-tenant transaction. Use sparingly and only from auth/webhook code. */
export function withSystem<T>(fn: (db: Db) => Promise<T>, ctx: RequestContext = {}): Promise<T> {
  return run(systemPool, { 'app.user_id': ctx.userId ?? '', 'app.ip': ctx.ip ?? '' }, fn);
}

export async function closePools() {
  await Promise.all([appPool.end(), systemPool.end()]);
}
