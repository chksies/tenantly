import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { appPool, withSystem, withTenant } from '../src/db.js';
import { bearer, makeApp, register, shutdown, sql, type Session } from './helpers.js';

let app: FastifyInstance;
let a: Session;
let b: Session;
let projectA: string;
let projectB: string;

beforeAll(async () => {
  app = await makeApp();
  a = await register(app, 'Tenant A');
  b = await register(app, 'Tenant B');
  const create = async (s: Session, name: string) =>
    (await app.inject({ method: 'POST', url: '/projects', headers: bearer(s), payload: { name } })).json().id as string;
  projectA = await create(a, 'A secret');
  projectB = await create(b, 'B secret');
});
afterAll(() => shutdown(app));

describe('PostgreSQL row-level security (queried directly, bypassing the API)', () => {
  it("tenant A's context sees only tenant A's rows", async () => {
    const rows = await withTenant({ tenantId: a.tenantId }, async (db) => (await db.query('SELECT id, tenant_id FROM projects')).rows);
    expect(rows.map((r) => r.id)).toEqual([projectA]);
    expect(rows.every((r) => r.tenant_id === a.tenantId)).toBe(true);
  });

  it('a WHERE clause naming another tenant still returns nothing', async () => {
    const rows = await withTenant({ tenantId: a.tenantId }, async (db) =>
      (await db.query('SELECT id FROM projects WHERE tenant_id = $1 OR id = $2', [b.tenantId, projectB])).rows);
    expect(rows).toEqual([]);
  });

  it('fails closed: with no tenant context set, no rows are visible', async () => {
    const { rows } = await sql.app('SELECT count(*)::int AS n FROM projects');
    expect(rows[0].n).toBe(0);
  });

  it('context does not leak across pooled connections after a transaction ends', async () => {
    await withTenant({ tenantId: a.tenantId }, async (db) => db.query('SELECT 1'));
    const { rows } = await sql.app('SELECT count(*)::int AS n FROM projects');
    expect(rows[0].n).toBe(0);
    const setting = await sql.app(`SELECT current_setting('app.tenant_id', true) AS t`);
    expect(setting.rows[0].t ?? '').toBe('');
  });

  it("cannot INSERT a row into another tenant (WITH CHECK)", async () => {
    await expect(withTenant({ tenantId: a.tenantId }, (db) =>
      db.query('INSERT INTO projects (tenant_id, name) VALUES ($1, $2)', [b.tenantId, 'planted']),
    )).rejects.toThrow(/row-level security/);
  });

  it("cannot UPDATE or DELETE another tenant's rows (0 rows affected)", async () => {
    const res = await withTenant({ tenantId: a.tenantId }, async (db) => {
      const u = await db.query(`UPDATE projects SET name = 'pwned' WHERE id = $1`, [projectB]);
      const d = await db.query('DELETE FROM projects WHERE id = $1', [projectB]);
      return [u.rowCount, d.rowCount];
    });
    expect(res).toEqual([0, 0]);
    const { rows } = await sql.system('SELECT name FROM projects WHERE id = $1', [projectB]);
    expect(rows[0].name).toBe('B secret');
  });

  it("cannot move a row to another tenant via UPDATE tenant_id", async () => {
    await expect(withTenant({ tenantId: a.tenantId }, (db) =>
      db.query('UPDATE projects SET tenant_id = $1 WHERE id = $2', [b.tenantId, projectA]),
    )).rejects.toThrow(/permission denied|row-level security/);
  });

  it("tenants, memberships and audit logs are isolated too", async () => {
    await withTenant({ tenantId: a.tenantId }, async (db) => {
      expect((await db.query('SELECT id FROM tenants')).rows.map((r) => r.id)).toEqual([a.tenantId]);
      expect((await db.query('SELECT DISTINCT tenant_id FROM memberships')).rows.map((r) => r.tenant_id)).toEqual([a.tenantId]);
      expect((await db.query('SELECT DISTINCT tenant_id FROM audit_logs')).rows.map((r) => r.tenant_id)).toEqual([a.tenantId]);
    });
  });

  it("users of other tenants are invisible", async () => {
    const rows = await withTenant({ tenantId: a.tenantId }, async (db) =>
      (await db.query('SELECT id FROM users WHERE id = $1', [b.userId])).rows);
    expect(rows).toEqual([]);
    const own = await withTenant({ tenantId: a.tenantId }, async (db) =>
      (await db.query('SELECT id FROM users WHERE id = $1', [a.userId])).rows);
    expect(own).toHaveLength(1);
  });
});

describe('least-privilege grants for the runtime role', () => {
  it('cannot read password hashes', async () => {
    await expect(withTenant({ tenantId: a.tenantId }, (db) => db.query('SELECT password_hash FROM users')))
      .rejects.toThrow(/permission denied/);
    await expect(withTenant({ tenantId: a.tenantId }, (db) => db.query('SELECT * FROM users')))
      .rejects.toThrow(/permission denied/);
  });

  it.each(['refresh_tokens', 'oauth_identities', 'oauth_states', 'stripe_events'])('has no access to %s', async (table) => {
    await expect(appPool.query(`SELECT 1 FROM ${table}`)).rejects.toThrow(/permission denied/);
  });

  it('cannot change its own plan or write subscriptions', async () => {
    await expect(withTenant({ tenantId: a.tenantId }, (db) => db.query(`UPDATE tenants SET plan = 'pro'`)))
      .rejects.toThrow(/permission denied/);
    await expect(withTenant({ tenantId: a.tenantId }, (db) =>
      db.query(`INSERT INTO subscriptions (tenant_id, stripe_subscription_id, status, plan, last_event_at) VALUES ($1, 'x', 'active', 'pro', now())`, [a.tenantId]),
    )).rejects.toThrow(/permission denied/);
  });
});

describe('audit log integrity', () => {
  it('is append-only for every role, including the system role', async () => {
    await expect(withTenant({ tenantId: a.tenantId }, (db) => db.query(`UPDATE audit_logs SET action = 'x'`))).rejects.toThrow(/permission denied/);
    await expect(withTenant({ tenantId: a.tenantId }, (db) => db.query('DELETE FROM audit_logs'))).rejects.toThrow(/permission denied/);
    await expect(withSystem((db) => db.query(`UPDATE audit_logs SET action = 'x'`))).rejects.toThrow(/permission denied/);
  });

  it('the trigger blocks tampering even by the table owner / superuser', async () => {
    const pg = await import('pg');
    const { adminUrl } = await import('./env.js');
    const admin = new pg.default.Client({ connectionString: adminUrl });
    await admin.connect();
    try {
      await expect(admin.query(`UPDATE audit_logs SET action = 'x'`)).rejects.toThrow(/append-only/);
      await expect(admin.query('DELETE FROM audit_logs')).rejects.toThrow(/append-only/);
    } finally {
      await admin.end();
    }
  });

  it('DB triggers record row changes with actor and before/after state', async () => {
    const created = (await app.inject({
      method: 'POST', url: '/projects', headers: bearer(a), payload: { name: 'Audited' },
    })).json();
    await app.inject({ method: 'PATCH', url: `/projects/${created.id}`, headers: bearer(a), payload: { name: 'Audited v2' } });
    await app.inject({ method: 'DELETE', url: `/projects/${created.id}`, headers: bearer(a) });

    const { rows } = await sql.system(
      `SELECT action, actor_id, metadata FROM audit_logs WHERE entity_type = 'projects' AND entity_id = $1 ORDER BY id`, [created.id]);
    expect(rows.map((r) => r.action)).toEqual(['projects.insert', 'projects.update', 'projects.delete']);
    expect(rows.every((r) => r.actor_id === a.userId)).toBe(true);
    expect(rows[1].metadata.before.name).toBe('Audited');
    expect(rows[1].metadata.after.name).toBe('Audited v2');
  });
});
