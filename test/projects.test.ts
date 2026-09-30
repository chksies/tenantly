import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { bearer, makeApp, register, shutdown, sql, type Session } from './helpers.js';

let app: FastifyInstance;
let s: Session;
beforeAll(async () => { app = await makeApp(); s = await register(app, 'Projects Inc'); });
afterAll(() => shutdown(app));

const create = (name: string, session = s) =>
  app.inject({ method: 'POST', url: '/projects', headers: bearer(session), payload: { name } });

describe('projects CRUD & validation', () => {
  it('supports create / read / update / delete', async () => {
    const p = (await create('First')).json();
    expect(p.name).toBe('First');
    expect((await app.inject({ method: 'GET', url: `/projects/${p.id}`, headers: bearer(s) })).json().id).toBe(p.id);
    const upd = await app.inject({ method: 'PATCH', url: `/projects/${p.id}`, headers: bearer(s), payload: { description: 'hello' } });
    expect(upd.json()).toMatchObject({ name: 'First', description: 'hello' });
    expect((await app.inject({ method: 'DELETE', url: `/projects/${p.id}`, headers: bearer(s) })).statusCode).toBe(204);
    expect((await app.inject({ method: 'GET', url: `/projects/${p.id}`, headers: bearer(s) })).statusCode).toBe(404);
  });

  it('validates input and ids', async () => {
    expect((await create('')).statusCode).toBe(400);
    expect((await app.inject({ method: 'GET', url: '/projects/not-a-uuid', headers: bearer(s) })).statusCode).toBe(400);
    expect((await app.inject({ method: 'PATCH', url: '/projects/00000000-0000-4000-8000-000000000000', headers: bearer(s), payload: {} })).statusCode).toBe(400);
    const bad = await app.inject({ method: 'POST', url: '/projects', headers: { ...bearer(s), 'content-type': 'application/json' }, payload: '{not json' });
    expect(bad.statusCode).toBe(400);
  });

  it('ignores a client-supplied tenant_id (tenant comes from the token, enforced by RLS)', async () => {
    const other = await register(app, 'Someone Else');
    const res = await app.inject({ method: 'POST', url: '/projects', headers: bearer(s), payload: { name: 'Sneaky', tenant_id: other.tenantId } });
    expect(res.statusCode).toBe(201);
    const { rows } = await sql.system('SELECT tenant_id FROM projects WHERE id = $1', [res.json().id]);
    expect(rows[0].tenant_id).toBe(s.tenantId);
  });

  it('paginates', async () => {
    const fresh = await register(app, 'Pager');
    await create('a', fresh); await create('b', fresh);
    const page = (await app.inject({ method: 'GET', url: '/projects?limit=1&offset=1', headers: bearer(fresh) })).json();
    expect(page.projects).toHaveLength(1);
  });
});

describe('plan limits', () => {
  it('free plan caps at 3 projects (402), even under concurrent creates', async () => {
    const t = await register(app, 'Limit Co');
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => create(`p${i}`, t)));
    const codes = results.map((r) => r.statusCode).sort();
    expect(codes.filter((c) => c === 201)).toHaveLength(3);
    expect(codes.filter((c) => c === 402)).toHaveLength(5);
    const { rows } = await sql.system('SELECT count(*)::int AS n FROM projects WHERE tenant_id = $1', [t.tenantId]);
    expect(rows[0].n).toBe(3);
  });

  it('pro plan lifts the cap', async () => {
    const t = await register(app, 'Pro Co');
    await sql.system(`UPDATE tenants SET plan = 'pro' WHERE id = $1`, [t.tenantId]);
    for (let i = 0; i < 5; i++) expect((await create(`p${i}`, t)).statusCode).toBe(201);
  });
});
