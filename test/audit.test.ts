import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { addMember, bearer, makeApp, register, shutdown, type Session } from './helpers.js';

let app: FastifyInstance;
let a: Session, b: Session;
beforeAll(async () => { app = await makeApp(); a = await register(app, 'Audit A'); b = await register(app, 'Audit B'); });
afterAll(() => shutdown(app));

const logs = async (s: Session, qs = '') =>
  (await app.inject({ method: 'GET', url: `/audit-logs${qs}`, headers: bearer(s) })).json();

describe('audit log API', () => {
  it('captures the activity trail for the workspace, newest first', async () => {
    const m = await addMember(app, a, 'member');
    const p = (await app.inject({ method: 'POST', url: '/projects', headers: bearer(m), payload: { name: 'Traced' } })).json();
    await app.inject({ method: 'PATCH', url: '/tenants/current', headers: bearer(a), payload: { name: 'Audit A Renamed' } });

    const { items } = await logs(a);
    const actions = items.map((i: { action: string }) => i.action);
    expect(actions).toEqual(expect.arrayContaining(['tenant.created', 'invitation.created', 'invitation.accepted', 'memberships.insert', 'projects.insert', 'tenant.updated']));
    const created = items.find((i: { action: string; entity_id: string }) => i.action === 'projects.insert' && i.entity_id === p.id);
    expect(created.actor_id).toBe(m.userId);
    const ids = items.map((i: { id: string }) => BigInt(i.id));
    expect([...ids].sort((x, y) => (x < y ? 1 : -1))).toEqual(ids);
  });

  it("never leaks another workspace's events", async () => {
    await app.inject({ method: 'POST', url: '/projects', headers: bearer(b), payload: { name: 'B only' } });
    const { items } = await logs(a);
    expect(JSON.stringify(items)).not.toContain('B only');
  });

  it('filters by action prefix and paginates with a cursor', async () => {
    const t = await register(app, 'Pagination');
    for (let i = 0; i < 3; i++) await app.inject({ method: 'POST', url: '/projects', headers: bearer(t), payload: { name: `p${i}` } });
    const page1 = await logs(t, '?action=projects.&limit=2');
    expect(page1.items).toHaveLength(2);
    expect(page1.nextCursor).toBeTruthy();
    const page2 = await logs(t, `?action=projects.&limit=2&before=${page1.nextCursor}`);
    expect(page2.items).toHaveLength(1);
    expect(page2.nextCursor).toBeNull();
    expect(page1.items.every((i: { action: string }) => i.action.startsWith('projects.'))).toBe(true);
  });

  it('cannot be written through the API (no mutating routes)', async () => {
    for (const method of ['POST', 'PATCH', 'PUT', 'DELETE'] as const) {
      const res = await app.inject({ method, url: '/audit-logs', headers: bearer(a), payload: {} });
      expect(res.statusCode).toBe(404);
    }
  });
});

describe('platform basics', () => {
  it('health check works and unknown routes return JSON 404', async () => {
    expect((await app.inject({ method: 'GET', url: '/healthz' })).json()).toEqual({ status: 'ok' });
    const nf = await app.inject({ method: 'GET', url: '/nope' });
    expect(nf.statusCode).toBe(404);
    expect(nf.json().error.code).toBe('not_found');
  });

  it('sets security headers', async () => {
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['strict-transport-security']).toBeTruthy();
  });
});
