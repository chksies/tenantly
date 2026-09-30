import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { ROLES, can, canManageRole, type Permission } from '../src/rbac.js';
import { addMember, bearer, makeApp, register, shutdown, sql, type Session } from './helpers.js';

let app: FastifyInstance;
let owner: Session, admin: Session, member: Session, viewer: Session;
let other: Session; // a completely separate tenant

beforeAll(async () => {
  app = await makeApp();
  owner = await register(app, 'RBAC Corp');
  admin = await addMember(app, owner, 'admin');
  member = await addMember(app, owner, 'member');
  viewer = await addMember(app, owner, 'viewer');
  other = await register(app, 'Other Corp');
});
afterAll(() => shutdown(app));

const call = (s: Session, method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, payload?: object) =>
  app.inject({ method, url, headers: bearer(s), payload });

describe('permission matrix (unit)', () => {
  const matrix: Record<Permission, Record<(typeof ROLES)[number], boolean>> = {
    'tenant:read': { owner: true, admin: true, member: true, viewer: true },
    'tenant:update': { owner: true, admin: true, member: false, viewer: false },
    'projects:read': { owner: true, admin: true, member: true, viewer: true },
    'projects:write': { owner: true, admin: true, member: true, viewer: false },
    'projects:delete': { owner: true, admin: true, member: false, viewer: false },
    'members:read': { owner: true, admin: true, member: true, viewer: true },
    'members:manage': { owner: true, admin: true, member: false, viewer: false },
    'billing:read': { owner: true, admin: true, member: false, viewer: false },
    'billing:manage': { owner: true, admin: false, member: false, viewer: false },
    'audit:read': { owner: true, admin: true, member: false, viewer: false },
  };
  it.each(Object.entries(matrix))('%s', (permission, expected) => {
    for (const role of ROLES) expect(can(role, permission as Permission), `${role} ${permission}`).toBe(expected[role]);
  });

  it('admins cannot manage owners or other admins', () => {
    expect(canManageRole('admin', 'owner')).toBe(false);
    expect(canManageRole('admin', 'admin')).toBe(false);
    expect(canManageRole('admin', 'member')).toBe(true);
    expect(canManageRole('member', 'viewer')).toBe(false);
  });
});

describe('enforcement over HTTP', () => {
  it('viewer can read but not write', async () => {
    expect((await call(viewer, 'GET', '/projects')).statusCode).toBe(200);
    expect((await call(viewer, 'POST', '/projects', { name: 'nope' })).statusCode).toBe(403);
  });

  it('member can create/edit but not delete; admin can delete', async () => {
    const created = await call(member, 'POST', '/projects', { name: 'Member project' });
    expect(created.statusCode).toBe(201);
    const id = created.json().id;
    expect((await call(member, 'PATCH', `/projects/${id}`, { name: 'Renamed' })).statusCode).toBe(200);
    expect((await call(member, 'DELETE', `/projects/${id}`)).statusCode).toBe(403);
    expect((await call(admin, 'DELETE', `/projects/${id}`)).statusCode).toBe(204);
  });

  it('audit log and billing are hidden from members and viewers', async () => {
    for (const s of [member, viewer]) {
      expect((await call(s, 'GET', '/audit-logs')).statusCode).toBe(403);
      expect((await call(s, 'GET', '/billing')).statusCode).toBe(403);
    }
    expect((await call(admin, 'GET', '/audit-logs')).statusCode).toBe(200);
    expect((await call(admin, 'GET', '/billing')).statusCode).toBe(200);
  });

  it('only owners can start checkout / open the billing portal', async () => {
    expect((await call(admin, 'POST', '/billing/checkout')).statusCode).toBe(403);
    expect((await call(admin, 'POST', '/billing/portal')).statusCode).toBe(403);
  });
});

describe('privilege escalation guards', () => {
  it('admin cannot promote anyone to owner or admin, nor touch the owner', async () => {
    expect((await call(admin, 'PATCH', `/tenants/current/members/${member.userId}`, { role: 'owner' })).statusCode).toBe(403);
    expect((await call(admin, 'PATCH', `/tenants/current/members/${member.userId}`, { role: 'admin' })).statusCode).toBe(403);
    expect((await call(admin, 'PATCH', `/tenants/current/members/${owner.userId}`, { role: 'viewer' })).statusCode).toBe(403);
    expect((await call(admin, 'DELETE', `/tenants/current/members/${owner.userId}`)).statusCode).toBe(403);
  });

  it('admin cannot invite an admin, but can invite a member', async () => {
    expect((await call(admin, 'POST', '/tenants/current/invitations', { email: 'a@example.com', role: 'admin' })).statusCode).toBe(403);
    expect((await call(admin, 'POST', '/tenants/current/invitations', { email: 'b@example.com', role: 'member' })).statusCode).toBe(201);
  });

  it('nobody can change their own role, and owner is not an invitable role', async () => {
    expect((await call(owner, 'PATCH', `/tenants/current/members/${owner.userId}`, { role: 'viewer' })).statusCode).toBe(400);
    expect((await call(owner, 'POST', '/tenants/current/invitations', { email: 'c@example.com', role: 'owner' })).statusCode).toBe(400);
  });

  it('the last owner cannot leave or be removed', async () => {
    const res = await call(owner, 'DELETE', `/tenants/current/members/${owner.userId}`);
    expect(res.statusCode).toBe(409);
    expect(res.json().error.code).toBe('last_owner');
  });

  it('owner can promote/demote, and role changes take effect immediately (JWT role is not trusted)', async () => {
    const m = await addMember(app, owner, 'member');
    expect((await call(m, 'POST', '/projects', { name: 'as member' })).statusCode).toBe(201);
    expect((await call(owner, 'PATCH', `/tenants/current/members/${m.userId}`, { role: 'viewer' })).statusCode).toBe(200);
    // Same access token (still says "member"), but the DB now says viewer.
    expect((await call(m, 'POST', '/projects', { name: 'as demoted' })).statusCode).toBe(403);
  });

  it('a removed member loses access instantly, even with an unexpired token, and cannot refresh', async () => {
    const m = await addMember(app, owner, 'member');
    expect((await call(m, 'GET', '/projects')).statusCode).toBe(200);
    expect((await call(owner, 'DELETE', `/tenants/current/members/${m.userId}`)).statusCode).toBe(204);
    expect((await call(m, 'GET', '/projects')).statusCode).toBe(401);
    expect((await app.inject({ method: 'POST', url: '/auth/refresh', payload: { refreshToken: m.refreshToken } })).statusCode).toBe(401);
  });
});

describe('cross-tenant access over HTTP', () => {
  it("a valid user cannot read, edit or delete another tenant's project by id (404, not 403)", async () => {
    const theirs = (await call(other, 'POST', '/projects', { name: 'Confidential' })).json();
    expect((await call(owner, 'GET', `/projects/${theirs.id}`)).statusCode).toBe(404);
    expect((await call(owner, 'PATCH', `/projects/${theirs.id}`, { name: 'hax' })).statusCode).toBe(404);
    expect((await call(owner, 'DELETE', `/projects/${theirs.id}`)).statusCode).toBe(404);
    const list = (await call(owner, 'GET', '/projects')).json().projects;
    expect(list.find((p: { id: string }) => p.id === theirs.id)).toBeUndefined();
    const { rows } = await sql.system('SELECT name FROM projects WHERE id = $1', [theirs.id]);
    expect(rows[0].name).toBe('Confidential');
  });

  it("member lists never include other tenants' users", async () => {
    const members = (await call(owner, 'GET', '/tenants/current/members')).json().members;
    const ids = members.map((m: { id: string }) => m.id);
    expect(ids).toEqual(expect.arrayContaining([owner.userId, admin.userId, member.userId, viewer.userId]));
    expect(ids).not.toContain(other.userId);
  });

  it("cannot forge a token for another tenant without the signing key, and role-in-token can't elevate", async () => {
    const { SignJWT } = await import('jose');
    const forged = await new SignJWT({ tid: other.tenantId, role: 'owner' }).setProtectedHeader({ alg: 'HS256' })
      .setSubject(viewer.userId).setIssuer('tenantly').setAudience('tenantly-api').setIssuedAt().setExpirationTime('5m')
      // correct secret (test-only) but the user is NOT a member of `other`
      .sign(new TextEncoder().encode('test-secret-test-secret-test-secret-1234'));
    const res = await app.inject({ method: 'GET', url: '/projects', headers: { authorization: `Bearer ${forged}` } });
    expect(res.statusCode).toBe(401); // membership is re-verified in the database
  });
});

describe('invitations', () => {
  it('are single-use, expire, are tied to the invited email, and can be revoked', async () => {
    const email = `inv-${Date.now()}@example.com`;
    const inv = (await call(owner, 'POST', '/tenants/current/invitations', { email, role: 'member' })).json();
    const ok = await app.inject({ method: 'POST', url: '/invitations/accept', payload: { token: inv.token, name: 'New', password: 'a-long-enough-password' } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().role).toBe('member');
    const reuse = await app.inject({ method: 'POST', url: '/invitations/accept', payload: { token: inv.token, name: 'New2', password: 'a-long-enough-password' } });
    expect(reuse.statusCode).toBe(400);

    const expired = (await call(owner, 'POST', '/tenants/current/invitations', { email: `exp-${Date.now()}@example.com`, role: 'viewer' })).json();
    await sql.system(`UPDATE invitations SET expires_at = now() - interval '1 minute' WHERE id = $1`, [expired.id]);
    expect((await app.inject({ method: 'POST', url: '/invitations/accept', payload: { token: expired.token, name: 'E', password: 'a-long-enough-password' } })).statusCode).toBe(400);

    const revoked = (await call(owner, 'POST', '/tenants/current/invitations', { email: `rev-${Date.now()}@example.com`, role: 'viewer' })).json();
    expect((await call(owner, 'DELETE', `/tenants/current/invitations/${revoked.id}`)).statusCode).toBe(204);
    expect((await app.inject({ method: 'POST', url: '/invitations/accept', payload: { token: revoked.token, name: 'R', password: 'a-long-enough-password' } })).statusCode).toBe(400);

    // Someone else's authenticated account can't redeem an invite addressed to a different email.
    const target = (await call(owner, 'POST', '/tenants/current/invitations', { email: `target-${Date.now()}@example.com`, role: 'member' })).json();
    const thief = await app.inject({ method: 'POST', url: '/invitations/accept', headers: bearer(other), payload: { token: target.token } });
    expect(thief.statusCode).toBe(403);
  });

  it('are invisible to other tenants', async () => {
    const list = (await call(other, 'GET', '/tenants/current/invitations')).json().invitations;
    expect(list).toEqual([]);
  });
});
