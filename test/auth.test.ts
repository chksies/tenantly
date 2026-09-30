import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { SignJWT } from 'jose';
import { PASSWORD, bearer, fakeProvider, makeApp, register, shutdown, sql, uniqueEmail } from './helpers.js';

let app: FastifyInstance;
beforeAll(async () => { app = await makeApp(); });
afterAll(() => shutdown(app));

const post = (url: string, payload: object, headers: Record<string, string> = {}) =>
  app.inject({ method: 'POST', url, payload, headers });

describe('registration & login', () => {
  it('registers a user, creates a workspace, and makes them owner', async () => {
    const s = await register(app, 'Globex');
    const me = await app.inject({ method: 'GET', url: '/me', headers: bearer(s) });
    expect(me.statusCode).toBe(200);
    expect(me.json().workspaces).toEqual([expect.objectContaining({ id: s.tenantId, name: 'Globex', role: 'owner', plan: 'free' })]);
  });

  it('never stores the password in plaintext and rejects weak passwords / duplicate emails', async () => {
    const email = uniqueEmail();
    expect((await post('/auth/register', { email, password: 'short', name: 'X' })).statusCode).toBe(400);
    expect((await post('/auth/register', { email, password: PASSWORD, name: 'X' })).statusCode).toBe(201);
    expect((await post('/auth/register', { email: email.toUpperCase(), password: PASSWORD, name: 'X' })).statusCode).toBe(409);
    const { rows } = await sql.system('SELECT password_hash FROM users WHERE email = $1', [email]);
    expect(rows[0].password_hash).toMatch(/^scrypt\$/);
    expect(rows[0].password_hash).not.toContain(PASSWORD);
  });

  it('logs in with correct credentials only, with a generic error for unknown email and wrong password', async () => {
    const s = await register(app);
    const ok = await post('/auth/login', { email: s.email, password: PASSWORD });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().accessToken).toBeTruthy();
    const wrong = await post('/auth/login', { email: s.email, password: 'wrong-password-123' });
    const unknown = await post('/auth/login', { email: uniqueEmail('nobody'), password: PASSWORD });
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(wrong.json()).toEqual(unknown.json());
  });
});

describe('JWT access tokens', () => {
  it('rejects missing, malformed, tampered, wrong-secret and expired tokens', async () => {
    const s = await register(app);
    const get = (authorization?: string) => app.inject({ method: 'GET', url: '/projects', headers: authorization ? { authorization } : {} });
    expect((await get()).statusCode).toBe(401);
    expect((await get('Bearer garbage')).statusCode).toBe(401);
    expect((await get(`Bearer ${s.accessToken.slice(0, -3)}abc`)).statusCode).toBe(401);

    const forge = (secret: string, exp: number) =>
      new SignJWT({ tid: s.tenantId, role: 'owner' }).setProtectedHeader({ alg: 'HS256' }).setSubject(s.userId)
        .setIssuer('tenantly').setAudience('tenantly-api').setIssuedAt().setExpirationTime(exp).sign(new TextEncoder().encode(secret));
    const now = Math.floor(Date.now() / 1000);
    expect((await get(`Bearer ${await forge('a-completely-different-secret-value-123456', now + 600)}`)).statusCode).toBe(401);
    expect((await get(`Bearer ${await forge('test-secret-test-secret-test-secret-1234', now - 60)}`)).statusCode).toBe(401);
    expect((await get(`Bearer ${await forge('test-secret-test-secret-test-secret-1234', now + 600)}`)).statusCode).toBe(200);
  });

  it('rejects unsigned (alg=none) tokens', async () => {
    const s = await register(app);
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const token = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: s.userId, tid: s.tenantId, role: 'owner', iss: 'tenantly', aud: 'tenantly-api', exp: 9999999999 })}.`;
    expect((await app.inject({ method: 'GET', url: '/projects', headers: { authorization: `Bearer ${token}` } })).statusCode).toBe(401);
  });
});

describe('refresh token rotation', () => {
  it('rotates on every use and returns working tokens', async () => {
    const s = await register(app);
    const r1 = await post('/auth/refresh', { refreshToken: s.refreshToken });
    expect(r1.statusCode).toBe(200);
    expect(r1.json().refreshToken).not.toBe(s.refreshToken);
    const me = await app.inject({ method: 'GET', url: '/me', headers: { authorization: `Bearer ${r1.json().accessToken}` } });
    expect(me.statusCode).toBe(200);
  });

  it('detects reuse of a rotated token and revokes the entire family', async () => {
    const s = await register(app);
    const r1 = (await post('/auth/refresh', { refreshToken: s.refreshToken })).json();
    const replay = await post('/auth/refresh', { refreshToken: s.refreshToken }); // attacker replays the old token
    expect(replay.statusCode).toBe(401);
    expect(replay.json().error.code).toBe('refresh_token_reused');
    // The legitimate holder's newest token is now dead as well.
    expect((await post('/auth/refresh', { refreshToken: r1.refreshToken })).statusCode).toBe(401);
    const { rows } = await sql.system(`SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = 'auth.refresh_reuse_detected'`, [s.tenantId]);
    expect(rows[0].n).toBe(1);
  });

  it('logout revokes the session', async () => {
    const s = await register(app);
    expect((await post('/auth/logout', { refreshToken: s.refreshToken })).statusCode).toBe(204);
    expect((await post('/auth/refresh', { refreshToken: s.refreshToken })).statusCode).toBe(401);
  });

  it('rejects unknown refresh tokens', async () => {
    expect((await post('/auth/refresh', { refreshToken: 'x'.repeat(43) })).statusCode).toBe(401);
  });
});

describe('multi-workspace users', () => {
  it('can switch between workspaces they belong to, but not into others', async () => {
    const a = await register(app, 'Alpha');
    const b = await register(app, 'Beta');
    // Alpha's owner invites Beta's owner (an existing account) as a member.
    const inv = await app.inject({ method: 'POST', url: '/tenants/current/invitations', headers: bearer(a), payload: { email: b.email, role: 'member' } });
    const accept = await post('/invitations/accept', { token: inv.json().token }, bearer(b));
    expect(accept.statusCode).toBe(200);

    const me = await app.inject({ method: 'GET', url: '/me', headers: bearer(b) });
    expect(me.json().workspaces).toHaveLength(2);

    const switched = await post('/auth/switch-tenant', { tenantId: a.tenantId }, bearer(b));
    expect(switched.statusCode).toBe(200);
    const projects = await app.inject({ method: 'GET', url: '/projects', headers: { authorization: `Bearer ${switched.json().accessToken}` } });
    expect(projects.statusCode).toBe(200);

    const c = await register(app, 'Gamma');
    expect((await post('/auth/switch-tenant', { tenantId: c.tenantId }, bearer(b))).statusCode).toBe(403);
  });
});

describe('OAuth2 authorization code + PKCE', () => {
  const profile = { subject: 'idp-user-1', email: uniqueEmail('oauth'), emailVerified: true, name: 'Oauth User' };
  let local: FastifyInstance;
  const provider = fakeProvider(profile);
  beforeAll(async () => { local = await makeApp({ oauthProviders: { fake: provider } }); });
  afterAll(() => local.close());

  const start = async () => {
    const res = await local.inject({ method: 'GET', url: '/auth/oauth/fake/start' });
    expect(res.statusCode).toBe(302);
    const url = new URL(res.headers.location as string);
    return { state: url.searchParams.get('state')!, challenge: url.searchParams.get('code_challenge')! };
  };

  it('redirects with state + S256 challenge, then signs the user in and provisions a workspace', async () => {
    const { state, challenge } = await start();
    const cb = await local.inject({ method: 'GET', url: `/auth/oauth/fake/callback?code=good-code&state=${state}` });
    expect(cb.statusCode).toBe(200);
    const body = cb.json();
    expect(body.tenant.role).toBe('owner');
    // The verifier sent to the provider must hash to the challenge we put in the redirect.
    const { createHash } = await import('node:crypto');
    expect(createHash('sha256').update(provider.lastVerifier!).digest('base64url')).toBe(challenge);
    const me = await local.inject({ method: 'GET', url: '/me', headers: bearer(body) });
    expect(me.json().user.email).toBe(profile.email);
  });

  it('is idempotent for returning users (same account, no duplicate)', async () => {
    const { state } = await start();
    const cb = await local.inject({ method: 'GET', url: `/auth/oauth/fake/callback?code=good-code&state=${state}` });
    expect(cb.statusCode).toBe(200);
    const { rows } = await sql.system('SELECT count(*)::int AS n FROM users WHERE lower(email) = lower($1)', [profile.email]);
    expect(rows[0].n).toBe(1);
  });

  it('rejects replayed, unknown and missing state (CSRF protection)', async () => {
    const { state } = await start();
    expect((await local.inject({ method: 'GET', url: `/auth/oauth/fake/callback?code=good-code&state=${state}` })).statusCode).toBe(200);
    expect((await local.inject({ method: 'GET', url: `/auth/oauth/fake/callback?code=good-code&state=${state}` })).statusCode).toBe(400);
    expect((await local.inject({ method: 'GET', url: '/auth/oauth/fake/callback?code=good-code&state=forged' })).statusCode).toBe(400);
    expect((await local.inject({ method: 'GET', url: '/auth/oauth/fake/callback?code=good-code' })).statusCode).toBe(400);
  });

  it('rejects a bad authorization code, unverified provider emails and unknown providers', async () => {
    const { state } = await start();
    expect((await local.inject({ method: 'GET', url: `/auth/oauth/fake/callback?code=bad&state=${state}` })).statusCode).toBe(401);

    const unverified = await makeApp({ oauthProviders: { fake: fakeProvider({ ...profile, subject: 'u2', email: uniqueEmail('unv'), emailVerified: false }) } });
    const s = new URL((await unverified.inject({ method: 'GET', url: '/auth/oauth/fake/start' })).headers.location as string).searchParams.get('state');
    expect((await unverified.inject({ method: 'GET', url: `/auth/oauth/fake/callback?code=good-code&state=${s}` })).statusCode).toBe(403);
    await unverified.close();

    expect((await local.inject({ method: 'GET', url: '/auth/oauth/nope/start' })).statusCode).toBe(404);
  });
});
