import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  addMember, bearer, fakeProvider, makeApp, PASSWORD, register, shutdown, sql, uniqueEmail, type Session,
} from './helpers.js';

let app: FastifyInstance;
beforeAll(async () => { app = await makeApp(); });
afterAll(() => shutdown(app));

const post = (url: string, payload?: object, headers: Record<string, string> = {}) =>
  app.inject({ method: 'POST', url, payload, headers });

/** Registers through the real endpoint and returns the session plus the emailed token. */
async function signUp(workspaceName = 'Verify Co') {
  const email = uniqueEmail('new');
  const res = await post('/auth/register', { email, password: PASSWORD, name: 'New Person', workspaceName });
  expect(res.statusCode).toBe(201);
  const body = res.json();
  const session: Session = {
    userId: body.user.id, tenantId: body.tenant.id, email, accessToken: body.accessToken, refreshToken: body.refreshToken,
  };
  return { session, body, token: body.verificationToken as string };
}

const isVerified = async (userId: string) =>
  (await sql.system('SELECT email_verified FROM users WHERE id = $1', [userId])).rows[0].email_verified as boolean;
const me = async (s: Session) => (await app.inject({ method: 'GET', url: '/me', headers: bearer(s) })).json();

describe('signing up', () => {
  it('creates an unverified account and issues a link', async () => {
    const { session, body, token } = await signUp();
    expect(body.user.emailVerified).toBe(false);
    expect(token).toMatch(/^[\w-]{40,}$/);
    expect(await isVerified(session.userId)).toBe(false);
    expect((await me(session)).user.email_verified).toBe(false);
  });

  it('stores only a hash of the token', async () => {
    const { session, token } = await signUp();
    const { rows } = await sql.system('SELECT token_hash, email FROM email_verifications WHERE user_id = $1', [session.userId]);
    expect(rows).toHaveLength(1);
    expect(rows[0].token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(rows[0].token_hash).not.toContain(token);
    expect(rows[0].email).toBe(session.email);
  });

  it('login reports whether the address is verified', async () => {
    const { session } = await signUp();
    const before = await post('/auth/login', { email: session.email, password: PASSWORD });
    expect(before.json().user.emailVerified).toBe(false);
    await sql.system('UPDATE users SET email_verified = true WHERE id = $1', [session.userId]);
    expect((await post('/auth/login', { email: session.email, password: PASSWORD })).json().user.emailVerified).toBe(true);
  });
});

describe('POST /auth/verify-email', () => {
  it('verifies the account, takes effect immediately, and records an audit event', async () => {
    const { session, token } = await signUp();
    const res = await post('/auth/verify-email', { token });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ verified: true });
    expect(await isVerified(session.userId)).toBe(true);
    expect((await me(session)).user.email_verified).toBe(true); // same access token, no re-login needed

    const { rows } = await sql.system(
      `SELECT actor_id FROM audit_logs WHERE tenant_id = $1 AND action = 'auth.email_verified'`, [session.tenantId]);
    expect(rows).toHaveLength(1);
    expect(rows[0].actor_id).toBe(session.userId);
  });

  it('works without being signed in (the link can be opened on another device)', async () => {
    const { session, token } = await signUp();
    expect((await post('/auth/verify-email', { token })).statusCode).toBe(200);
    expect(await isVerified(session.userId)).toBe(true);
  });

  it('is single use', async () => {
    const { token } = await signUp();
    expect((await post('/auth/verify-email', { token })).statusCode).toBe(200);
    const again = await post('/auth/verify-email', { token });
    expect(again.statusCode).toBe(400);
    expect(again.json().error.code).toBe('invalid_verification_token');
  });

  it('rejects unknown, malformed and missing tokens without verifying anyone', async () => {
    const { session, token } = await signUp();
    const forged = `${token.slice(0, -3)}${token.endsWith('aaa') ? 'bbb' : 'aaa'}`;
    expect((await post('/auth/verify-email', { token: forged })).statusCode).toBe(400);
    expect((await post('/auth/verify-email', { token: 'x'.repeat(40) })).statusCode).toBe(400);
    expect((await post('/auth/verify-email', { token: 'short' })).statusCode).toBe(400);
    expect((await post('/auth/verify-email', {})).statusCode).toBe(400);
    expect(await isVerified(session.userId)).toBe(false);
  });

  it('rejects an expired link', async () => {
    const { session, token } = await signUp();
    await sql.system(`UPDATE email_verifications SET expires_at = now() - interval '1 second' WHERE user_id = $1`, [session.userId]);
    expect((await post('/auth/verify-email', { token })).statusCode).toBe(400);
    expect(await isVerified(session.userId)).toBe(false);
  });

  it('does not accept a link that was sent to an address the account no longer has', async () => {
    const { session, token } = await signUp();
    await sql.system('UPDATE users SET email = $2 WHERE id = $1', [session.userId, uniqueEmail('changed')]);
    expect((await post('/auth/verify-email', { token })).statusCode).toBe(400);
    expect(await isVerified(session.userId)).toBe(false);
  });

  it('lets exactly one of many concurrent redemptions succeed', async () => {
    const { token } = await signUp();
    const results = await Promise.all(Array.from({ length: 8 }, () => post('/auth/verify-email', { token })));
    expect(results.filter((r) => r.statusCode === 200)).toHaveLength(1);
    expect(results.filter((r) => r.statusCode === 400)).toHaveLength(7);
  });
});

describe('POST /auth/resend-verification', () => {
  it('requires authentication', async () => {
    expect((await post('/auth/resend-verification')).statusCode).toBe(401);
  });

  it('issues a new link and voids the old one', async () => {
    const { session, token: oldToken } = await signUp();
    await sql.system(`UPDATE email_verifications SET created_at = now() - interval '61 seconds' WHERE user_id = $1`, [session.userId]);
    const res = await post('/auth/resend-verification', undefined, bearer(session));
    expect(res.statusCode).toBe(202);
    const fresh = res.json().verificationToken as string;
    expect(res.json().status).toBe('sent');
    expect(fresh).not.toBe(oldToken);

    expect((await post('/auth/verify-email', { token: oldToken })).statusCode).toBe(400);
    expect((await post('/auth/verify-email', { token: fresh })).statusCode).toBe(200);
    const { rows } = await sql.system('SELECT count(*)::int AS n FROM email_verifications WHERE user_id = $1 AND used_at IS NULL', [session.userId]);
    expect(rows[0].n).toBe(0);
  });

  it('allows one email a minute per account, with a Retry-After', async () => {
    const { session } = await signUp();
    const first = await post('/auth/resend-verification', undefined, bearer(session));
    expect(first.statusCode).toBe(429); // signing up already sent one a moment ago
    const wait = Number(first.headers['retry-after']);
    expect(wait).toBeGreaterThanOrEqual(1);
    expect(wait).toBeLessThanOrEqual(60);
    expect(first.json().error).toMatchObject({ code: 'verification_email_throttled', details: { retryAfterSeconds: wait } });

    await sql.system(`UPDATE email_verifications SET created_at = now() - interval '61 seconds' WHERE user_id = $1`, [session.userId]);
    expect((await post('/auth/resend-verification', undefined, bearer(session))).statusCode).toBe(202);
    expect((await post('/auth/resend-verification', undefined, bearer(session))).statusCode).toBe(429);
  });

  it('cannot be used to flood: concurrent resends send one email', async () => {
    const { session } = await signUp();
    await sql.system(`UPDATE email_verifications SET created_at = now() - interval '61 seconds' WHERE user_id = $1`, [session.userId]);
    const results = await Promise.all(Array.from({ length: 6 }, () => post('/auth/resend-verification', undefined, bearer(session))));
    expect(results.filter((r) => r.statusCode === 202)).toHaveLength(1);
    expect(results.filter((r) => r.statusCode === 429)).toHaveLength(5);
  });

  it('says so when the address is already verified, and sends nothing', async () => {
    const { session, token } = await signUp();
    await post('/auth/verify-email', { token });
    const res = await post('/auth/resend-verification', undefined, bearer(session));
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'already_verified' });
    expect(res.json().verificationToken).toBeUndefined();
  });
});

describe('what an unverified address can and cannot do', () => {
  it('can use the product', async () => {
    const { session } = await signUp();
    const project = await app.inject({ method: 'POST', url: '/projects', headers: bearer(session), payload: { name: 'First' } });
    expect(project.statusCode).toBe(201);
    expect((await app.inject({ method: 'GET', url: '/tenants/current', headers: bearer(session) })).statusCode).toBe(200);
  });

  it('cannot invite people or start a checkout until verified', async () => {
    const { session, token } = await signUp();
    const invite = () => app.inject({
      method: 'POST', url: '/tenants/current/invitations', headers: bearer(session),
      payload: { email: uniqueEmail('friend'), role: 'member' },
    });
    const blocked = await invite();
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json().error.code).toBe('email_not_verified');
    const checkout = await app.inject({ method: 'POST', url: '/billing/checkout', headers: bearer(session) });
    expect(checkout.statusCode).toBe(403);
    expect(checkout.json().error.code).toBe('email_not_verified');

    await post('/auth/verify-email', { token });
    expect((await invite()).statusCode).toBe(201); // the same access token works straight away
  });

  it('still reports a missing permission before mentioning verification', async () => {
    const { session, token } = await signUp();
    await post('/auth/verify-email', { token });
    const viewer = await addMember(app, session, 'viewer');
    const res = await app.inject({
      method: 'POST', url: '/tenants/current/invitations', headers: bearer(viewer),
      payload: { email: uniqueEmail('x'), role: 'viewer' },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('forbidden');
  });

  it('treats people who joined through an invitation as verified (the emailed token proved their address)', async () => {
    const owner = await register(app, 'Inviter');
    const member = await addMember(app, owner, 'member');
    expect((await me(member)).user.email_verified).toBe(true);
  });
});

describe('Google sign-in and unverified accounts', () => {
  const providerFor = (email: string, subject: string) =>
    fakeProvider({ subject, email, emailVerified: true, name: 'Real Owner' });

  const signInWithGoogle = async (email: string, subject: string) => {
    const local = await makeApp({ oauthProviders: { fake: providerFor(email, subject) } });
    try {
      const start = await local.inject({ method: 'GET', url: '/auth/oauth/fake/start' });
      const state = new URL(start.headers.location as string).searchParams.get('state');
      return await local.inject({ method: 'GET', url: `/auth/oauth/fake/callback?code=good-code&state=${state}` });
    } finally {
      await local.close();
    }
  };

  it("takes the account away from whoever registered an address they hadn't verified", async () => {
    // An attacker registers the victim's address with a password of their own, before the victim signs up.
    const attacker = await signUp('Attacker Workspace');
    const victimEmail = attacker.session.email;

    const res = await signInWithGoogle(victimEmail, `idp-${attacker.session.userId}`);
    expect(res.statusCode).toBe(200);
    expect(res.json().user.id).toBe(attacker.session.userId); // same account, now the real owner's

    expect(await isVerified(attacker.session.userId)).toBe(true);
    // The attacker's password no longer works...
    expect((await post('/auth/login', { email: victimEmail, password: PASSWORD })).statusCode).toBe(401);
    // ...their existing session can't be refreshed...
    expect((await post('/auth/refresh', { refreshToken: attacker.session.refreshToken })).statusCode).toBe(401);
    // ...and the verification link they were holding is dead.
    expect((await post('/auth/verify-email', { token: attacker.token })).statusCode).toBe(400);

    const audit = await sql.system(
      `SELECT 1 FROM audit_logs WHERE tenant_id = $1 AND action = 'auth.unverified_account_reclaimed'`, [attacker.session.tenantId]);
    expect(audit.rowCount).toBe(1);
  });

  it('leaves a verified password account alone when it links Google', async () => {
    const owner = await register(app, 'Legit Owner'); // verified
    const res = await signInWithGoogle(owner.email, `idp-${owner.userId}`);
    expect(res.statusCode).toBe(200);
    expect((await post('/auth/login', { email: owner.email, password: PASSWORD })).statusCode).toBe(200);
    expect((await post('/auth/refresh', { refreshToken: owner.refreshToken })).statusCode).toBe(200);
  });
});
