import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import Stripe from 'stripe';
import { buildApp } from '../src/app.js';
import { appPool, closePools, systemPool, withSystem } from '../src/db.js';
import type { OAuthProfile, OAuthProvider } from '../src/modules/auth/oauth.js';

export const PASSWORD = 'correct-horse-battery';

export async function makeApp(overrides: Parameters<typeof buildApp>[0] = {}) {
  return buildApp(overrides);
}

export async function shutdown(app: FastifyInstance) {
  await app.close();
  await closePools();
}

export interface Session {
  userId: string;
  tenantId: string;
  email: string;
  accessToken: string;
  refreshToken: string;
}

export const bearer = (s: { accessToken: string }) => ({ authorization: `Bearer ${s.accessToken}` });
export const uniqueEmail = (prefix = 'user') => `${prefix}-${randomUUID().slice(0, 8)}@example.com`;

/** Registers a new user with a fresh workspace (the user is its owner). */
export async function register(app: FastifyInstance, workspaceName = 'Acme'): Promise<Session> {
  const email = uniqueEmail('owner');
  const res = await app.inject({
    method: 'POST', url: '/auth/register',
    payload: { email, password: PASSWORD, name: 'Test Owner', workspaceName },
  });
  if (res.statusCode !== 201) throw new Error(`register failed: ${res.body}`);
  const body = res.json();
  return { userId: body.user.id, tenantId: body.tenant.id, email, accessToken: body.accessToken, refreshToken: body.refreshToken };
}

/** Invites a brand-new person into `owner`'s workspace with `role` and accepts on their behalf. */
export async function addMember(app: FastifyInstance, owner: Session, role: 'admin' | 'member' | 'viewer'): Promise<Session> {
  const email = uniqueEmail(role);
  const inv = await app.inject({
    method: 'POST', url: '/tenants/current/invitations', headers: bearer(owner), payload: { email, role },
  });
  if (inv.statusCode !== 201) throw new Error(`invite failed: ${inv.body}`);
  const acc = await app.inject({
    method: 'POST', url: '/invitations/accept',
    payload: { token: inv.json().token, name: `Test ${role}`, password: PASSWORD },
  });
  if (acc.statusCode !== 200) throw new Error(`accept failed: ${acc.body}`);
  const body = acc.json();
  const me = await app.inject({ method: 'GET', url: '/me', headers: { authorization: `Bearer ${body.accessToken}` } });
  return { userId: me.json().user.id, tenantId: body.tenantId, email, accessToken: body.accessToken, refreshToken: body.refreshToken };
}

export const sql = {
  app: (text: string, params?: unknown[]) => appPool.query(text, params),
  system: (text: string, params?: unknown[]) => systemPool.query(text, params),
};
export { withSystem };

// ------------------------------------------------------------------ Stripe helpers
export const stripeForTests = new Stripe('sk_test_dummy');

export function stripeEvent(type: string, object: Record<string, unknown>, created = Math.floor(Date.now() / 1000), id = `evt_${randomUUID()}`) {
  return { id, object: 'event', type, created, data: { object }, livemode: false, api_version: '2025-01-01', pending_webhooks: 1 };
}

export function signedWebhook(app: FastifyInstance, event: object, secret = 'whsec_test_secret') {
  const payload = JSON.stringify(event);
  const signature = stripeForTests.webhooks.generateTestHeaderString({ payload, secret });
  return app.inject({
    method: 'POST', url: '/webhooks/stripe', payload,
    headers: { 'content-type': 'application/json', 'stripe-signature': signature },
  });
}

export const subscriptionObject = (tenantId: string, over: Record<string, unknown> = {}) => ({
  id: 'sub_test_1', object: 'subscription', status: 'active', customer: 'cus_test_1',
  cancel_at_period_end: false, metadata: { tenant_id: tenantId },
  items: { data: [{ price: { id: 'price_pro_test' }, current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400 }] },
  ...over,
});

// ------------------------------------------------------------------ OAuth helper
export function fakeProvider(profile: OAuthProfile): OAuthProvider & { lastVerifier?: string } {
  const p: OAuthProvider & { lastVerifier?: string } = {
    name: 'fake',
    authorizationUrl: ({ state, codeChallenge }) => `https://idp.example/authorize?state=${state}&code_challenge=${codeChallenge}`,
    async exchange({ code, codeVerifier }) {
      if (code !== 'good-code') throw new Error('bad code');
      p.lastVerifier = codeVerifier;
      return profile;
    },
  };
  return p;
}
