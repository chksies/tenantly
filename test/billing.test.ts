import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { bearer, makeApp, register, shutdown, signedWebhook, sql, stripeEvent, subscriptionObject, type Session } from './helpers.js';

let app: FastifyInstance;
beforeAll(async () => { app = await makeApp(); });
afterAll(() => shutdown(app));

const state = async (t: Session) => ({
  tenant: (await sql.system('SELECT plan, stripe_customer_id FROM tenants WHERE id = $1', [t.tenantId])).rows[0],
  sub: (await sql.system('SELECT * FROM subscriptions WHERE tenant_id = $1', [t.tenantId])).rows[0],
});
const customer = () => `cus_${Math.random().toString(36).slice(2, 10)}`;

describe('Stripe webhook signature verification', () => {
  it('rejects missing, invalid and wrongly-keyed signatures without side effects', async () => {
    const t = await register(app);
    const evt = stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId));
    const noSig = await app.inject({ method: 'POST', url: '/webhooks/stripe', payload: JSON.stringify(evt), headers: { 'content-type': 'application/json' } });
    expect(noSig.statusCode).toBe(400);
    const bad = await app.inject({ method: 'POST', url: '/webhooks/stripe', payload: JSON.stringify(evt), headers: { 'content-type': 'application/json', 'stripe-signature': 't=1,v1=deadbeef' } });
    expect(bad.statusCode).toBe(400);
    expect((await signedWebhook(app, evt, 'whsec_wrong_secret')).statusCode).toBe(400);
    expect((await state(t)).tenant.plan).toBe('free');
    const { rows } = await sql.system('SELECT 1 FROM stripe_events WHERE id = $1', [evt.id]);
    expect(rows).toHaveLength(0);
  });

  it('rejects a payload that was modified after signing', async () => {
    const t = await register(app);
    const evt = stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId));
    const { stripeForTests } = await import('./helpers.js');
    const payload = JSON.stringify(evt);
    const header = stripeForTests.webhooks.generateTestHeaderString({ payload, secret: 'whsec_test_secret' });
    const tampered = payload.replace('"active"', '"trialing"');
    const res = await app.inject({ method: 'POST', url: '/webhooks/stripe', payload: tampered, headers: { 'content-type': 'application/json', 'stripe-signature': header } });
    expect(res.statusCode).toBe(400);
  });
});

describe('subscription lifecycle', () => {
  it('upgrades the tenant on subscription.created and unlocks paid limits', async () => {
    const t = await register(app);
    const res = await signedWebhook(app, stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId, { customer: customer(), id: `sub_${t.tenantId}` })));
    expect(res.statusCode).toBe(200);
    expect(res.json().result).toBe('processed');
    const s = await state(t);
    expect(s.tenant.plan).toBe('pro');
    expect(s.sub).toMatchObject({ status: 'active', plan: 'pro', price_id: 'price_pro_test' });
    const billing = (await app.inject({ method: 'GET', url: '/billing', headers: bearer(t) })).json();
    expect(billing).toMatchObject({ plan: 'pro', subscription: { status: 'active' } });
    for (let i = 0; i < 5; i++) {
      expect((await app.inject({ method: 'POST', url: '/projects', headers: bearer(t), payload: { name: `p${i}` } })).statusCode).toBe(201);
    }
  });

  it('is idempotent: a redelivered event is acknowledged but processed once', async () => {
    const t = await register(app);
    const evt = stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId, { customer: customer(), id: `sub_${t.tenantId}` }));
    expect((await signedWebhook(app, evt)).json().result).toBe('processed');
    expect((await signedWebhook(app, evt)).json().result).toBe('duplicate');
    const { rows } = await sql.system(`SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = 'billing.subscription.created'`, [t.tenantId]);
    expect(rows[0].n).toBe(1);
  });

  it('is idempotent under concurrent duplicate deliveries', async () => {
    const t = await register(app);
    const evt = stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId, { customer: customer(), id: `sub_${t.tenantId}` }));
    const results = await Promise.all(Array.from({ length: 5 }, () => signedWebhook(app, evt)));
    expect(results.every((r) => r.statusCode === 200)).toBe(true);
    expect(results.filter((r) => r.json().result === 'processed')).toHaveLength(1);
    const { rows } = await sql.system(`SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = 'billing.subscription.created'`, [t.tenantId]);
    expect(rows[0].n).toBe(1);
  });

  it('downgrades on cancellation, and ignores out-of-order (older) events', async () => {
    const t = await register(app);
    const cus = customer();
    const sub = `sub_${t.tenantId}`;
    const now = Math.floor(Date.now() / 1000);
    await signedWebhook(app, stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId, { customer: cus, id: sub }), now - 100));
    expect((await state(t)).tenant.plan).toBe('pro');

    await signedWebhook(app, stripeEvent('customer.subscription.deleted', subscriptionObject(t.tenantId, { customer: cus, id: sub, status: 'canceled' }), now));
    expect((await state(t)).tenant.plan).toBe('free');
    expect((await state(t)).sub.status).toBe('canceled');

    // A delayed "updated: active" event from *before* the cancellation arrives late: must not resurrect the plan.
    const late = await signedWebhook(app, stripeEvent('customer.subscription.updated', subscriptionObject(t.tenantId, { customer: cus, id: sub, status: 'active' }), now - 50));
    expect(late.statusCode).toBe(200);
    expect((await state(t)).tenant.plan).toBe('free');
    expect((await state(t)).sub.status).toBe('canceled');
  });

  it('keeps paid access during past_due grace, removes it on unpaid', async () => {
    const t = await register(app);
    const cus = customer(); const sub = `sub_${t.tenantId}`;
    const now = Math.floor(Date.now() / 1000);
    await signedWebhook(app, stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId, { customer: cus, id: sub }), now - 20));
    await signedWebhook(app, stripeEvent('customer.subscription.updated', subscriptionObject(t.tenantId, { customer: cus, id: sub, status: 'past_due' }), now - 10));
    expect((await state(t)).tenant.plan).toBe('pro');
    await signedWebhook(app, stripeEvent('customer.subscription.updated', subscriptionObject(t.tenantId, { customer: cus, id: sub, status: 'unpaid' }), now));
    expect((await state(t)).tenant.plan).toBe('free');
  });

  it('a stale cancellation of an OLD subscription cannot downgrade a newer active one', async () => {
    const t = await register(app);
    const cus = customer();
    const now = Math.floor(Date.now() / 1000);
    await signedWebhook(app, stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId, { customer: cus, id: 'sub_new' }), now - 10));
    await signedWebhook(app, stripeEvent('customer.subscription.deleted', subscriptionObject(t.tenantId, { customer: cus, id: 'sub_old', status: 'canceled' }), now));
    expect((await state(t)).tenant.plan).toBe('pro');
    expect((await state(t)).sub.stripe_subscription_id).toBe('sub_new');
  });

  it('resolves the tenant from the Stripe customer id when metadata is absent', async () => {
    const t = await register(app);
    const cus = customer();
    await sql.system('UPDATE tenants SET stripe_customer_id = $2 WHERE id = $1', [t.tenantId, cus]);
    await signedWebhook(app, stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId, { customer: cus, id: `sub_${t.tenantId}`, metadata: {} })));
    expect((await state(t)).tenant.plan).toBe('pro');
  });

  it('acknowledges events for unknown tenants and unhandled event types without erroring', async () => {
    expect((await signedWebhook(app, stripeEvent('customer.subscription.created', subscriptionObject('00000000-0000-4000-8000-000000000000', { customer: customer() })))).statusCode).toBe(200);
    expect((await signedWebhook(app, stripeEvent('charge.refunded', { id: 'ch_1' }))).statusCode).toBe(200);
  });

  it('a failed handler rolls back the idempotency ledger so Stripe can retry', async () => {
    const t = await register(app);
    // Malformed object (no items / id) is fine, but a bogus tenant uuid in metadata triggers a DB error path.
    const evt = stripeEvent('customer.subscription.created', subscriptionObject(t.tenantId, { customer: customer(), id: null }));
    const res = await signedWebhook(app, evt);
    expect(res.statusCode).toBe(500);
    const { rows } = await sql.system('SELECT 1 FROM stripe_events WHERE id = $1', [evt.id]);
    expect(rows).toHaveLength(0);
  });

  it('records invoice and checkout events in the tenant audit trail', async () => {
    const t = await register(app);
    const cus = customer();
    await sql.system('UPDATE tenants SET stripe_customer_id = $2 WHERE id = $1', [t.tenantId, cus]);
    await signedWebhook(app, stripeEvent('invoice.payment_failed', { id: 'in_1', customer: cus, amount_due: 2000, currency: 'usd' }));
    const logs = (await app.inject({ method: 'GET', url: '/audit-logs?action=billing.', headers: bearer(t) })).json().items;
    expect(logs.map((l: { action: string }) => l.action)).toContain('billing.invoice.payment_failed');
  });
});

describe('checkout & portal (with a stubbed Stripe client)', () => {
  it('creates a customer once, then a checkout session bound to the tenant', async () => {
    const calls: { customers: unknown[]; sessions: any[] } = { customers: [], sessions: [] };
    const fake = {
      customers: { create: async (p: unknown) => { calls.customers.push(p); return { id: 'cus_fake_1' }; } },
      checkout: { sessions: { create: async (p: unknown) => { calls.sessions.push(p); return { url: 'https://checkout.stripe.test/s/1' }; } } },
      billingPortal: { sessions: { create: async () => ({ url: 'https://billing.stripe.test/p/1' }) } },
      webhooks: (await import('./helpers.js')).stripeForTests.webhooks,
    };
    const local = await makeApp({ stripe: fake as never });
    const t = await register(local);
    const first = await local.inject({ method: 'POST', url: '/billing/checkout', headers: bearer(t) });
    expect(first.json().url).toBe('https://checkout.stripe.test/s/1');
    await local.inject({ method: 'POST', url: '/billing/checkout', headers: bearer(t) });
    expect(calls.customers).toHaveLength(1); // customer reused on the second call
    expect(calls.sessions[0]).toMatchObject({
      mode: 'subscription', customer: 'cus_fake_1', client_reference_id: t.tenantId,
      subscription_data: { metadata: { tenant_id: t.tenantId } },
    });
    expect((await local.inject({ method: 'POST', url: '/billing/portal', headers: bearer(t) })).json().url).toContain('billing.stripe.test');
    await local.close();
  });
});
