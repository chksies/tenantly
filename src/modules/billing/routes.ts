import type { FastifyInstance } from 'fastify';
import Stripe from 'stripe';
import { audit } from '../../audit.js';
import { requirePermission, tenantTx } from '../../auth.js';
import { config } from '../../config.js';
import { AppError } from '../../errors.js';
import { processStripeEvent } from './webhook.js';

export function createStripe(): Stripe {
  return new Stripe(config.STRIPE_SECRET_KEY);
}

export async function billingRoutes(app: FastifyInstance, opts: { stripe: Stripe }) {
  const { stripe } = opts;

  app.get('/billing', { preHandler: requirePermission('billing:read') }, async (req) =>
    tenantTx(req, async (db) => {
      const tenant = (await db.query('SELECT plan, stripe_customer_id IS NOT NULL AS has_customer FROM tenants')).rows[0];
      const subscription = (await db.query(
        'SELECT status, plan, price_id, current_period_end, cancel_at_period_end FROM subscriptions')).rows[0] ?? null;
      return { plan: tenant.plan, hasStripeCustomer: tenant.has_customer, subscription };
    }));

  /** Ensures the tenant has a Stripe customer, creating one on first use. */
  async function ensureCustomer(req: Parameters<typeof tenantTx>[0]): Promise<string> {
    return tenantTx(req, async (db) => {
      const t = (await db.query('SELECT id, name, stripe_customer_id FROM tenants FOR UPDATE')).rows[0];
      if (t.stripe_customer_id) return t.stripe_customer_id as string;
      const customer = await stripe.customers.create(
        { name: t.name, metadata: { tenant_id: t.id } },
        { idempotencyKey: `tenant-customer-${t.id}` });
      await db.query('UPDATE tenants SET stripe_customer_id = $1 WHERE id = app_tenant_id()', [customer.id]);
      await audit(db, { tenantId: t.id, action: 'billing.customer.created', metadata: { customerId: customer.id } });
      return customer.id;
    });
  }

  app.post('/billing/checkout', { preHandler: requirePermission('billing:manage') }, async (req) => {
    const tenantId = req.auth!.tenantId;
    const customer = await ensureCustomer(req);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer,
      client_reference_id: tenantId,
      line_items: [{ price: config.STRIPE_PRICE_PRO, quantity: 1 }],
      subscription_data: { metadata: { tenant_id: tenantId } },
      success_url: `${config.APP_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${config.APP_URL}/billing/cancelled`,
    });
    if (!session.url) throw new AppError(502, 'stripe_error', 'Stripe did not return a checkout URL');
    return { url: session.url };
  });

  app.post('/billing/portal', { preHandler: requirePermission('billing:manage') }, async (req) => {
    const customer = await ensureCustomer(req);
    const session = await stripe.billingPortal.sessions.create({ customer, return_url: `${config.APP_URL}/billing` });
    return { url: session.url };
  });

  // Webhook lives in its own encapsulated scope so we can keep the raw body (required for
  // signature verification) without affecting JSON parsing anywhere else.
  await app.register(async (scope) => {
    scope.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));

    scope.post('/webhooks/stripe', async (req, reply) => {
      const signature = req.headers['stripe-signature'];
      if (typeof signature !== 'string') throw new AppError(400, 'invalid_signature', 'Missing Stripe-Signature header');
      let event: Stripe.Event;
      try {
        event = stripe.webhooks.constructEvent(req.body as Buffer, signature, config.STRIPE_WEBHOOK_SECRET);
      } catch {
        throw new AppError(400, 'invalid_signature', 'Webhook signature verification failed');
      }
      const result = await processStripeEvent(event);
      return reply.status(200).send({ received: true, result });
    });
  });
}
