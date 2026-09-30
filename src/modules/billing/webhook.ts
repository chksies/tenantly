import type Stripe from 'stripe';
import { audit } from '../../audit.js';
import { withSystem, type Db } from '../../db.js';
import { ENTITLED_STATUSES } from '../../plans.js';

export type WebhookResult = 'processed' | 'duplicate';

const customerId = (c: unknown): string | null =>
  typeof c === 'string' ? c : c && typeof c === 'object' && 'id' in c ? String((c as { id: string }).id) : null;

async function tenantFor(db: Db, metaTenantId: string | undefined, customer: string | null): Promise<string | null> {
  if (metaTenantId) {
    const r = await db.query('SELECT id FROM tenants WHERE id = $1', [metaTenantId]);
    if (r.rows[0]) return r.rows[0].id;
  }
  if (customer) {
    const r = await db.query('SELECT id FROM tenants WHERE stripe_customer_id = $1', [customer]);
    if (r.rows[0]) return r.rows[0].id;
  }
  return null;
}

async function applySubscription(db: Db, event: Stripe.Event) {
  const sub = event.data.object as unknown as Stripe.Subscription & { current_period_end?: number };
  const customer = customerId(sub.customer);
  const tenantId = await tenantFor(db, sub.metadata?.tenant_id, customer);
  if (!tenantId) return; // Not one of ours (or tenant deleted). Recorded as processed so Stripe stops retrying.

  const status = event.type === 'customer.subscription.deleted' ? 'canceled' : sub.status;
  const plan = ENTITLED_STATUSES.has(status) ? 'pro' : 'free';
  const item = sub.items?.data?.[0] as (Stripe.SubscriptionItem & { current_period_end?: number }) | undefined;
  const periodEnd = item?.current_period_end ?? sub.current_period_end ?? null;

  // Only apply if this event is at least as new as what we hold (webhooks arrive out of order), and
  // never let a stale event for a *different* subscription downgrade the tenant's current one.
  const upsert = await db.query(
    `INSERT INTO subscriptions (tenant_id, stripe_subscription_id, status, plan, price_id, current_period_end, cancel_at_period_end, last_event_at)
     VALUES ($1, $2, $3, $4, $5, to_timestamp($6), $7, to_timestamp($8))
     ON CONFLICT (tenant_id) DO UPDATE SET
       stripe_subscription_id = EXCLUDED.stripe_subscription_id, status = EXCLUDED.status, plan = EXCLUDED.plan,
       price_id = EXCLUDED.price_id, current_period_end = EXCLUDED.current_period_end,
       cancel_at_period_end = EXCLUDED.cancel_at_period_end, last_event_at = EXCLUDED.last_event_at, updated_at = now()
     WHERE subscriptions.last_event_at <= EXCLUDED.last_event_at
       AND (subscriptions.stripe_subscription_id = EXCLUDED.stripe_subscription_id
            OR EXCLUDED.status IN ('active', 'trialing', 'past_due'))`,
    [tenantId, sub.id, status, plan, item?.price?.id ?? null, periodEnd, sub.cancel_at_period_end ?? false, event.created]);
  if (upsert.rowCount === 0) return; // stale event, ignored

  await db.query(
    'UPDATE tenants SET plan = $2, stripe_customer_id = coalesce(stripe_customer_id, $3) WHERE id = $1', [tenantId, plan, customer]);
  await audit(db, {
    tenantId, action: `billing.${event.type.replace('customer.', '')}`, entityType: 'subscriptions', entityId: sub.id,
    metadata: { status, plan, eventId: event.id },
  });
}

async function applyInvoice(db: Db, event: Stripe.Event) {
  const invoice = event.data.object as Stripe.Invoice;
  const tenantId = await tenantFor(db, undefined, customerId(invoice.customer));
  if (!tenantId) return;
  await audit(db, {
    tenantId, action: `billing.${event.type}`, entityType: 'invoices', entityId: invoice.id ?? undefined,
    metadata: { amount: event.type === 'invoice.paid' ? invoice.amount_paid : invoice.amount_due, currency: invoice.currency, eventId: event.id },
  });
}

async function applyCheckoutCompleted(db: Db, event: Stripe.Event) {
  const session = event.data.object as Stripe.Checkout.Session;
  const customer = customerId(session.customer);
  const tenantId = await tenantFor(db, session.client_reference_id ?? undefined, customer);
  if (!tenantId) return;
  if (customer) await db.query('UPDATE tenants SET stripe_customer_id = coalesce(stripe_customer_id, $2) WHERE id = $1', [tenantId, customer]);
  await audit(db, { tenantId, action: 'billing.checkout.completed', entityType: 'checkout_sessions', entityId: session.id, metadata: { eventId: event.id } });
}

/**
 * Idempotent, transactional event handler. The ledger insert and all side effects share one
 * transaction: if handling throws, the ledger row rolls back too, the endpoint returns 500,
 * and Stripe's retry gets a clean second attempt. If two deliveries of the same event race,
 * the loser blocks on the primary key and then sees a duplicate.
 */
export async function processStripeEvent(event: Stripe.Event): Promise<WebhookResult> {
  return withSystem(async (db) => {
    const fresh = await db.query(
      'INSERT INTO stripe_events (id, type) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING RETURNING id', [event.id, event.type]);
    if (fresh.rowCount === 0) return 'duplicate';

    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted':
        await applySubscription(db, event);
        break;
      case 'invoice.paid':
      case 'invoice.payment_failed':
        await applyInvoice(db, event);
        break;
      case 'checkout.session.completed':
        await applyCheckoutCompleted(db, event);
        break;
      default:
        break; // Unhandled types are acknowledged so Stripe doesn't retry them.
    }
    return 'processed';
  });
}
