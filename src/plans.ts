export type Plan = 'free' | 'pro';

export const PLAN_LIMITS: Record<Plan, { projects: number }> = {
  free: { projects: 3 },
  pro: { projects: Number.POSITIVE_INFINITY },
};

/** Stripe subscription statuses that keep paid entitlements (past_due = grace period while Stripe retries). */
export const ENTITLED_STATUSES = new Set(['active', 'trialing', 'past_due']);
