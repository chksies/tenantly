export type Plan = 'free' | 'pro' | 'enterprise';

export interface PlanLimits {
  projects: number;
  /** Requests a single tenant may make per rate-limit window (shared by all of its users and tokens). */
  requestsPerWindow: number;
}

export const PLAN_LIMITS: Record<Plan, PlanLimits> = {
  free: { projects: 3, requestsPerWindow: 60 },
  pro: { projects: Number.POSITIVE_INFINITY, requestsPerWindow: 600 },
  // Sold by hand rather than through Stripe Checkout; see "Plans" in the README.
  enterprise: { projects: Number.POSITIVE_INFINITY, requestsPerWindow: 6000 },
};

export const isPlan = (value: unknown): value is Plan =>
  typeof value === 'string' && Object.hasOwn(PLAN_LIMITS, value);

/** Stripe subscription statuses that keep paid entitlements (past_due = grace period while Stripe retries). */
export const ENTITLED_STATUSES = new Set(['active', 'trialing', 'past_due']);
