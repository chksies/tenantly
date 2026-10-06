import { isPlan, PLAN_LIMITS, type Plan } from '../plans.js';
import { rateLimitKey, type RateLimitDecision, type RateLimitStore } from './store.js';

export interface TenantLimitResult extends RateLimitDecision {
  plan: Plan;
  windowSeconds: number;
}

export interface TenantRateLimiterOptions {
  store: RateLimitStore;
  /** Returns the tenant's current plan, or null if the tenant no longer exists. */
  loadPlan: (tenantId: string) => Promise<string | null>;
  windowSeconds: number;
  /** 0 disables the cache (every request reads the plan from the database). */
  planCacheSeconds: number;
  now?: () => number;
}

const MAX_CACHED_TENANTS = 10_000;

/**
 * Decides, per tenant, whether a request fits in the tenant's plan.
 *
 * The limit belongs to the tenant, not the user or token: ten members share one budget, so a tenant
 * can't multiply its allowance by adding seats or minting tokens.
 *
 * The plan comes from Postgres, but not on every request. A rate limiter that costs a database
 * round-trip per request would add the very load it exists to shed, so plans are cached
 * per process for a few seconds. Concurrent misses for one tenant share a single query. The price
 * is that a plan change reaches each node within `planCacheSeconds`, which is fine for a quota.
 */
export class TenantRateLimiter {
  private readonly plans = new Map<string, { plan: Promise<Plan>; expiresAt: number }>();
  private readonly now: () => number;

  constructor(private readonly opts: TenantRateLimiterOptions) {
    this.now = opts.now ?? Date.now;
  }

  async check(tenantId: string): Promise<TenantLimitResult> {
    const plan = await this.planFor(tenantId);
    const decision = await this.opts.store.hit(
      rateLimitKey(tenantId), PLAN_LIMITS[plan].requestsPerWindow, this.opts.windowSeconds * 1000);
    return { ...decision, plan, windowSeconds: this.opts.windowSeconds };
  }

  /** Drops a tenant's cached plan so the next request re-reads it (this process only). */
  invalidatePlan(tenantId: string) {
    this.plans.delete(tenantId);
  }

  private planFor(tenantId: string): Promise<Plan> {
    const ttlMs = this.opts.planCacheSeconds * 1000;
    const hit = this.plans.get(tenantId);
    if (hit && hit.expiresAt > this.now()) return hit.plan;

    // A tenant that has been deleted (or an unrecognised value) gets the strictest tier.
    const plan = this.opts.loadPlan(tenantId).then((p): Plan => (isPlan(p) ? p : 'free'));
    if (ttlMs > 0) {
      this.plans.delete(tenantId); // re-insert so Map order tracks recency for eviction
      this.plans.set(tenantId, { plan, expiresAt: this.now() + ttlMs });
      if (this.plans.size > MAX_CACHED_TENANTS) this.plans.delete(this.plans.keys().next().value!);
      // Never cache a failure: the next request should try the database again.
      plan.catch(() => { if (this.plans.get(tenantId)?.plan === plan) this.plans.delete(tenantId); });
    }
    return plan;
  }
}
