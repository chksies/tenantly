import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { TenantRateLimiter } from '../src/ratelimit/index.js';
import type { RateLimitDecision, RateLimitStore } from '../src/ratelimit/index.js';
import {
  addMember, bearer, makeApp, PASSWORD, register, shutdown, signedWebhook, sql, stripeEvent, subscriptionObject,
  type Session,
} from './helpers.js';

/**
 * In-memory sliding-window log with a manual clock: the same algorithm as the Redis script, so the
 * HTTP behaviour (tiers, headers, 429s, isolation, fail-open) can be tested quickly and
 * deterministically. The Redis script itself is tested against a real Redis in ratelimit-redis.test.ts.
 */
class FakeStore implements RateLimitStore {
  now = 1_000_000;
  failing = false;
  private log = new Map<string, number[]>();

  async hit(key: string, limit: number, windowMs: number): Promise<RateLimitDecision> {
    if (this.failing) throw new Error('redis is down');
    const hits = (this.log.get(key) ?? []).filter((t) => t > this.now - windowMs);
    const allowed = hits.length < limit;
    if (allowed) hits.push(this.now);
    this.log.set(key, hits);
    const resetMs = hits.length ? hits[0]! + windowMs - this.now : windowMs;
    return { allowed, limit, remaining: limit - hits.length, resetMs };
  }
}

const store = new FakeStore();
let app: FastifyInstance;

beforeAll(async () => {
  // planCacheSeconds: 0 so a plan changed in the database is seen by the very next request.
  app = await makeApp({ rateLimit: { store, planCacheSeconds: 0, windowSeconds: 60 } });
});
afterAll(() => shutdown(app));

const me = (s: Session) => app.inject({ method: 'GET', url: '/me', headers: bearer(s) });
const setPlan = (s: Session, plan: string) => sql.system('UPDATE tenants SET plan = $2 WHERE id = $1', [s.tenantId, plan]);

describe('limits by plan', () => {
  it.each([['free', 60], ['pro', 600], ['enterprise', 6000]])('%s tenants get %i requests per minute', async (plan, limit) => {
    const t = await register(app, `${plan} tier`);
    await setPlan(t, plan);
    const first = await me(t);
    expect(first.statusCode).toBe(200);
    expect(first.headers['ratelimit-limit']).toBe(String(limit));
    expect(first.headers['ratelimit-remaining']).toBe(String(limit - 1));
    expect(first.headers['ratelimit-policy']).toBe(`${limit};w=60`);
    const second = await me(t);
    expect(second.headers['ratelimit-remaining']).toBe(String(limit - 2));
  });

  it('a plan change applies to the next request', async () => {
    const t = await register(app, 'Upgrader');
    expect((await me(t)).headers['ratelimit-limit']).toBe('60');
    await setPlan(t, 'pro');
    expect((await me(t)).headers['ratelimit-limit']).toBe('600');
  });
});

describe('429 responses', () => {
  it('rejects the request over the limit with a 429, Retry-After, and the standard error body', async () => {
    const t = await register(app, 'Spammer');
    for (let i = 0; i < 60; i++) expect((await me(t)).statusCode).toBe(200);

    const res = await me(t);
    expect(res.statusCode).toBe(429);
    expect(res.json()).toEqual({
      error: {
        code: 'rate_limited',
        message: expect.stringContaining('60 requests per 60s on the free plan'),
        details: { plan: 'free', limit: 60, windowSeconds: 60, retryAfterSeconds: 60 },
      },
    });
    expect(res.headers['retry-after']).toBe('60');
    expect(res.headers['ratelimit-limit']).toBe('60');
    expect(res.headers['ratelimit-remaining']).toBe('0');
    expect(res.headers['ratelimit-reset']).toBe('60');
    expect(res.headers['ratelimit-policy']).toBe('60;w=60');
  });

  it('is a sliding window: capacity returns gradually, not all at once at a boundary', async () => {
    const t = await register(app, 'Slider');
    for (let i = 0; i < 40; i++) await me(t); // 40 requests at t=0
    store.now += 40_000;
    for (let i = 0; i < 20; i++) expect((await me(t)).statusCode).toBe(200); // 60 in the last 40s
    const blocked = await me(t);
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers['retry-after']).toBe('20'); // the oldest request leaves the window in 20s

    store.now += 21_000; // t=61s: the first 40 have aged out, the 20 from t=40s have not
    const ok = await me(t);
    expect(ok.statusCode).toBe(200);
    expect(ok.headers['ratelimit-remaining']).toBe('39');
  });

  it('rounds Retry-After up to whole seconds, never 0', async () => {
    const t = await register(app, 'Rounding');
    for (let i = 0; i < 60; i++) await me(t);
    store.now += 59_001; // the oldest request leaves the window in 999ms
    const blocked = await me(t);
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers['retry-after']).toBe('1');
    expect(blocked.headers['ratelimit-reset']).toBe('1');
  });

  it('keeps headers on error responses produced by routes', async () => {
    const t = await register(app, 'Errors');
    const bad = await app.inject({ method: 'GET', url: '/projects/not-a-uuid', headers: bearer(t) });
    expect(bad.statusCode).toBe(400);
    expect(bad.headers['ratelimit-limit']).toBe('60');
    const missing = await app.inject({ method: 'GET', url: '/nope', headers: bearer(t) });
    expect(missing.statusCode).toBe(404);
    expect(missing.headers['ratelimit-remaining']).toBeDefined();
  });
});

describe('isolation', () => {
  it('one tenant exhausting its budget does not affect another', async () => {
    const noisy = await register(app, 'Noisy');
    const quiet = await register(app, 'Quiet');
    for (let i = 0; i < 61; i++) await me(noisy);
    expect((await me(noisy)).statusCode).toBe(429);
    const res = await me(quiet);
    expect(res.statusCode).toBe(200);
    expect(res.headers['ratelimit-remaining']).toBe('59');
  });

  it('all members of a tenant share one budget', async () => {
    const owner = await register(app, 'Shared');
    const member = await addMember(app, owner, 'member');
    const used = (await me(owner)).headers['ratelimit-remaining'];
    const next = (await me(member)).headers['ratelimit-remaining'];
    expect(Number(next)).toBe(Number(used) - 1);

    for (let i = 0; i < 70; i++) await me(owner);
    expect((await me(member)).statusCode).toBe(429);
  });
});

describe('what is not limited', () => {
  it('leaves health checks and the Stripe webhook alone, even for a throttled tenant', async () => {
    const t = await register(app, 'Throttled');
    for (let i = 0; i < 61; i++) await me(t);
    expect((await me(t)).statusCode).toBe(429);

    const health = await app.inject({ method: 'GET', url: '/healthz', headers: bearer(t) });
    expect(health.statusCode).toBe(200);
    expect(health.headers['ratelimit-limit']).toBeUndefined();

    const hook = await app.inject({
      method: 'POST', url: '/webhooks/stripe', payload: '{}',
      headers: { ...bearer(t), 'content-type': 'application/json', 'stripe-signature': 't=1,v1=bad' },
    });
    expect(hook.statusCode).toBe(400); // signature failure, not 429
  });

  it('ignores requests without a valid token (they are answered by their own routes)', async () => {
    const t = await register(app, 'Bystander');
    for (let i = 0; i < 61; i++) await me(t);

    const anon = await app.inject({ method: 'GET', url: '/me' });
    expect(anon.statusCode).toBe(401);
    expect(anon.headers['ratelimit-limit']).toBeUndefined();
    const forged = await app.inject({ method: 'GET', url: '/me', headers: { authorization: 'Bearer not.a.jwt' } });
    expect(forged.statusCode).toBe(401);

    const login = await app.inject({ method: 'POST', url: '/auth/login', payload: { email: t.email, password: PASSWORD } });
    expect(login.statusCode).toBe(200);
    expect(login.headers['ratelimit-limit']).toBeUndefined();
  });
});

describe('when the limiter store fails', () => {
  it('fails open: requests succeed, without rate-limit headers', async () => {
    const t = await register(app, 'Resilient');
    store.failing = true;
    try {
      const res = await me(t);
      expect(res.statusCode).toBe(200);
      expect(res.headers['ratelimit-limit']).toBeUndefined();
    } finally {
      store.failing = false;
    }
    expect((await me(t)).headers['ratelimit-limit']).toBe('60');
  });
});

describe('enterprise plan', () => {
  it('lifts the project cap like pro does', async () => {
    const t = await register(app, 'Big Corp');
    await setPlan(t, 'enterprise');
    for (let i = 0; i < 5; i++) {
      expect((await app.inject({ method: 'POST', url: '/projects', headers: bearer(t), payload: { name: `p${i}` } })).statusCode).toBe(201);
    }
  });

  it('is not downgraded by Stripe subscription events', async () => {
    const t = await register(app, 'Negotiated');
    await setPlan(t, 'enterprise');
    const sub = (over: Record<string, unknown>) => stripeEvent('customer.subscription.updated',
      subscriptionObject(t.tenantId, { customer: `cus_${t.tenantId.slice(0, 8)}`, id: `sub_${t.tenantId}`, ...over }));

    expect((await signedWebhook(app, sub({ status: 'active' }))).json().result).toBe('processed');
    expect((await sql.system('SELECT plan FROM tenants WHERE id = $1', [t.tenantId])).rows[0].plan).toBe('enterprise');

    const later = stripeEvent('customer.subscription.deleted', subscriptionObject(t.tenantId, {
      customer: `cus_${t.tenantId.slice(0, 8)}`, id: `sub_${t.tenantId}`, status: 'canceled',
    }), Math.floor(Date.now() / 1000) + 60);
    expect((await signedWebhook(app, later)).json().result).toBe('processed');
    expect((await sql.system('SELECT plan FROM tenants WHERE id = $1', [t.tenantId])).rows[0].plan).toBe('enterprise');
  });

  it('cannot be self-assigned: the runtime role has no UPDATE on tenants.plan', async () => {
    const t = await register(app, 'Cheeky');
    await expect(sql.app(`UPDATE tenants SET plan = 'enterprise'`)).rejects.toThrow();
    await setPlan(t, 'enterprise'); // allowed for the owner role
  });
});

describe('TenantRateLimiter plan cache', () => {
  const makeLimiter = (loadPlan: (id: string) => Promise<string | null>, ttl: number, clock: { now: number }) =>
    new TenantRateLimiter({
      store: new FakeStore(), loadPlan, windowSeconds: 60, planCacheSeconds: ttl, now: () => clock.now,
    });

  it('reads the database once per TTL, not once per request', async () => {
    const clock = { now: 0 };
    let loads = 0;
    const limiter = makeLimiter(async () => { loads++; return 'pro'; }, 10, clock);
    for (let i = 0; i < 5; i++) expect((await limiter.check('t1')).plan).toBe('pro');
    expect(loads).toBe(1);
    clock.now += 10_001;
    await limiter.check('t1');
    expect(loads).toBe(2);
  });

  it('shares one query between concurrent first requests', async () => {
    let loads = 0;
    const limiter = makeLimiter(async () => { loads++; await new Promise((r) => setTimeout(r, 20)); return 'free'; }, 10, { now: 0 });
    await Promise.all(Array.from({ length: 20 }, () => limiter.check('t1')));
    expect(loads).toBe(1);
  });

  it('does not cache failures, and can be invalidated', async () => {
    const clock = { now: 0 };
    let plan = 'free';
    let failNext = true;
    const limiter = makeLimiter(async () => { if (failNext) throw new Error('db down'); return plan; }, 10, clock);
    await expect(limiter.check('t1')).rejects.toThrow('db down');
    failNext = false;
    expect((await limiter.check('t1')).plan).toBe('free');
    plan = 'enterprise';
    expect((await limiter.check('t1')).plan).toBe('free'); // still cached
    limiter.invalidatePlan('t1');
    expect((await limiter.check('t1')).plan).toBe('enterprise');
  });

  it('applies the strictest tier to unknown tenants or plan values', async () => {
    const limiter = makeLimiter(async (id) => (id === 'gone' ? null : 'platinum'), 0, { now: 0 });
    expect((await limiter.check('gone')).limit).toBe(60);
    expect((await limiter.check('weird')).plan).toBe('free');
  });
});
