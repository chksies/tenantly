import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { Redis } from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createRedis, RedisSlidingWindowStore, rateLimitKey } from '../src/ratelimit/index.js';
import { bearer, makeApp, register, shutdown } from './helpers.js';

/**
 * Runs the real Lua script against a real Redis (>= 5). Skipped unless TEST_REDIS_URL is set, e.g.
 *   TEST_REDIS_URL=redis://localhost:6379 npm test
 * CI always sets it. Every test uses its own random tenant key and cleans up after itself, so it is
 * safe to point at a Redis that holds other data.
 */
const url = process.env.TEST_REDIS_URL;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const quiet = () => undefined;

describe.skipIf(!url)('Redis sliding-window store', () => {
  let redis: Redis;
  let store: RedisSlidingWindowStore;
  const keys: string[] = [];
  const newKey = () => { const k = rateLimitKey(randomUUID()); keys.push(k); return k; };

  beforeAll(async () => {
    redis = createRedis({ url: url!, timeoutMs: 1_000, onError: quiet });
    await redis.connect();
    store = new RedisSlidingWindowStore(redis);
  });
  afterAll(async () => {
    if (keys.length) await redis.del(...keys);
    redis.disconnect();
  });

  it('admits up to the limit, then denies', async () => {
    const key = newKey();
    const results = [];
    for (let i = 0; i < 5; i++) results.push(await store.hit(key, 3, 5_000));
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false, false]);
    expect(results.map((r) => r.remaining)).toEqual([2, 1, 0, 0, 0]);
    expect(results.every((r) => r.limit === 3)).toBe(true);
  });

  it('reports how long until a slot frees up', async () => {
    const key = newKey();
    for (let i = 0; i < 2; i++) await store.hit(key, 2, 5_000);
    await sleep(300);
    const denied = await store.hit(key, 2, 5_000);
    expect(denied.allowed).toBe(false);
    expect(denied.resetMs).toBeGreaterThan(4_000);
    expect(denied.resetMs).toBeLessThanOrEqual(4_700);
  });

  it('slides: capacity comes back request by request as old ones age out', async () => {
    const key = newKey();
    const w = 800;
    expect((await store.hit(key, 3, w)).allowed).toBe(true); // t=0
    await sleep(400);
    expect((await store.hit(key, 3, w)).allowed).toBe(true); // t=400
    expect((await store.hit(key, 3, w)).allowed).toBe(true); // t=400
    expect((await store.hit(key, 3, w)).allowed).toBe(false);
    await sleep(500); // t=900: only the first request has aged out
    expect((await store.hit(key, 3, w)).allowed).toBe(true);
    expect((await store.hit(key, 3, w)).allowed).toBe(false);
    await sleep(w + 100); // everything has aged out
    expect((await store.hit(key, 3, w)).allowed).toBe(true);
  });

  it('does not record denied requests, so hammering cannot extend or inflate the penalty', async () => {
    const key = newKey();
    for (let i = 0; i < 100; i++) await store.hit(key, 5, 5_000);
    expect(await redis.zcard(key)).toBe(5);
  });

  it('is atomic across clients: concurrent requests from many "nodes" never exceed the limit', async () => {
    const other = createRedis({ url: url!, timeoutMs: 1_000, onError: quiet });
    await other.connect();
    try {
      const stores = [store, new RedisSlidingWindowStore(other)];
      const key = newKey();
      const results = await Promise.all(Array.from({ length: 200 }, (_, i) => stores[i % 2]!.hit(key, 25, 10_000)));
      expect(results.filter((r) => r.allowed)).toHaveLength(25);
      expect(await redis.zcard(key)).toBe(25); // same-millisecond requests were all counted separately
    } finally {
      other.disconnect();
    }
  });

  it('expires idle keys so inactive tenants cost no memory', async () => {
    const key = newKey();
    await store.hit(key, 5, 2_000);
    const ttl = await redis.pttl(key);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(2_000);
  });

  it('keeps tenants separate', async () => {
    const a = newKey();
    const b = newKey();
    for (let i = 0; i < 3; i++) await store.hit(a, 3, 5_000);
    expect((await store.hit(a, 3, 5_000)).allowed).toBe(false);
    expect((await store.hit(b, 3, 5_000)).allowed).toBe(true);
  });

  it('recovers when Redis loses its script cache (NOSCRIPT)', async () => {
    const key = newKey();
    await store.hit(key, 3, 5_000);
    await redis.script('FLUSH');
    expect((await store.hit(key, 3, 5_000)).remaining).toBe(1);
  });

  describe('through the API', () => {
    let app: FastifyInstance;
    beforeAll(async () => { app = await makeApp({ rateLimit: { redisUrl: url, planCacheSeconds: 0 } }); });
    afterAll(() => app.close()); // pools stay open: the file's last describe shuts them down

    it('enforces the free tier end to end', async () => {
      const t = await register(app, 'Redis Co');
      keys.push(rateLimitKey(t.tenantId));
      let last;
      for (let i = 0; i < 60; i++) {
        last = await app.inject({ method: 'GET', url: '/me', headers: bearer(t) });
        expect(last.statusCode).toBe(200);
      }
      expect(last!.headers['ratelimit-remaining']).toBe('0');
      const res = await app.inject({ method: 'GET', url: '/me', headers: bearer(t) });
      expect(res.statusCode).toBe(429);
      expect(res.json().error.code).toBe('rate_limited');
      expect(Number(res.headers['retry-after'])).toBeGreaterThanOrEqual(1);
      expect(res.headers['ratelimit-policy']).toBe('60;w=60');
    });
  });
});

describe('with Redis unreachable', () => {
  let app: FastifyInstance;
  beforeAll(async () => {
    // Nothing listens on port 1. The app must still boot and serve traffic.
    app = await makeApp({ rateLimit: { redisUrl: 'redis://127.0.0.1:1', planCacheSeconds: 0 } });
  });
  afterAll(() => shutdown(app));

  it('fails open quickly instead of erroring or hanging', async () => {
    const t = await register(app, 'No Redis');
    const started = Date.now();
    const res = await app.inject({ method: 'GET', url: '/me', headers: bearer(t) });
    expect(res.statusCode).toBe(200);
    expect(res.headers['ratelimit-limit']).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});
