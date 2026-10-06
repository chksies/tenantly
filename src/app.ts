import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import type Stripe from 'stripe';
import { AppError } from './errors.js';
import { config } from './config.js';
import { appPool, systemPool, withTenant } from './db.js';
import { auditRoutes } from './modules/audit/routes.js';
import { defaultOAuthProviders, type OAuthProvider } from './modules/auth/oauth.js';
import { authRoutes } from './modules/auth/routes.js';
import { billingRoutes, createStripe } from './modules/billing/routes.js';
import { projectRoutes } from './modules/projects/routes.js';
import { tenantRoutes } from './modules/tenants/routes.js';
import {
  createRedis, installTenantRateLimit, RedisSlidingWindowStore, TenantRateLimiter, type RateLimitStore,
} from './ratelimit/index.js';

export interface AppOptions {
  stripe?: Stripe;
  oauthProviders?: Record<string, OAuthProvider>;
  /** Per-tenant rate limiting. With neither `store` nor a Redis URL (here or REDIS_URL) it is off. */
  rateLimit?: {
    store?: RateLimitStore;
    redisUrl?: string;
    windowSeconds?: number;
    planCacheSeconds?: number;
  };
}

/** Resolves the limiter's store: an injected one, else Redis if configured, else none. */
async function rateLimitStore(app: FastifyInstance, opts: AppOptions['rateLimit'] = {}): Promise<RateLimitStore | null> {
  if (opts.store) return opts.store;
  const url = opts.redisUrl ?? config.REDIS_URL;
  if (!url) return null;

  let lastLogged = 0;
  const redis = createRedis({
    url,
    timeoutMs: config.RATE_LIMIT_REDIS_TIMEOUT_MS,
    onError: (err) => { // reconnect attempts can error every couple of seconds: log at most every 30s
      if (Date.now() - lastLogged < 30_000) return;
      lastLogged = Date.now();
      app.log.warn({ err }, 'redis error (rate limiting fails open while it is unreachable)');
    },
  });
  // Give Redis a moment to come up so the first requests are limited, but never block startup on it:
  // while disconnected the limiter fails open and ioredis keeps reconnecting in the background.
  // (connect() alone can stay pending forever while retrying, hence the timer.)
  let timer: NodeJS.Timeout | undefined;
  await Promise.race([
    redis.connect().catch(() => undefined),
    new Promise((resolve) => { timer = setTimeout(resolve, 1_000); }),
  ]);
  clearTimeout(timer);
  app.addHook('onClose', async () => { redis.disconnect(); });
  return new RedisSlidingWindowStore(redis);
}

export async function buildApp(opts: AppOptions = {}) {
  const app = Fastify({
    logger: config.NODE_ENV === 'test' ? false : { level: 'info', redact: ['req.headers.authorization'] },
    trustProxy: config.TRUST_PROXY,
    bodyLimit: 1024 * 1024,
  });

  // Error handling must be installed BEFORE any plugin is registered: Fastify child scopes only
  // inherit handlers that already exist when they load (otherwise clients would get the default
  // handler, which can echo internal error messages on 500s).
  app.setNotFoundHandler((_req, reply) =>
    reply.status(404).send({ error: { code: 'not_found', message: 'Route not found' } }));

  app.setErrorHandler((err: Error & { statusCode?: number; code?: string }, req, reply) => {
    if (err instanceof AppError) {
      return reply.status(err.status).send({ error: { code: err.code, message: err.message, details: err.details } });
    }
    if (err.statusCode && err.statusCode < 500) {
      // Framework-level client errors: malformed JSON, payload too large, rate limited...
      return reply.status(err.statusCode).send({ error: { code: err.code ?? 'bad_request', message: err.message } });
    }
    req.log.error({ err }, 'unhandled error');
    return reply.status(500).send({ error: { code: 'internal_error', message: 'Internal server error' } });
  });

  app.decorateRequest('auth', null);
  await app.register(helmet);
  await app.register(rateLimit, { global: false });

  // Per-tenant, plan-tiered limiting for authenticated traffic. (The plugin above is the per-IP
  // limiter for unauthenticated routes such as login.) Must come before any route is registered.
  const store = await rateLimitStore(app, opts.rateLimit);
  if (store) {
    installTenantRateLimit(app, new TenantRateLimiter({
      store,
      windowSeconds: opts.rateLimit?.windowSeconds ?? config.RATE_LIMIT_WINDOW_SECONDS,
      planCacheSeconds: opts.rateLimit?.planCacheSeconds ?? config.RATE_LIMIT_PLAN_CACHE_SECONDS,
      loadPlan: (tenantId) => withTenant({ tenantId }, async (db) =>
        (await db.query('SELECT plan FROM tenants')).rows[0]?.plan ?? null),
    }));
  } else {
    app.log.warn('REDIS_URL is not set: per-tenant rate limiting is disabled');
  }

  app.get('/healthz', async () => {
    await Promise.all([appPool.query('SELECT 1'), systemPool.query('SELECT 1')]);
    return { status: 'ok' };
  });

  await app.register(authRoutes, { oauthProviders: opts.oauthProviders ?? defaultOAuthProviders() });
  await app.register(tenantRoutes);
  await app.register(projectRoutes);
  await app.register(auditRoutes);
  await app.register(billingRoutes, { stripe: opts.stripe ?? createStripe() });

  return app;
}
