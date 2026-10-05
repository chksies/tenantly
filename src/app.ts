import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';
import type Stripe from 'stripe';
import { AppError } from './errors.js';
import { config } from './config.js';
import { appPool, systemPool } from './db.js';
import { auditRoutes } from './modules/audit/routes.js';
import { defaultOAuthProviders, type OAuthProvider } from './modules/auth/oauth.js';
import { authRoutes } from './modules/auth/routes.js';
import { billingRoutes, createStripe } from './modules/billing/routes.js';
import { projectRoutes } from './modules/projects/routes.js';
import { tenantRoutes } from './modules/tenants/routes.js';

export interface AppOptions {
  stripe?: Stripe;
  oauthProviders?: Record<string, OAuthProvider>;
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
   // edit the tentaly database
  app.decorateRequest('auth', null);
  await app.register(helmet);
  await app.register(rateLimit, { global: false });

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
