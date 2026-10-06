import type { FastifyInstance, FastifyReply } from 'fastify';
import { verifyAccessToken } from '../security/tokens.js';
import type { TenantLimitResult, TenantRateLimiter } from './limiter.js';

/** Never limited: load balancers and Stripe must be able to reach these however busy a tenant is. */
const EXEMPT_PATHS = new Set(['/healthz', '/webhooks/stripe']);

const seconds = (ms: number) => Math.max(1, Math.ceil(ms / 1000));

/**
 * Standard rate-limit headers, sent on every limited response (not just 429s) so well-behaved
 * clients can pace themselves instead of discovering the limit by hitting it.
 *
 * RateLimit-* follow the IETF httpapi "RateLimit header fields" draft; the older X-RateLimit-* names
 * it supersedes are intentionally not duplicated. RateLimit-Reset is a delta in seconds, not an
 * epoch, so it is immune to client clock skew. For a sliding window it means "seconds until the
 * oldest counted request ages out and one slot frees up".
 */
function setRateLimitHeaders(reply: FastifyReply, r: TenantLimitResult) {
  reply.header('RateLimit-Limit', r.limit);
  reply.header('RateLimit-Remaining', r.remaining);
  reply.header('RateLimit-Reset', seconds(r.resetMs));
  reply.header('RateLimit-Policy', `${r.limit};w=${r.windowSeconds}`);
}

/**
 * Installs the per-tenant limiter as a global onRequest hook. Call it before registering routes
 * (hooks only apply to routes registered after them).
 *
 * Placement is deliberate. It runs after the JWT signature check, which is stateless (no I/O), so
 * the tenant is known and trustworthy, but before any route handler, so a throttled tenant costs us
 * one Redis round-trip and never a Postgres connection. Requests without a valid bearer token pass
 * through untouched: they cannot be attributed to a tenant, and the routes that serve them
 * (login, register, ...) are already covered by the per-IP limiter, while protected routes reject
 * them with a 401 on their own.
 *
 * It fails OPEN. If Redis is down or slow the request is admitted and a warning is logged:
 * rate limiting protects the service, so it must not be able to take the service down.
 */
export function installTenantRateLimit(app: FastifyInstance, limiter: TenantRateLimiter) {
  app.addHook('onRequest', async (req, reply) => {
    if (EXEMPT_PATHS.has(req.url.split('?')[0]!)) return;

    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return;

    let auth;
    try {
      auth = await verifyAccessToken(header.slice(7));
    } catch {
      return; // the route's own authentication will answer 401
    }
    req.auth = auth; // verified here, so authenticate() doesn't repeat the signature check

    let result: TenantLimitResult;
    try {
      result = await limiter.check(auth.tenantId);
    } catch (err) {
      req.log.warn({ err, tenantId: auth.tenantId }, 'rate limiter unavailable, failing open');
      return;
    }

    setRateLimitHeaders(reply, result);
    if (result.allowed) return;

    const retryAfter = seconds(result.resetMs);
    req.log.info({ tenantId: auth.tenantId, plan: result.plan, limit: result.limit }, 'tenant rate limited');
    reply.header('Retry-After', retryAfter);
    return reply.status(429).send({
      error: {
        code: 'rate_limited',
        message: `Rate limit exceeded for this workspace (${result.limit} requests per ${result.windowSeconds}s on the ${result.plan} plan). Retry in ${retryAfter}s.`,
        details: { plan: result.plan, limit: result.limit, windowSeconds: result.windowSeconds, retryAfterSeconds: retryAfter },
      },
    });
  });
}
