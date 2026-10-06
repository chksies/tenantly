# Tenantly

A multi-tenant SaaS backend built from scratch in TypeScript. Tenant isolation is enforced **by PostgreSQL itself** (row-level security), not by remembering to add `WHERE tenant_id = ...` to every query.

![CI](https://github.com/chksies/tenantly/actions/workflows/ci.yml/badge.svg)

| Concern | What's implemented |
|---|---|
| **Tenant isolation** | Postgres RLS on every tenant-owned table, `FORCE`d, fail-closed, with a non-privileged runtime role |
| **Authentication** | Email/password (scrypt), short-lived JWT access tokens, rotating refresh tokens with reuse detection, OAuth2 authorization-code + PKCE (Google) |
| **Authorization** | Role-based access control (owner / admin / member / viewer), re-checked against the database on every request, with privilege-escalation guards |
| **Billing** | Stripe Checkout + customer portal, signature-verified webhooks, idempotent and out-of-order safe, plan limits enforced server-side |
| **Audit logging** | Append-only log written by DB triggers (can't be forgotten by app code) plus application events; immutable even to the table owner |
| **Rate limiting** | Per-tenant, tiered by plan (free / pro / enterprise), Redis sliding-window log in an atomic Lua script, `429` + `Retry-After` + `RateLimit-*` headers, fails open |

**Stack:** Node 22, TypeScript, Fastify 5, PostgreSQL 16, Redis, `pg`, `ioredis`, `jose`, `zod`, Stripe SDK, Vitest.

---

## How tenant isolation works

Two database roles, on purpose:

| Role | Attributes | Used for |
|---|---|---|
| `saas_app` | `NOBYPASSRLS`, column-level grants | **Every** tenant-scoped request |
| `saas_system` | `BYPASSRLS` | Only code that legitimately spans tenants: login, token refresh, invitation acceptance, Stripe webhooks |

Each request runs in one transaction that first sets the tenant context, scoped to that transaction only (`is_local = true`) so a pooled connection can never leak it to the next request:

```ts
await client.query('BEGIN');
await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
// ... queries run here, and Postgres filters every table by that tenant ...
await client.query('COMMIT');
```

The policies read that setting:

```sql
CREATE POLICY tenant_isolation ON projects
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
```

Consequences worth noting:

- **Fail closed.** If the context is missing, `app_tenant_id()` is `NULL`, the predicate is never true, and queries return zero rows instead of everyone's data.
- **Handlers don't filter by tenant at all** (see `src/modules/projects/routes.ts`). A forgotten `WHERE` can't leak data because that isn't what enforces isolation.
- **`WITH CHECK`** stops a tenant inserting or moving rows into someone else's tenant.
- **Least privilege.** `saas_app` has no access to `refresh_tokens`, `oauth_*`, or `stripe_events`, cannot read `users.password_hash`, and cannot change its own plan or write subscriptions.
- **Cross-tenant IDs return 404, not 403**, so IDs can't be probed for existence.

## Authentication & sessions

- **Passwords:** scrypt (memory-hard, built into Node, no native build step). Login always performs a hash verification, even for unknown emails, so response time doesn't reveal which accounts exist.
- **Access tokens:** HS256 JWTs, 15 min by default, with `iss`/`aud` checks and an explicit algorithm allow-list (so `alg: none` is rejected). Each token is scoped to exactly one tenant.
- **Refresh tokens:** opaque, stored only as SHA-256 hashes, rotated on every use. Each belongs to a *family*; replaying an already-rotated token revokes the whole family and writes an `auth.refresh_reuse_detected` audit event.
- **Roles aren't trusted from the JWT.** `requirePermission()` re-reads the caller's role from `memberships` inside the tenant's RLS scope on every request, so a removed or demoted member loses access immediately instead of when their token expires.
- **OAuth2:** authorization-code flow with PKCE (S256). `state` and the code verifier are stored server-side, single-use, and expire after 10 minutes. Google ID tokens are verified against Google's JWKS (signature, issuer, audience, expiry). Sign-in requires a provider-verified email.
- **Multi-workspace:** a user can belong to many tenants; `POST /auth/switch-tenant` exchanges the session for one scoped to another workspace they belong to.

## Billing

Webhook handling (`src/modules/billing/webhook.ts`) is built for how Stripe really behaves:

- **Signature verification** on the raw request body (the webhook route has its own encapsulated body parser).
- **Idempotent:** the event id is inserted into `stripe_events` in the *same transaction* as the side effects. Duplicate or concurrent redeliveries are acknowledged but processed once. If handling throws, the ledger row rolls back, the endpoint returns 500, and Stripe's retry starts clean.
- **Out-of-order safe:** each subscription row stores `last_event_at`; older events can't overwrite newer state. A stale cancellation for an *old* subscription can't downgrade a newer active one.
- **Entitlements from state, not events:** `active`, `trialing` and `past_due` (grace period) keep Pro; anything else drops to Free.
- Plan limits (Free = 3 projects) are enforced in the API under a row lock on the tenant, so concurrent requests can't exceed them.

## Rate limiting

Every authenticated request counts against its **tenant's** budget, and the size of the budget depends on the tenant's plan:

| Plan | Requests per minute | How a tenant gets it |
|---|---:|---|
| `free` | 60 | default |
| `pro` | 600 | Stripe subscription |
| `enterprise` | 6,000 | set by hand (below) |

Limits live in `src/plans.ts` next to the project caps. The budget is per tenant, not per user or token, so adding seats or minting tokens doesn't buy more capacity. A noisy tenant is throttled; its neighbours never notice.

```
$ curl -i localhost:3000/projects -H "authorization: Bearer $TOKEN"
HTTP/1.1 200 OK
RateLimit-Limit: 60
RateLimit-Remaining: 59
RateLimit-Reset: 60
RateLimit-Policy: 60;w=60

... 60 requests later ...

HTTP/1.1 429 Too Many Requests
Retry-After: 23
RateLimit-Limit: 60
RateLimit-Remaining: 0
RateLimit-Reset: 23
RateLimit-Policy: 60;w=60

{"error":{"code":"rate_limited","message":"Rate limit exceeded for this workspace (60 requests per 60s on the free plan). Retry in 23s.",
 "details":{"plan":"free","limit":60,"windowSeconds":60,"retryAfterSeconds":23}}}
```

The headers follow the IETF `RateLimit` header-fields draft and are sent on every limited response, not only 429s, so clients can pace themselves. `RateLimit-Reset` and `Retry-After` are *delta seconds* (rounded up, never 0), so client clock skew can't break them. The 429 body uses the same `{ error: { code, message, details } }` shape as every other error.

**Assigning enterprise.** It isn't sold through Checkout. Run this as the table owner (the runtime role can't change plans) and it takes effect within `RATE_LIMIT_PLAN_CACHE_SECONDS`. Stripe subscription events never overwrite it:

```sql
UPDATE tenants SET plan = 'enterprise' WHERE slug = 'acme';
```

### How it works

`src/ratelimit/` has three small pieces: `store.ts` (the Redis algorithm), `limiter.ts` (tenant → plan → limit), and `hook.ts` (the Fastify hook and the HTTP semantics).

**Algorithm: sliding-window log in Lua.** Each allowed request is a member of a Redis sorted set scored by its timestamp. One script trims entries older than the window, counts what's left, and adds the new request only if there is room:

```lua
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
if redis.call('ZCARD', key) < limit then redis.call('ZADD', key, now, member) ... end
```

- **Exact, with no boundary burst.** A fixed-window counter lets a client send `limit` requests at 0:59 and `limit` more at 1:01. A sliding window can't: at most `limit` requests in *any* trailing 60 seconds.
- **Atomic.** Check-then-insert as separate commands would let two API servers both see `limit - 1` and both admit a request. Redis runs a script to completion before serving anyone else, so it can't happen (test: 200 concurrent hits from two clients, limit 25, exactly 25 admitted).
- **Redis's clock, not the app server's.** The script reads `TIME`, so skewed API nodes can't disagree about where the window starts. This needs Redis 5+.
- **Denied requests aren't recorded.** Memory per tenant is bounded by its limit, and a client hammering while throttled doesn't extend its own penalty: it recovers when its oldest allowed request ages out.
- **Idle tenants cost nothing.** Each key has a `PEXPIRE` of one window.
- **Cluster-safe keys.** `rl:{tenantId}:requests`: the braces are a hash tag, so everything for one tenant stays in one slot.

**Where it sits in the request.** A global `onRequest` hook verifies the JWT signature (stateless, no I/O), then asks Redis. A throttled tenant therefore costs one Redis round-trip and never a Postgres connection, which matters because the per-request role check in `requirePermission` is a database query. The verified token is reused by `authenticate()`, so the signature isn't checked twice. Requests with no valid token pass through: they can't be attributed to a tenant, protected routes reject them with a 401 anyway, and login/register keep their separate per-IP limiter. `/healthz` and the Stripe webhook are exempt, so a load balancer or Stripe is never throttled by tenant traffic.

**Finding the plan without a query per request.** The limiter needs the tenant's plan, but a rate limiter that costs a database round-trip per request adds the load it exists to shed. Plans are cached in-process for `RATE_LIMIT_PLAN_CACHE_SECONDS` (default 10), concurrent misses share one query, failures are never cached, and the cache is size-capped. The trade-off is that a plan change reaches each node within that window, which is fine for a quota.

**Failure mode: fail open.** If Redis is down, slow, or errors, the request is admitted and a warning is logged. Rate limiting protects the service, so it mustn't be able to take the service down. To make that hold in practice the Redis client has no offline queue, a 100 ms command timeout (`RATE_LIMIT_REDIS_TIMEOUT_MS`), and background reconnection with backoff, and the app starts (limiting off) even if Redis isn't up yet. The cost is that during a Redis outage there is no limit, so alert on those warnings. In production `REDIS_URL` is required, so a missing config is a startup error rather than a silently unprotected API. In development, leaving it unset turns the limiter off.

### Trade-offs I considered

- **Sliding-window log vs. sliding-window counter.** The log is exact but stores one entry per allowed request (bounded by the plan limit: at most 6,000 small entries for an enterprise tenant). The counter approximates by weighting the previous fixed window and stores two integers per tenant, so it scales to far larger limits. At these limits the exact answer is cheap, so I chose it; at 100k requests per window per tenant I'd switch.
- **Token bucket** allows controlled bursts and is the usual choice when you want that. Here the plans are quotas ("N per minute"), so a window matches what customers are told and what the headers report.
- **Fail open vs. fail closed.** Failing closed turns a cache outage into a full API outage. For abuse protection that's the wrong trade; for something like login-attempt throttling, where the limit is a security control, I'd consider the opposite.
- **Not covered yet:** per-endpoint costs (e.g. a stricter budget for expensive routes, which the hash-tagged key layout already allows), burst limits on top of the minute quota, and plan-cache invalidation across nodes (currently TTL-only).

## Audit logging

- Row changes on `projects` and `memberships` are captured by **database triggers** (actor, before/after JSON, IP), so they're logged even if application code forgets.
- Auth, invitation, billing and tenant events are written by the application through the same table.
- The table is **append-only**: `saas_app` has only `SELECT, INSERT`, and a trigger raises on `UPDATE`/`DELETE` for *every* role, including the superuser.
- `GET /audit-logs` is tenant-scoped by RLS, keyset-paginated, and filterable by action prefix.

## API overview

| Method & path | Permission | Notes |
|---|---|---|
| `POST /auth/register` | public | Creates user + workspace (owner) |
| `POST /auth/login` | public | Optional `tenantId` |
| `POST /auth/refresh` · `POST /auth/logout` | public | Rotation / family revocation |
| `POST /auth/switch-tenant` | authenticated | New tokens for another workspace |
| `GET /auth/oauth/:provider/start` · `.../callback` | public | OAuth2 + PKCE |
| `GET /me` | authenticated | User + workspaces |
| `GET/PATCH /tenants/current` | `tenant:read` / `tenant:update` | |
| `GET /tenants/current/members` | `members:read` | |
| `PATCH/DELETE /tenants/current/members/:userId` | `members:manage` | Escalation guards, last-owner protection |
| `POST/GET/DELETE /tenants/current/invitations` | `members:manage` | 7-day single-use tokens |
| `POST /invitations/accept` | public / authenticated | New or existing account |
| `GET/POST/PATCH/DELETE /projects` | `projects:*` | Example tenant-owned resource, plan-limited |
| `GET /billing` | `billing:read` | |
| `POST /billing/checkout` · `POST /billing/portal` | `billing:manage` | Owner only |
| `POST /webhooks/stripe` | Stripe signature | |
| `GET /audit-logs` | `audit:read` | |
| `GET /healthz` | public | Not rate limited |

All authenticated routes are subject to the per-tenant rate limit (see above).

**Permission matrix**

| | viewer | member | admin | owner |
|---|:-:|:-:|:-:|:-:|
| Read tenant, projects, members | ✅ | ✅ | ✅ | ✅ |
| Create / edit projects | | ✅ | ✅ | ✅ |
| Delete projects, manage members, edit tenant | | | ✅ | ✅ |
| Read billing and audit log | | | ✅ | ✅ |
| Manage billing | | | | ✅ |

Admins can only manage members and viewers. Only owners can create admins or owners, and nobody can change their own role.

## Running it

Requires Node 22+ and Docker (or any Postgres 16, plus Redis 5+ for rate limiting).

```bash
git clone https://github.com/chksies/tenantly && cd tenantly
cp .env.example .env            # then set JWT_SECRET and Stripe keys
docker compose up -d db redis   # creates the DB and the two runtime roles, and starts Redis
npm ci
npm run migrate
npm run dev
```

```bash
# register (creates a workspace and returns tokens)
curl -s localhost:3000/auth/register -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"a-long-password","name":"Me","workspaceName":"Acme"}'

# use the access token
curl -s localhost:3000/projects -H "authorization: Bearer $TOKEN"
```

**Stripe locally:** `stripe listen --forward-to localhost:3000/webhooks/stripe`, then put the printed `whsec_...` in `STRIPE_WEBHOOK_SECRET`.
**Google sign-in:** set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` and register `http://localhost:3000/auth/oauth/google/callback` as the redirect URI.

## Testing

```bash
npm test          # needs Postgres; see TEST_DATABASE_URL in test/env.ts
```

113 tests (104 without Redis; 9 need `TEST_REDIS_URL`) run against a real PostgreSQL, not mocks. The suite creates the roles, resets the schema and applies migrations itself. Highlights:

- **RLS tested directly in SQL, bypassing the API:** cross-tenant reads, writes and deletes, `WITH CHECK` violations, fail-closed behavior, no context leakage across pooled connections, blocked access to `password_hash` and internal tables.
- **Audit immutability** even for the superuser, and trigger-captured before/after state.
- **Auth attacks:** tampered, expired, wrong-key and `alg: none` JWTs; refresh-token replay; OAuth state replay/forgery and PKCE verifier/challenge matching.
- **RBAC:** the full permission matrix, escalation attempts, demotion/removal taking effect on an unexpired token, cross-tenant access by ID.
- **Billing:** bad/missing/tampered signatures, duplicate and *concurrent* redeliveries, out-of-order events, rollback-on-failure, and a concurrent-request race on the plan limit.
- **Rate limiting:** limits and headers per plan, the exact 429 response, sliding-window behaviour, tenant isolation, shared budget across members, exemptions, fail-open, enterprise not downgraded by Stripe, and the plan cache. The Lua script runs against a **real Redis** (`TEST_REDIS_URL=redis://localhost:6379 npm test`; CI always sets it, otherwise those tests are skipped): exact limit under 200 concurrent requests from two clients, window sliding, denied requests not recorded, key expiry, recovery after `SCRIPT FLUSH`, and an unreachable Redis failing open.

I verified the tests actually bite: removing the RLS policy on `projects` fails 6 tests, and removing the tenant row lock fails the plan-limit race test.

**What isn't covered by a live service:** Stripe Checkout/portal are tested against a stubbed Stripe client, and the Google flow against a fake OIDC provider. Webhook signatures use Stripe's real verification code. Try both against real test-mode credentials before relying on them.

## Project structure

```
migrations/            SQL: schema, RLS policies, audit triggers, grants
db/init/01-roles.sql   The two runtime roles (saas_app, saas_system)
src/
  db.ts                Pools + withTenant() / withSystem() transaction helpers
  auth.ts              authenticate(), requirePermission(), tenantTx()
  rbac.ts              Roles, permissions, escalation rules
  security/            scrypt password hashing, JWT + opaque token helpers
  ratelimit/           per-tenant limiter: Redis Lua store, plan-aware limiter, Fastify hook
  modules/
    auth/              register, login, refresh, OAuth2 + PKCE
    tenants/           tenant, members, invitations
    projects/          example tenant-owned resource + plan limits
    billing/           checkout, portal, webhook processor
    audit/             audit log API
test/                  Integration tests (Vitest + real Postgres)
```

## Design trade-offs and what I'd do next

- **Two pools, not one.** Cross-tenant flows need `BYPASSRLS`; keeping them on a separate credential with a tiny surface (`withSystem`) means a bug in a normal handler can't reach across tenants.
- **Role re-check costs one indexed query per request.** I chose immediate revocation over stateless speed; a short-TTL cache would be the next optimization.
- **Invitation emails are stubbed** (`src/mailer.ts`). The raw token is only echoed in the API response outside production, so it can't be intercepted by the inviter.
- **Not built yet:** email verification and password reset, MFA, background job for expired-row cleanup, OpenAPI docs, and a `pg_partman`-style retention policy for `audit_logs`.

## License

MIT
