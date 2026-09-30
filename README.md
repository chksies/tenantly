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

**Stack:** Node 22, TypeScript, Fastify 5, PostgreSQL 16, `pg`, `jose`, `zod`, Stripe SDK, Vitest.

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
| `GET /healthz` | public | |

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

Requires Node 22+ and Docker (or any Postgres 16).

```bash
git clone https://github.com/chksies/tenantly && cd tenantly
cp .env.example .env            # then set JWT_SECRET and Stripe keys
docker compose up -d db         # creates the DB and the two runtime roles
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

83 integration tests run against a real PostgreSQL, not mocks. The suite creates the roles, resets the schema and applies migrations itself. Highlights:

- **RLS tested directly in SQL, bypassing the API:** cross-tenant reads, writes and deletes, `WITH CHECK` violations, fail-closed behavior, no context leakage across pooled connections, blocked access to `password_hash` and internal tables.
- **Audit immutability** even for the superuser, and trigger-captured before/after state.
- **Auth attacks:** tampered, expired, wrong-key and `alg: none` JWTs; refresh-token replay; OAuth state replay/forgery and PKCE verifier/challenge matching.
- **RBAC:** the full permission matrix, escalation attempts, demotion/removal taking effect on an unexpired token, cross-tenant access by ID.
- **Billing:** bad/missing/tampered signatures, duplicate and *concurrent* redeliveries, out-of-order events, rollback-on-failure, and a concurrent-request race on the plan limit.

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
- **Not built yet:** email verification and password reset, MFA, per-tenant rate limits, background job for expired-row cleanup, OpenAPI docs, and a `pg_partman`-style retention policy for `audit_logs`.

## License

MIT
