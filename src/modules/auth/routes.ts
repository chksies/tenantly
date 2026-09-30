import { createHash, randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../../audit.js';
import { authenticate, parse } from '../../auth.js';
import { config } from '../../config.js';
import { withSystem } from '../../db.js';
import { AppError } from '../../errors.js';
import { hashPassword, verifyPassword } from '../../security/password.js';
import { hashToken } from '../../security/tokens.js';
import type { OAuthProvider } from './oauth.js';
import { createWorkspace, issueTokens, listWorkspaces } from './service.js';

const email = z.string().trim().toLowerCase().email().max(254);
const password = z.string().min(10, 'Password must be at least 10 characters').max(200);

const registerBody = z.object({
  email, password,
  name: z.string().trim().min(1).max(100),
  workspaceName: z.string().trim().min(1).max(100).optional(),
});
const loginBody = z.object({ email, password: z.string().max(200), tenantId: z.uuid().optional() });
const refreshBody = z.object({ refreshToken: z.string().min(20).max(200) });
const switchBody = z.object({ tenantId: z.uuid() });

export async function authRoutes(app: FastifyInstance, opts: { oauthProviders: Record<string, OAuthProvider> }) {
  const limited = { config: { rateLimit: { max: config.NODE_ENV === 'test' ? 10_000 : 10, timeWindow: '1 minute' } } };

  app.post('/auth/register', limited, async (req, reply) => {
    const body = parse(registerBody, req.body);
    const passwordHash = await hashPassword(body.password);
    const result = await withSystem(async (db) => {
      const exists = await db.query('SELECT 1 FROM users WHERE lower(email) = lower($1)', [body.email]);
      if (exists.rowCount) throw new AppError(409, 'email_taken', 'An account with this email already exists');
      const { rows } = await db.query(
        'INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id, email, name',
        [body.email, body.name, passwordHash]);
      const user = rows[0];
      const tenant = await createWorkspace(db, user.id, body.workspaceName ?? `${body.name}'s workspace`);
      await audit(db, { tenantId: tenant.id, actorId: user.id, action: 'tenant.created', entityType: 'tenants', entityId: tenant.id });
      const tokens = await issueTokens(db, { userId: user.id, tenantId: tenant.id, role: 'owner' });
      return { user, tenant: { ...tenant, role: 'owner' }, ...tokens };
    }, { ip: req.ip });
    return reply.status(201).send(result);
  });

  app.post('/auth/login', limited, async (req) => {
    const body = parse(loginBody, req.body);
    const user = await withSystem(async (db) =>
      (await db.query('SELECT id, email, name, password_hash FROM users WHERE lower(email) = lower($1)', [body.email])).rows[0]);
    // Always run a hash verification (against a dummy hash if the user is unknown) to keep timing uniform.
    const ok = await verifyPassword(body.password, user?.password_hash ?? null);
    if (!user || !ok) throw new AppError(401, 'invalid_credentials', 'Invalid email or password');

    return withSystem(async (db) => {
      const workspaces = await listWorkspaces(db, user.id);
      const chosen = body.tenantId ? workspaces.find((w) => w.id === body.tenantId) : workspaces[0];
      if (!chosen) {
        throw new AppError(403, 'no_workspace', body.tenantId ? 'You are not a member of that workspace' : 'You do not belong to any workspace');
      }
      const tokens = await issueTokens(db, { userId: user.id, tenantId: chosen.id, role: chosen.role });
      await audit(db, { tenantId: chosen.id, actorId: user.id, action: 'auth.login', entityType: 'users', entityId: user.id });
      return { user: { id: user.id, email: user.email, name: user.name }, tenant: chosen, workspaces, ...tokens };
    }, { ip: req.ip, userId: user.id });
  });

  app.post('/auth/refresh', limited, async (req) => {
    const { refreshToken } = parse(refreshBody, req.body);
    const outcome = await withSystem(async (db) => {
      const { rows } = await db.query(
        `SELECT id, user_id, tenant_id, family_id, revoked_at, expires_at < now() AS expired
           FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, [hashToken(refreshToken)]);
      const row = rows[0];
      if (!row) return { kind: 'invalid' as const };
      if (row.revoked_at) {
        // A rotated-out token is being replayed: assume theft and kill the whole rotation family.
        const killed = await db.query(
          'UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL RETURNING id', [row.family_id]);
        // If nothing was live the session was already dead (logout, or an earlier reuse alert):
        // treat as a plain invalid token instead of raising a duplicate theft alert.
        if (killed.rowCount === 0) return { kind: 'invalid' as const };
        await audit(db, { tenantId: row.tenant_id, actorId: row.user_id, action: 'auth.refresh_reuse_detected', metadata: { familyId: row.family_id } });
        return { kind: 'reuse' as const };
      }
      if (row.expired) return { kind: 'invalid' as const };
      const m = (await db.query('SELECT role FROM memberships WHERE tenant_id = $1 AND user_id = $2', [row.tenant_id, row.user_id])).rows[0];
      if (!m) {
        await db.query('UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL', [row.family_id]);
        return { kind: 'invalid' as const };
      }
      await db.query('UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1', [row.id]);
      const tokens = await issueTokens(db, { userId: row.user_id, tenantId: row.tenant_id, role: m.role, familyId: row.family_id });
      return { kind: 'ok' as const, tokens };
    }, { ip: req.ip });
    // Throw only after the transaction has committed, so the family revocation on reuse persists.
    if (outcome.kind === 'reuse') throw new AppError(401, 'refresh_token_reused', 'Refresh token was already used; session revoked');
    if (outcome.kind === 'invalid') throw new AppError(401, 'invalid_refresh_token', 'Invalid or expired refresh token');
    return outcome.tokens;
  });

  app.post('/auth/logout', async (req, reply) => {
    const { refreshToken } = parse(refreshBody, req.body);
    await withSystem(async (db) => {
      await db.query(
        `UPDATE refresh_tokens SET revoked_at = now()
          WHERE revoked_at IS NULL AND family_id IN (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)`,
        [hashToken(refreshToken)]);
    });
    return reply.status(204).send();
  });

  /** Exchange the current session for one scoped to another workspace the user belongs to. */
  app.post('/auth/switch-tenant', async (req) => {
    const auth = await authenticate(req);
    const { tenantId } = parse(switchBody, req.body);
    return withSystem(async (db) => {
      const m = (await db.query('SELECT role FROM memberships WHERE tenant_id = $1 AND user_id = $2', [tenantId, auth.userId])).rows[0];
      if (!m) throw new AppError(403, 'forbidden', 'You are not a member of that workspace');
      await audit(db, { tenantId, actorId: auth.userId, action: 'auth.switch_tenant' });
      return issueTokens(db, { userId: auth.userId, tenantId, role: m.role });
    }, { ip: req.ip, userId: auth.userId });
  });

  app.get('/me', async (req) => {
    const auth = await authenticate(req);
    return withSystem(async (db) => {
      const user = (await db.query('SELECT id, email, name, email_verified FROM users WHERE id = $1', [auth.userId])).rows[0];
      if (!user) throw new AppError(401, 'unauthorized', 'Account no longer exists');
      return { user, currentTenantId: auth.tenantId, workspaces: await listWorkspaces(db, auth.userId) };
    });
  });

  // ------------------------------------------------------------------ OAuth2 (auth code + PKCE)
  const redirectUri = (provider: string) => `${config.APP_URL}/auth/oauth/${provider}/callback`;
  const getProvider = (name: string) => {
    const p = opts.oauthProviders[name];
    if (!p) throw new AppError(404, 'unknown_provider', `OAuth provider "${name}" is not configured`);
    return p;
  };

  app.get<{ Params: { provider: string } }>('/auth/oauth/:provider/start', limited, async (req, reply) => {
    const provider = getProvider(req.params.provider);
    const state = randomBytes(24).toString('base64url');
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    await withSystem(async (db) => {
      await db.query('DELETE FROM oauth_states WHERE expires_at < now()');
      await db.query(
        `INSERT INTO oauth_states (state, provider, code_verifier, expires_at) VALUES ($1, $2, $3, now() + interval '10 minutes')`,
        [state, provider.name, codeVerifier]);
    });
    return reply.redirect(provider.authorizationUrl({ state, codeChallenge, redirectUri: redirectUri(provider.name) }));
  });

  const callbackQuery = z.object({ code: z.string().min(1), state: z.string().min(1) });
  app.get<{ Params: { provider: string } }>('/auth/oauth/:provider/callback', limited, async (req) => {
    const provider = getProvider(req.params.provider);
    const { code, state } = parse(callbackQuery, req.query);
    // The state row is single-use: consumed atomically, which also defeats CSRF and replay.
    const consumed = await withSystem(async (db) =>
      (await db.query(
        'DELETE FROM oauth_states WHERE state = $1 AND provider = $2 AND expires_at > now() RETURNING code_verifier',
        [state, provider.name])).rows[0]);
    if (!consumed) throw new AppError(400, 'invalid_state', 'Invalid or expired OAuth state');

    let profile;
    try {
      profile = await provider.exchange({ code, codeVerifier: consumed.code_verifier, redirectUri: redirectUri(provider.name) });
    } catch (err) {
      req.log.warn({ err }, 'oauth exchange failed');
      throw new AppError(401, 'oauth_failed', 'Could not verify identity with provider');
    }
    if (!profile.emailVerified) throw new AppError(403, 'email_not_verified', 'Your provider account email is not verified');

    return withSystem(async (db) => {
      let user = (await db.query(
        `SELECT u.id, u.email, u.name FROM oauth_identities i JOIN users u ON u.id = i.user_id
          WHERE i.provider = $1 AND i.subject = $2`, [provider.name, profile.subject])).rows[0];
      if (!user) {
        // Link to an existing account with the same (provider-verified) email, else create one.
        user = (await db.query('SELECT id, email, name FROM users WHERE lower(email) = lower($1)', [profile.email])).rows[0];
        if (!user) {
          user = (await db.query(
            'INSERT INTO users (email, name, email_verified) VALUES ($1, $2, true) RETURNING id, email, name',
            [profile.email.toLowerCase(), profile.name])).rows[0];
        }
        await db.query('INSERT INTO oauth_identities (user_id, provider, subject) VALUES ($1, $2, $3)', [user.id, provider.name, profile.subject]);
      }
      let workspaces = await listWorkspaces(db, user.id);
      if (workspaces.length === 0) {
        const t = await createWorkspace(db, user.id, `${user.name}'s workspace`);
        await audit(db, { tenantId: t.id, actorId: user.id, action: 'tenant.created', entityType: 'tenants', entityId: t.id });
        workspaces = await listWorkspaces(db, user.id);
      }
      const chosen = workspaces[0]!;
      await audit(db, { tenantId: chosen.id, actorId: user.id, action: 'auth.login', metadata: { provider: provider.name } });
      const tokens = await issueTokens(db, { userId: user.id, tenantId: chosen.id, role: chosen.role });
      return { user, tenant: chosen, workspaces, ...tokens };
    }, { ip: req.ip, userId: undefined });
  });
}
