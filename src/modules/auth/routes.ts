import { createHash, randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../../audit.js';
import { authenticate, parse } from '../../auth.js';
import { config, isProd } from '../../config.js';
import { withSystem } from '../../db.js';
import { AppError } from '../../errors.js';
import { sendVerificationEmail } from '../../mailer.js';
import { hashPassword, verifyPassword } from '../../security/password.js';
import { hashToken } from '../../security/tokens.js';
import type { OAuthProvider } from './oauth.js';
import {
  createEmailVerification, createWorkspace, issueTokens, listWorkspaces, reclaimUnverifiedAccount,
  VERIFICATION_RESEND_COOLDOWN_SECONDS,
} from './service.js';

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
const verifyBody = z.object({ token: z.string().min(20).max(200) });

export async function authRoutes(app: FastifyInstance, opts: { oauthProviders: Record<string, OAuthProvider> }) {
  const limited = { config: { rateLimit: { max: config.NODE_ENV === 'test' ? 10_000 : 10, timeWindow: '1 minute' } } };

  /** Mail delivery must never fail the request that triggered it: the user can always ask for another link. */
  const deliverVerification = async (log: FastifyInstance['log'], to: string, token: string) => {
    try {
      await sendVerificationEmail(log, to, token);
    } catch (err) {
      log.warn({ err }, 'could not send verification email');
    }
  };

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
      const verificationToken = await createEmailVerification(db, user.id, user.email);
      return { user: { ...user, emailVerified: false }, tenant: { ...tenant, role: 'owner' }, ...tokens, verificationToken };
    }, { ip: req.ip });
    await deliverVerification(req.log, result.user.email, result.verificationToken);
    // The raw token is only echoed outside production (it is otherwise delivered by email only).
    const { verificationToken, ...response } = result;
    return reply.status(201).send({ ...response, ...(isProd ? {} : { verificationToken }) });
  });

  /**
   * Redeems an emailed link. Public on purpose (the link may be opened on a different device than the
   * one that signed up) and POST, so scanners that prefetch links can't burn a token. The claim is
   * atomic: the first request consumes the token, any concurrent or later one gets a 400.
   */
  app.post('/auth/verify-email', limited, async (req) => {
    const { token } = parse(verifyBody, req.body);
    const verified = await withSystem(async (db) => {
      const link = (await db.query(
        `UPDATE email_verifications SET used_at = now()
          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING user_id, email`,
        [hashToken(token)])).rows[0];
      if (!link) return false;
      // Only verify if the account still has the address the link was sent to.
      const updated = await db.query(
        'UPDATE users SET email_verified = true WHERE id = $1 AND lower(email) = lower($2)', [link.user_id, link.email]);
      if (!updated.rowCount) return false;
      for (const w of await listWorkspaces(db, link.user_id)) {
        await audit(db, { tenantId: w.id, actorId: link.user_id, action: 'auth.email_verified', entityType: 'users', entityId: link.user_id });
      }
      return true;
    }, { ip: req.ip });
    if (!verified) throw new AppError(400, 'invalid_verification_token', 'Verification link is invalid, expired or already used');
    return { verified: true };
  });

  /** Sends a new link to the signed-in user's address, at most one a minute. */
  app.post('/auth/resend-verification', limited, async (req, reply) => {
    const auth = await authenticate(req);
    const outcome = await withSystem(async (db) => {
      // The row lock serialises concurrent resends, so the cooldown check below can't be raced.
      const user = (await db.query('SELECT email, email_verified FROM users WHERE id = $1 FOR UPDATE', [auth.userId])).rows[0];
      if (!user) throw new AppError(401, 'unauthorized', 'Account no longer exists');
      if (user.email_verified) return { kind: 'already_verified' as const };
      const wait = (await db.query(
        `SELECT ceil(extract(epoch FROM (max(created_at) + make_interval(secs => $2) - now())))::int AS wait
           FROM email_verifications WHERE user_id = $1`,
        [auth.userId, VERIFICATION_RESEND_COOLDOWN_SECONDS])).rows[0].wait as number | null;
      if (wait !== null && wait > 0) return { kind: 'throttled' as const, wait };
      return { kind: 'sent' as const, email: user.email as string, token: await createEmailVerification(db, auth.userId, user.email) };
    }, { ip: req.ip, userId: auth.userId });

    if (outcome.kind === 'already_verified') return { status: 'already_verified' };
    if (outcome.kind === 'throttled') {
      reply.header('Retry-After', outcome.wait);
      throw new AppError(429, 'verification_email_throttled',
        `A verification email was sent recently. Try again in ${outcome.wait}s.`, { retryAfterSeconds: outcome.wait });
    }
    await deliverVerification(req.log, outcome.email, outcome.token);
    return reply.status(202).send({ status: 'sent', ...(isProd ? {} : { verificationToken: outcome.token }) });
  });

  app.post('/auth/login', limited, async (req) => {
    const body = parse(loginBody, req.body);
    const user = await withSystem(async (db) =>
      (await db.query('SELECT id, email, name, email_verified, password_hash FROM users WHERE lower(email) = lower($1)', [body.email])).rows[0]);
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
      return { user: { id: user.id, email: user.email, name: user.name, emailVerified: user.email_verified }, tenant: chosen, workspaces, ...tokens };
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
        const existing = (await db.query(
          'SELECT id, email, name, email_verified FROM users WHERE lower(email) = lower($1)', [profile.email])).rows[0];
        if (existing) {
          user = { id: existing.id, email: existing.email, name: existing.name };
          if (!existing.email_verified) {
            // The provider just proved who owns this address; whoever registered it with a password did not.
            await reclaimUnverifiedAccount(db, existing.id);
            for (const w of await listWorkspaces(db, existing.id)) {
              await audit(db, { tenantId: w.id, actorId: existing.id, action: 'auth.unverified_account_reclaimed', entityType: 'users', entityId: existing.id, metadata: { provider: provider.name } });
            }
          }
        }
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
