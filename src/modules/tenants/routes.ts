import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { audit } from '../../audit.js';
import { authenticate, parse, requirePermission, tenantTx } from '../../auth.js';
import { isProd } from '../../config.js';
import { withSystem } from '../../db.js';
import { AppError } from '../../errors.js';
import { sendInvitationEmail } from '../../mailer.js';
import { canManageRole, type Role } from '../../rbac.js';
import { generateOpaqueToken, hashToken } from '../../security/tokens.js';
import { hashPassword } from '../../security/password.js';
import { issueTokens } from '../auth/service.js';

const uuidParam = z.object({ userId: z.uuid() });
const inviteBody = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  role: z.enum(['admin', 'member', 'viewer']),
});
const roleBody = z.object({ role: z.enum(['owner', 'admin', 'member', 'viewer']) });
const acceptBody = z.object({
  token: z.string().min(20).max(200),
  name: z.string().trim().min(1).max(100).optional(),
  password: z.string().min(10).max(200).optional(),
});

export async function tenantRoutes(app: FastifyInstance) {
  app.get('/tenants/current', { preHandler: requirePermission('tenant:read') }, async (req) =>
    tenantTx(req, async (db) =>
      (await db.query('SELECT id, name, slug, plan, created_at FROM tenants')).rows[0]));

  app.patch('/tenants/current', { preHandler: requirePermission('tenant:update') }, async (req) => {
    const { name } = parse(z.object({ name: z.string().trim().min(1).max(100) }), req.body);
    return tenantTx(req, async (db) => {
      const { rows } = await db.query(
        'UPDATE tenants SET name = $1 WHERE id = app_tenant_id() RETURNING id, name, slug, plan', [name]);
      await audit(db, { tenantId: req.auth!.tenantId, action: 'tenant.updated', entityType: 'tenants', entityId: req.auth!.tenantId, metadata: { name } });
      return rows[0];
    });
  });

  // ---------------------------------------------------------------- members
  app.get('/tenants/current/members', { preHandler: requirePermission('members:read') }, async (req) =>
    tenantTx(req, async (db) => ({
      members: (await db.query(
        `SELECT u.id, u.email, u.name, m.role, m.created_at
           FROM memberships m JOIN users u ON u.id = m.user_id ORDER BY m.created_at, u.id`)).rows,
    })));

  app.patch<{ Params: { userId: string } }>(
    '/tenants/current/members/:userId', { preHandler: requirePermission('members:manage') }, async (req) => {
      const { userId } = parse(uuidParam, req.params);
      const { role: newRole } = parse(roleBody, req.body);
      const actor = req.auth!;
      if (userId === actor.userId) throw new AppError(400, 'cannot_change_own_role', 'You cannot change your own role');
      return tenantTx(req, async (db) => {
        const target = (await db.query('SELECT role FROM memberships WHERE user_id = $1 FOR UPDATE', [userId])).rows[0];
        if (!target) throw new AppError(404, 'not_found', 'Member not found');
        if (!canManageRole(actor.role, target.role as Role) || !canManageRole(actor.role, newRole)) {
          throw new AppError(403, 'forbidden', 'You cannot grant or change that role');
        }
        const { rows } = await db.query(
          'UPDATE memberships SET role = $1 WHERE user_id = $2 RETURNING user_id AS id, role', [newRole, userId]);
        return rows[0];
      });
    });

  app.delete<{ Params: { userId: string } }>(
    '/tenants/current/members/:userId', { preHandler: requirePermission('members:manage') }, async (req, reply) => {
      const { userId } = parse(uuidParam, req.params);
      const actor = req.auth!;
      await tenantTx(req, async (db) => {
        const target = (await db.query('SELECT role FROM memberships WHERE user_id = $1 FOR UPDATE', [userId])).rows[0];
        if (!target) throw new AppError(404, 'not_found', 'Member not found');
        if (userId !== actor.userId && !canManageRole(actor.role, target.role as Role)) {
          throw new AppError(403, 'forbidden', 'You cannot remove that member');
        }
        if (target.role === 'owner') {
          const owners = (await db.query(`SELECT user_id FROM memberships WHERE role = 'owner' FOR UPDATE`)).rowCount;
          if (owners! <= 1) throw new AppError(409, 'last_owner', 'A workspace must keep at least one owner');
        }
        await db.query('DELETE FROM memberships WHERE user_id = $1', [userId]);
      });
      // Kill the removed member's sessions in this workspace (the per-request membership check
      // already denies access immediately; this stops them minting fresh access tokens).
      await withSystem(async (db) => {
        await db.query(
          'UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL',
          [userId, actor.tenantId]);
      });
      return reply.status(204).send();
    });

  // ---------------------------------------------------------------- invitations
  app.post('/tenants/current/invitations', { preHandler: requirePermission('members:manage') }, async (req, reply) => {
    const body = parse(inviteBody, req.body);
    if (!canManageRole(req.auth!.role, body.role)) throw new AppError(403, 'forbidden', 'You cannot invite someone with that role');
    const token = generateOpaqueToken();
    const invitation = await tenantTx(req, async (db) => {
      const existing = await db.query(
        `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id WHERE lower(u.email) = lower($1)`, [body.email]);
      if (existing.rowCount) throw new AppError(409, 'already_member', 'That person is already a member');
      const { rows } = await db.query(
        `INSERT INTO invitations (tenant_id, email, role, token_hash, invited_by, expires_at)
         VALUES (app_tenant_id(), $1, $2, $3, app_user_id(), now() + interval '7 days')
         RETURNING id, email, role, expires_at`, [body.email, body.role, hashToken(token)]);
      await audit(db, { tenantId: req.auth!.tenantId, action: 'invitation.created', entityType: 'invitations', entityId: rows[0].id, metadata: { email: body.email, role: body.role } });
      return rows[0];
    });
    await sendInvitationEmail(req.log, body.email, token);
    // The raw token is only echoed outside production (it is otherwise delivered by email only).
    return reply.status(201).send({ ...invitation, ...(isProd ? {} : { token }) });
  });

  app.get('/tenants/current/invitations', { preHandler: requirePermission('members:manage') }, async (req) =>
    tenantTx(req, async (db) => ({
      invitations: (await db.query(
        `SELECT id, email, role, expires_at, created_at FROM invitations
          WHERE accepted_at IS NULL AND expires_at > now() ORDER BY created_at DESC`)).rows,
    })));

  app.delete<{ Params: { id: string } }>(
    '/tenants/current/invitations/:id', { preHandler: requirePermission('members:manage') }, async (req, reply) => {
      const { id } = parse(z.object({ id: z.uuid() }), req.params);
      const n = await tenantTx(req, async (db) => {
        const r = await db.query('DELETE FROM invitations WHERE id = $1', [id]);
        if (r.rowCount) await audit(db, { tenantId: req.auth!.tenantId, action: 'invitation.revoked', entityType: 'invitations', entityId: id });
        return r.rowCount;
      });
      if (!n) throw new AppError(404, 'not_found', 'Invitation not found');
      return reply.status(204).send();
    });

  /**
   * Accept an invitation. Either authenticated as the invited person (existing account), or,
   * for a brand-new person, supply name + password to create the account in the same step.
   */
  app.post('/invitations/accept', async (req) => {
    const body = parse(acceptBody, req.body);
    const authed = req.headers.authorization ? await authenticate(req) : null;
    const passwordHash = !authed && body.password ? await hashPassword(body.password) : null;

    return withSystem(async (db) => {
      const inv = (await db.query(
        `SELECT id, tenant_id, email, role FROM invitations
          WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now() FOR UPDATE`, [hashToken(body.token)])).rows[0];
      if (!inv) throw new AppError(400, 'invalid_invitation', 'Invitation is invalid, expired or already used');

      let userId: string;
      if (authed) {
        const u = (await db.query('SELECT id, email FROM users WHERE id = $1', [authed.userId])).rows[0];
        if (!u || u.email.toLowerCase() !== inv.email.toLowerCase()) {
          throw new AppError(403, 'forbidden', 'This invitation was sent to a different email address');
        }
        userId = u.id;
      } else {
        const existing = await db.query('SELECT 1 FROM users WHERE lower(email) = lower($1)', [inv.email]);
        if (existing.rowCount) throw new AppError(409, 'account_exists', 'An account for this email exists. Log in and accept the invitation while authenticated.');
        if (!body.name || !passwordHash) throw new AppError(400, 'validation_error', 'name and password are required to create your account');
        // Possession of the emailed token proves ownership of the address.
        userId = (await db.query(
          'INSERT INTO users (email, name, password_hash, email_verified) VALUES ($1, $2, $3, true) RETURNING id',
          [inv.email, body.name, passwordHash])).rows[0].id;
      }

      const already = await db.query('SELECT 1 FROM memberships WHERE tenant_id = $1 AND user_id = $2', [inv.tenant_id, userId]);
      if (already.rowCount) throw new AppError(409, 'already_member', 'You are already a member of this workspace');
      await db.query('INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, $3)', [inv.tenant_id, userId, inv.role]);
      await db.query('UPDATE invitations SET accepted_at = now() WHERE id = $1', [inv.id]);
      await audit(db, { tenantId: inv.tenant_id, actorId: userId, action: 'invitation.accepted', entityType: 'invitations', entityId: inv.id });
      const tokens = await issueTokens(db, { userId, tenantId: inv.tenant_id, role: inv.role });
      return { tenantId: inv.tenant_id, role: inv.role, ...tokens };
    }, { ip: req.ip });
  });
}

