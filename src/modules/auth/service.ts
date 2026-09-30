import { randomBytes, randomUUID } from 'node:crypto';
import { config } from '../../config.js';
import type { Db } from '../../db.js';
import type { Role } from '../../rbac.js';
import { generateOpaqueToken, hashToken, signAccessToken } from '../../security/tokens.js';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

/** Mints an access JWT plus a new refresh token (in `familyId`, or a brand-new rotation family). */
export async function issueTokens(
  db: Db,
  p: { userId: string; tenantId: string; role: Role; familyId?: string },
): Promise<TokenPair> {
  const refreshToken = generateOpaqueToken();
  await db.query(
    `INSERT INTO refresh_tokens (user_id, tenant_id, family_id, token_hash, expires_at)
     VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))`,
    [p.userId, p.tenantId, p.familyId ?? randomUUID(), hashToken(refreshToken), config.REFRESH_TOKEN_TTL_DAYS],
  );
  const accessToken = await signAccessToken({ userId: p.userId, tenantId: p.tenantId, role: p.role });
  return { accessToken, refreshToken, tokenType: 'Bearer', expiresIn: config.ACCESS_TOKEN_TTL_SECONDS };
}

const slugify = (s: string) =>
  s.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'workspace';

/** Creates a tenant and makes `userId` its owner. Must run on the system pool. */
export async function createWorkspace(db: Db, userId: string, name: string) {
  const slug = `${slugify(name)}-${randomBytes(3).toString('hex')}`;
  const { rows } = await db.query(
    'INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id, name, slug, plan', [name, slug]);
  await db.query(`INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, 'owner')`, [rows[0].id, userId]);
  return rows[0] as { id: string; name: string; slug: string; plan: string };
}

export async function listWorkspaces(db: Db, userId: string) {
  const { rows } = await db.query(
    `SELECT t.id, t.name, t.slug, t.plan, m.role
       FROM memberships m JOIN tenants t ON t.id = m.tenant_id
      WHERE m.user_id = $1 ORDER BY m.created_at, t.id`, [userId]);
  return rows as { id: string; name: string; slug: string; plan: string; role: Role }[];
}
