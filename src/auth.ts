import type { FastifyRequest } from 'fastify';
import { withTenant, type Db } from './db.js';
import { AppError } from './errors.js';
import { can, type Permission } from './rbac.js';
import { verifyAccessToken, type AuthContext } from './security/tokens.js';

declare module 'fastify' {
  interface FastifyRequest {
    auth: AuthContext | null;
  }
}

/** Verifies the bearer JWT. Does not check permissions. */
export async function authenticate(req: FastifyRequest): Promise<AuthContext> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) throw new AppError(401, 'unauthorized', 'Missing bearer token');
  try {
    req.auth = await verifyAccessToken(header.slice(7));
  } catch {
    throw new AppError(401, 'unauthorized', 'Invalid or expired token');
  }
  return req.auth;
}

/**
 * Route guard: authenticates, then re-reads the caller's role from the database (inside the
 * tenant's RLS scope) so removed or demoted members lose access immediately instead of when
 * their access token expires.
 */
export function requirePermission(permission: Permission) {
  return async (req: FastifyRequest) => {
    const auth = await authenticate(req);
    const row = await withTenant(auth, async (db) =>
      (await db.query('SELECT role FROM memberships WHERE user_id = $1', [auth.userId])).rows[0]);
    if (!row) throw new AppError(401, 'unauthorized', 'You are no longer a member of this workspace');
    auth.role = row.role;
    if (!can(auth.role, permission)) {
      throw new AppError(403, 'forbidden', `Missing permission: ${permission}`);
    }
  };
}

/** Runs `fn` inside a transaction scoped (by Postgres RLS) to the caller's tenant. */
export function tenantTx<T>(req: FastifyRequest, fn: (db: Db) => Promise<T>): Promise<T> {
  const auth = req.auth;
  if (!auth) throw new AppError(401, 'unauthorized', 'Not authenticated');
  return withTenant({ tenantId: auth.tenantId, userId: auth.userId, ip: req.ip }, fn);
}

/** Validates a request body/query with zod, mapping failures to a 400. */
import type { ZodType } from 'zod';
export function parse<T>(schema: ZodType<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new AppError(400, 'validation_error', 'Invalid request', result.error.issues.map((i) => ({
      path: i.path.join('.'), message: i.message,
    })));
  }
  return result.data;
}
