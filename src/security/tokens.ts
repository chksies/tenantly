import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { config } from '../config.js';
import type { Role } from '../rbac.js';

const key = new TextEncoder().encode(config.JWT_SECRET);
const ISSUER = 'tenantly';
const AUDIENCE = 'tenantly-api';

export interface AuthContext {
  userId: string;
  tenantId: string;
  role: Role;
}

/** Short-lived access token scoped to exactly one tenant. */
export async function signAccessToken(ctx: AuthContext): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ tid: ctx.tenantId, role: ctx.role })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(ctx.userId)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt(now)
    .setExpirationTime(now + config.ACCESS_TOKEN_TTL_SECONDS)
    .sign(key);
}

export async function verifyAccessToken(token: string): Promise<AuthContext> {
  const { payload } = await jwtVerify(token, key, { issuer: ISSUER, audience: AUDIENCE, algorithms: ['HS256'] });
  if (!payload.sub || typeof payload.tid !== 'string') throw new Error('malformed token');
  return { userId: payload.sub, tenantId: payload.tid, role: payload.role as Role };
}

export const generateOpaqueToken = () => randomBytes(32).toString('base64url');
export const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');
