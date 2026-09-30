import type { Db } from './db.js';

export interface AuditEvent {
  tenantId: string;
  actorId?: string | null;
  action: string;
  entityType?: string;
  entityId?: string;
  metadata?: Record<string, unknown>;
}

/** Application-level audit entry (auth, billing). Row-level changes are captured by DB triggers. */
export async function audit(db: Db, e: AuditEvent) {
  await db.query(
    `INSERT INTO audit_logs (tenant_id, actor_id, action, entity_type, entity_id, metadata, ip)
     VALUES ($1, coalesce($2::uuid, app_user_id()), $3, $4, $5, $6, app_ip())`,
    [e.tenantId, e.actorId ?? null, e.action, e.entityType ?? null, e.entityId ?? null, JSON.stringify(e.metadata ?? {})],
  );
}
