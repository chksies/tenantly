import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { parse, requirePermission, tenantTx } from '../../auth.js';

const query = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  before: z.coerce.number().int().positive().optional(),
  action: z.string().max(100).optional(),
});

export async function auditRoutes(app: FastifyInstance) {
  /** Newest-first, keyset-paginated. `action` is a prefix filter, e.g. `projects.` or `billing.`. */
  app.get('/audit-logs', { preHandler: requirePermission('audit:read') }, async (req) => {
    const q = parse(query, req.query);
    const rows = await tenantTx(req, async (db) => (await db.query(
      `SELECT id::text, actor_id, action, entity_type, entity_id, metadata, ip, created_at
         FROM audit_logs
        WHERE ($1::bigint IS NULL OR id < $1)
          AND ($2::text IS NULL OR left(action, length($2)) = $2)
        ORDER BY id DESC LIMIT $3`,
      [q.before ?? null, q.action ?? null, q.limit + 1])).rows);
    const page = rows.slice(0, q.limit);
    return { items: page, nextCursor: rows.length > q.limit ? page[page.length - 1].id : null };
  });
}
