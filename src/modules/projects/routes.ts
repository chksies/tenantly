import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { parse, requirePermission, tenantTx } from '../../auth.js';
import { AppError } from '../../errors.js';
import { PLAN_LIMITS, type Plan } from '../../plans.js';

const idParam = z.object({ id: z.uuid() });
const createBody = z.object({ name: z.string().trim().min(1).max(120), description: z.string().max(2000).optional() });
const updateBody = z.object({
  name: z.string().trim().min(1).max(120).optional(),
  description: z.string().max(2000).nullable().optional(),
}).refine((b) => Object.keys(b).length > 0, 'Provide at least one field');
const listQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  offset: z.coerce.number().int().min(0).default(0),
});

const COLUMNS = 'id, name, description, created_by, created_at, updated_at';

// NOTE: no query below filters by tenant_id. Postgres row-level security does that; the
// application code cannot forget the WHERE clause because it isn't the thing enforcing isolation.
export async function projectRoutes(app: FastifyInstance) {
  app.get('/projects', { preHandler: requirePermission('projects:read') }, async (req) => {
    const { limit, offset } = parse(listQuery, req.query);
    return tenantTx(req, async (db) => ({
      projects: (await db.query(`SELECT ${COLUMNS} FROM projects ORDER BY created_at DESC, id LIMIT $1 OFFSET $2`, [limit, offset])).rows,
    }));
  });

  app.post('/projects', { preHandler: requirePermission('projects:write') }, async (req, reply) => {
    const body = parse(createBody, req.body);
    const project = await tenantTx(req, async (db) => {
      // Lock the tenant row so concurrent creates can't both slip under the plan limit.
      const { plan } = (await db.query('SELECT plan FROM tenants FOR UPDATE')).rows[0];
      const limit = PLAN_LIMITS[plan as Plan].projects;
      const { count } = (await db.query('SELECT count(*)::int AS count FROM projects')).rows[0];
      if (count >= limit) {
        throw new AppError(402, 'plan_limit_reached', `The ${plan} plan allows ${limit} projects. Upgrade to create more.`);
      }
      return (await db.query(
        `INSERT INTO projects (tenant_id, name, description, created_by)
         VALUES (app_tenant_id(), $1, $2, app_user_id()) RETURNING ${COLUMNS}`, [body.name, body.description ?? null])).rows[0];
    });
    return reply.status(201).send(project);
  });

  app.get<{ Params: { id: string } }>('/projects/:id', { preHandler: requirePermission('projects:read') }, async (req) => {
    const { id } = parse(idParam, req.params);
    const row = await tenantTx(req, async (db) => (await db.query(`SELECT ${COLUMNS} FROM projects WHERE id = $1`, [id])).rows[0]);
    if (!row) throw new AppError(404, 'not_found', 'Project not found');
    return row;
  });

  app.patch<{ Params: { id: string } }>('/projects/:id', { preHandler: requirePermission('projects:write') }, async (req) => {
    const { id } = parse(idParam, req.params);
    const body = parse(updateBody, req.body);
    const row = await tenantTx(req, async (db) => (await db.query(
      `UPDATE projects SET name = coalesce($2, name),
                           description = CASE WHEN $4 THEN $3 ELSE description END,
                           updated_at = now()
        WHERE id = $1 RETURNING ${COLUMNS}`,
      [id, body.name ?? null, body.description ?? null, 'description' in body])).rows[0]);
    if (!row) throw new AppError(404, 'not_found', 'Project not found');
    return row;
  });

  app.delete<{ Params: { id: string } }>('/projects/:id', { preHandler: requirePermission('projects:delete') }, async (req, reply) => {
    const { id } = parse(idParam, req.params);
    const n = await tenantTx(req, async (db) => (await db.query('DELETE FROM projects WHERE id = $1', [id])).rowCount);
    if (!n) throw new AppError(404, 'not_found', 'Project not found');
    return reply.status(204).send();
  });
}
