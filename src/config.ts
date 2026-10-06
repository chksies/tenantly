import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),
  APP_URL: z.string().url().default('http://localhost:3000'),
  TRUST_PROXY: z.enum(['true', 'false']).default('false').transform((v) => v === 'true'),

  DATABASE_URL: z.string().url(),
  SYSTEM_DATABASE_URL: z.string().url(),
  MIGRATION_DATABASE_URL: z.string().url().optional(),

  // Per-tenant rate limiting. Unset = limiter off (dev/tests); required in production.
  REDIS_URL: z.string().url().optional(),
  RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).default(60),
  // Redis calls are bounded so a slow Redis can't stall API traffic: on timeout the request is let through.
  RATE_LIMIT_REDIS_TIMEOUT_MS: z.coerce.number().int().min(10).default(100),
  // How long a tenant's plan is cached in-process, i.e. how long a plan change can take to reach the limiter.
  RATE_LIMIT_PLAN_CACHE_SECONDS: z.coerce.number().min(0).default(10),

  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().default(30),

  STRIPE_SECRET_KEY: z.string().default('sk_test_placeholder'),
  STRIPE_WEBHOOK_SECRET: z.string().default('whsec_placeholder'),
  STRIPE_PRICE_PRO: z.string().default('price_pro_placeholder'),

  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
});

export const config = schema
  .refine((c) => c.NODE_ENV !== 'production' || c.REDIS_URL, {
    path: ['REDIS_URL'], message: 'REDIS_URL is required in production (per-tenant rate limiting)',
  })
  .parse(process.env);
export const isProd = config.NODE_ENV === 'production';
