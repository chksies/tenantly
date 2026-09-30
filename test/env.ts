// Shared by vitest.config.ts (worker env) and globalSetup (schema reset). Point TEST_DATABASE_URL at a
// throwaway superuser connection: the suite drops and recreates the `public` schema in that database.
const admin = new URL(process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/tenantly_test');

const as = (user: string, password: string) => {
  const u = new URL(admin);
  u.username = user;
  u.password = password;
  return u.toString();
};

export const adminUrl = admin.toString();

export const testEnv = {
  NODE_ENV: 'test',
  DATABASE_URL: as('saas_app', 'saas_app_dev'),
  SYSTEM_DATABASE_URL: as('saas_system', 'saas_system_dev'),
  JWT_SECRET: 'test-secret-test-secret-test-secret-1234',
  STRIPE_SECRET_KEY: 'sk_test_dummy',
  STRIPE_WEBHOOK_SECRET: 'whsec_test_secret',
  STRIPE_PRICE_PRO: 'price_pro_test',
  APP_URL: 'http://localhost:3000',
};
