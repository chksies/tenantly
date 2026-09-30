-- Two runtime roles, on purpose:
--   saas_app     : NOBYPASSRLS. Every tenant-scoped request runs as this role, so row-level
--                  security is enforced by the database no matter what the application does.
--   saas_system  : BYPASSRLS. Used only by code that legitimately spans tenants
--                  (login, token refresh, invitation acceptance, Stripe webhooks).
-- Dev-only passwords. In production create these roles with secrets from your secret manager.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saas_app') THEN
    CREATE ROLE saas_app LOGIN PASSWORD 'saas_app_dev' NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saas_system') THEN
    CREATE ROLE saas_system LOGIN PASSWORD 'saas_system_dev' NOSUPERUSER BYPASSRLS;
  END IF;
END
$$;
