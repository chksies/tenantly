-- ---------------------------------------------------------------------------
-- Request context helpers. The API sets these with set_config(..., true), which
-- scopes them to the current transaction, so pooled connections never leak context.
-- If unset they return NULL and every policy below evaluates to "no rows" (fail closed).
-- ---------------------------------------------------------------------------
CREATE FUNCTION app_tenant_id() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE FUNCTION app_user_id() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;

CREATE FUNCTION app_ip() RETURNS text LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.ip', true), '') $$;

-- ---------------------------------------------------------------------------
-- Row-level security. FORCE applies policies to the table owner too.
-- ---------------------------------------------------------------------------
ALTER TABLE tenants       ENABLE ROW LEVEL SECURITY; ALTER TABLE tenants       FORCE ROW LEVEL SECURITY;
ALTER TABLE memberships   ENABLE ROW LEVEL SECURITY; ALTER TABLE memberships   FORCE ROW LEVEL SECURITY;
ALTER TABLE invitations   ENABLE ROW LEVEL SECURITY; ALTER TABLE invitations   FORCE ROW LEVEL SECURITY;
ALTER TABLE projects      ENABLE ROW LEVEL SECURITY; ALTER TABLE projects      FORCE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY; ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs    ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_logs    FORCE ROW LEVEL SECURITY;
ALTER TABLE users         ENABLE ROW LEVEL SECURITY; ALTER TABLE users         FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenants
  USING (id = app_tenant_id()) WITH CHECK (id = app_tenant_id());
CREATE POLICY tenant_isolation ON memberships
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY tenant_isolation ON invitations
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY tenant_isolation ON projects
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY tenant_isolation ON subscriptions
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY tenant_isolation ON audit_logs
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

-- Users are global, but a tenant may only see users who are members of it.
-- The subquery is itself filtered by the memberships policy above.
CREATE POLICY members_of_current_tenant ON users
  USING (EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = users.id));

-- ---------------------------------------------------------------------------
-- Audit trail: append-only, plus row-change triggers so mutations are logged
-- even if application code forgets to.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit_logs_immutable() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END $$;

CREATE TRIGGER audit_logs_append_only
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();

CREATE FUNCTION audit_row_change() RETURNS trigger LANGUAGE plpgsql AS
$$
DECLARE
  rec  jsonb := to_jsonb(CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END);
  meta jsonb;
BEGIN
  meta := CASE TG_OP
    WHEN 'INSERT' THEN jsonb_build_object('after', to_jsonb(NEW))
    WHEN 'UPDATE' THEN jsonb_build_object('before', to_jsonb(OLD), 'after', to_jsonb(NEW))
    ELSE jsonb_build_object('before', to_jsonb(OLD))
  END;
  INSERT INTO audit_logs (tenant_id, actor_id, action, entity_type, entity_id, metadata, ip)
  VALUES ((rec->>'tenant_id')::uuid, app_user_id(),
          TG_TABLE_NAME || '.' || lower(TG_OP), TG_TABLE_NAME,
          coalesce(rec->>'id', rec->>'user_id'), meta, app_ip());
  RETURN NULL;
END
$$;

CREATE TRIGGER projects_audit    AFTER INSERT OR UPDATE OR DELETE ON projects
  FOR EACH ROW EXECUTE FUNCTION audit_row_change();
CREATE TRIGGER memberships_audit AFTER INSERT OR UPDATE OR DELETE ON memberships
  FOR EACH ROW EXECUTE FUNCTION audit_row_change();

-- ---------------------------------------------------------------------------
-- Least-privilege grants. saas_app has no access at all to refresh_tokens,
-- oauth_identities, oauth_states or stripe_events, and can never read password_hash.
-- ---------------------------------------------------------------------------
GRANT SELECT, UPDATE (name, stripe_customer_id) ON tenants TO saas_app;
GRANT SELECT (id, email, name)                  ON users TO saas_app;
GRANT SELECT, INSERT, DELETE, UPDATE (role)     ON memberships TO saas_app;
GRANT SELECT, INSERT, DELETE                    ON invitations TO saas_app;
GRANT SELECT, INSERT, UPDATE, DELETE            ON projects TO saas_app;
GRANT SELECT                                    ON subscriptions TO saas_app;
GRANT SELECT, INSERT                            ON audit_logs TO saas_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  tenants, users, oauth_identities, oauth_states, memberships, invitations, refresh_tokens,
  projects, subscriptions, stripe_events TO saas_system;
GRANT SELECT, INSERT ON audit_logs TO saas_system;
