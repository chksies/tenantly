-- Adds the 'enterprise' tier. Enterprise is assigned by hand (it is not sold through Stripe Checkout),
-- so saas_app still cannot change a tenant's plan: only the table owner or the Stripe webhook can.
ALTER TABLE tenants DROP CONSTRAINT tenants_plan_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_plan_check CHECK (plan IN ('free', 'pro', 'enterprise'));
