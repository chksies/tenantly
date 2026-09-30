CREATE TYPE member_role AS ENUM ('owner', 'admin', 'member', 'viewer');

CREATE TABLE tenants (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name               text NOT NULL,
  slug               text NOT NULL UNIQUE,
  plan               text NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro')),
  stripe_customer_id text UNIQUE,
  created_at         timestamptz NOT NULL DEFAULT now()
);

-- Users are global (one login can belong to many tenants); access is granted via memberships.
CREATE TABLE users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          text NOT NULL,
  name           text NOT NULL,
  password_hash  text,                          -- NULL for OAuth-only accounts
  email_verified boolean NOT NULL DEFAULT false,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_key ON users (lower(email));

CREATE TABLE oauth_identities (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  provider   text NOT NULL,
  subject    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, subject)
);

-- Server-side state for the OAuth2 authorization-code + PKCE flow (single use, short lived).
CREATE TABLE oauth_states (
  state         text PRIMARY KEY,
  provider      text NOT NULL,
  code_verifier text NOT NULL,
  expires_at    timestamptz NOT NULL
);

CREATE TABLE memberships (
  tenant_id  uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  role       member_role NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);

CREATE TABLE invitations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
  email       text NOT NULL,
  role        member_role NOT NULL CHECK (role <> 'owner'),
  token_hash  text NOT NULL UNIQUE,
  invited_by  uuid REFERENCES users ON DELETE SET NULL,
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invitations_tenant_idx ON invitations (tenant_id);

-- Refresh tokens are opaque, stored only as SHA-256 hashes, rotated on every use.
-- family_id links a chain of rotations so reuse of an old token can revoke the whole chain.
CREATE TABLE refresh_tokens (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  tenant_id  uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
  family_id  uuid NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

-- Example tenant-owned resource.
CREATE TABLE projects (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
  name        text NOT NULL,
  description text,
  created_by  uuid REFERENCES users ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX projects_tenant_idx ON projects (tenant_id, created_at DESC);

CREATE TABLE subscriptions (
  tenant_id              uuid PRIMARY KEY REFERENCES tenants ON DELETE CASCADE,
  stripe_subscription_id text NOT NULL UNIQUE,
  status                 text NOT NULL,
  plan                   text NOT NULL,
  price_id               text,
  current_period_end     timestamptz,
  cancel_at_period_end   boolean NOT NULL DEFAULT false,
  last_event_at          timestamptz NOT NULL,   -- guards against out-of-order webhook delivery
  updated_at             timestamptz NOT NULL DEFAULT now()
);

-- Idempotency ledger: one row per Stripe event we have fully processed.
CREATE TABLE stripe_events (
  id           text PRIMARY KEY,
  type         text NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only. No FK to tenants/users so history survives deletions.
CREATE TABLE audit_logs (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  actor_id    uuid,
  action      text NOT NULL,
  entity_type text,
  entity_id   text,
  metadata    jsonb NOT NULL DEFAULT '{}',
  ip          text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_tenant_idx ON audit_logs (tenant_id, id DESC);
