-- Email verification links. Same shape as the other opaque tokens: only the SHA-256 hash is stored,
-- each link is single use, and it expires. `email` records which address the link proves, so a link
-- sent to an old address can never verify a different one.
CREATE TABLE email_verifications (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  email      text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_verifications_user_idx ON email_verifications (user_id, created_at DESC);

-- Auth flows only (they run as saas_system). saas_app gets no access to the table, like refresh_tokens.
GRANT SELECT, INSERT, UPDATE, DELETE ON email_verifications TO saas_system;

-- Lets tenant-scoped requests ask "is this caller verified?" in the same transaction as the role check.
-- Still subject to the users RLS policy; saas_app continues to have no access to password_hash.
GRANT SELECT (email_verified) ON users TO saas_app;
