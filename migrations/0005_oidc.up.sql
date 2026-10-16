CREATE TABLE auth_ceremonies (
    id           uuid PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('signin', 'link', 'signup')),
    provider     text NOT NULL,
    audience     text NOT NULL,
    state_hash   bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
    binding_hash bytea NULL CHECK (octet_length(binding_hash) = 32),
    nonce_hash   bytea NULL CHECK (octet_length(nonce_hash) = 32),
    verifier     text NULL,
    principal_id uuid NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    subject      text NULL,
    email        text NULL,
    profile      jsonb NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    spent_at     timestamptz NULL,
    CONSTRAINT auth_ceremonies_principal CHECK ((kind = 'link') = (principal_id IS NOT NULL))
);
CREATE INDEX idx_auth_ceremonies_principal_id ON auth_ceremonies (principal_id);
CREATE INDEX idx_auth_ceremonies_expires_at ON auth_ceremonies (expires_at);

CREATE TABLE auth_identities (
    id           uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    provider     text NOT NULL,
    subject      text NOT NULL,
    email        text NULL,
    created_at   timestamptz NOT NULL,
    last_used_at timestamptz NULL,
    CONSTRAINT auth_identities_subject UNIQUE (provider, subject),
    CONSTRAINT auth_identities_principal UNIQUE (principal_id, provider)
);

ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_second_factor;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_second_factor CHECK (second_factor IN ('', 'totp', 'email', 'recovery', 'passkey', 'oidc'));
ALTER TABLE auth_events DROP CONSTRAINT auth_events_second_factor;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_second_factor CHECK (second_factor IN ('', 'totp', 'email', 'recovery', 'passkey', 'oidc'));
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_revoke_reason;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_revoke_reason CHECK (revoke_reason IS NULL OR revoke_reason IN ('logout', 'user', 'password_changed', 'password_reset', 'reuse_detected', 'admin', 'passkey_removed', 'identity_removed'));
UPDATE auth_schema SET version = 5;
