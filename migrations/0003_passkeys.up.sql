CREATE TABLE auth_passkeys (
    id            uuid PRIMARY KEY,
    principal_id  uuid NOT NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    label         text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    data          jsonb NOT NULL,
    created_at    timestamptz NOT NULL,
    last_used_at  timestamptz NULL
);
CREATE INDEX auth_passkeys_principal_idx ON auth_passkeys (principal_id, created_at);

CREATE TABLE auth_passkey_ceremonies (
    id            uuid PRIMARY KEY,
    ceremony_hash bytea NOT NULL UNIQUE,
    kind          text NOT NULL CHECK (kind IN ('register', 'login')),
    audience      text NOT NULL,
    principal_id  uuid NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    session_id    uuid NULL REFERENCES auth_sessions (id) ON DELETE CASCADE,
    data          jsonb NOT NULL,
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz NULL,
    CONSTRAINT auth_passkey_ceremonies_principal CHECK ((kind = 'login') = (principal_id IS NULL)),
    CONSTRAINT auth_passkey_ceremonies_session CHECK ((kind = 'login') = (session_id IS NULL))
);
CREATE INDEX idx_auth_passkey_ceremonies_principal_id ON auth_passkey_ceremonies (principal_id);
CREATE INDEX idx_auth_passkey_ceremonies_session_id ON auth_passkey_ceremonies (session_id);
CREATE INDEX idx_auth_passkey_ceremonies_expires_at ON auth_passkey_ceremonies (expires_at);

ALTER TABLE auth_events ADD COLUMN source text NOT NULL DEFAULT '';

ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_revoke_reason;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_revoke_reason CHECK (revoke_reason IS NULL OR revoke_reason IN ('logout', 'user', 'password_changed', 'password_reset', 'reuse_detected', 'admin', 'passkey_removed'));
UPDATE auth_schema SET version = 3;
