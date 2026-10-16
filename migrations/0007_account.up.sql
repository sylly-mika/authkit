CREATE TABLE auth_invites (
    id          uuid PRIMARY KEY,
    audience    text NOT NULL,
    email       text NOT NULL,
    scope_id    uuid NULL,
    invited_by  uuid NULL REFERENCES {{principals}} (id) ON DELETE SET NULL,
    payload     jsonb NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz NULL,
    accepted_by uuid NULL REFERENCES {{principals}} (id) ON DELETE SET NULL,
    revoked_at  timestamptz NULL,
    CONSTRAINT auth_invites_closed CHECK (accepted_at IS NULL OR revoked_at IS NULL),
    CONSTRAINT auth_invites_accepted CHECK (accepted_at IS NOT NULL OR accepted_by IS NULL)
);
CREATE UNIQUE INDEX auth_invites_open ON auth_invites (audience, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'), email) WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX auth_invites_email ON auth_invites (email);
CREATE INDEX auth_invites_expires ON auth_invites (expires_at);
CREATE INDEX idx_auth_invites_invited_by ON auth_invites (invited_by);
CREATE INDEX idx_auth_invites_accepted_by ON auth_invites (accepted_by);

CREATE TABLE auth_email_changes (
    principal_id uuid PRIMARY KEY REFERENCES {{principals}} (id) ON DELETE CASCADE,
    audience     text NOT NULL,
    old_email    text NOT NULL,
    new_email    text NOT NULL,
    session_id   uuid NULL REFERENCES auth_sessions (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX idx_auth_email_changes_session_id ON auth_email_changes (session_id);

ALTER TABLE auth_passkey_ceremonies DROP CONSTRAINT auth_passkey_ceremonies_kind_check;
ALTER TABLE auth_passkey_ceremonies ADD CONSTRAINT auth_passkey_ceremonies_kind_check CHECK (kind IN ('register', 'login', 'reverify'));
ALTER TABLE auth_ceremonies DROP CONSTRAINT auth_ceremonies_kind_check;
ALTER TABLE auth_ceremonies ADD CONSTRAINT auth_ceremonies_kind_check CHECK (kind IN ('signin', 'link', 'signup', 'reverify'));
ALTER TABLE auth_ceremonies DROP CONSTRAINT auth_ceremonies_principal;
ALTER TABLE auth_ceremonies ADD CONSTRAINT auth_ceremonies_principal CHECK ((kind IN ('link', 'reverify')) = (principal_id IS NOT NULL));
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_revoke_reason;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_revoke_reason CHECK (revoke_reason IS NULL OR revoke_reason IN ('logout', 'user', 'password_changed', 'password_reset', 'reuse_detected', 'admin', 'passkey_removed', 'identity_removed', 'email_changed'));
UPDATE auth_schema SET version = 7;
