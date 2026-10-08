-- authkit's tables, keyed by the app's principal uuid. Ids, timestamps and
-- token hashes all come from the library, so no INSERT needs RETURNING.

CREATE TABLE auth_schema (
    id      boolean PRIMARY KEY DEFAULT true CHECK (id),
    version integer NOT NULL
);
INSERT INTO auth_schema (id, version) VALUES (true, 1);

CREATE TABLE auth_credentials (
    principal_id  uuid PRIMARY KEY REFERENCES {{principals}} (id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    changed_at    timestamptz NOT NULL
);

CREATE TABLE auth_sessions (
    id               uuid PRIMARY KEY,
    principal_id     uuid NOT NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    audience         text NOT NULL,
    scope_id         uuid NULL,
    token_hash       bytea NOT NULL UNIQUE,
    prev_token_hash  bytea NULL,
    rotated_at       timestamptz NULL,
    authenticated_at timestamptz NOT NULL,
    ip               text NOT NULL DEFAULT '',
    user_agent       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL,
    last_seen_at     timestamptz NULL,
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz NULL,
    revoke_reason    text NULL,
    CONSTRAINT auth_sessions_revoke_reason CHECK (revoke_reason IS NULL OR revoke_reason IN ('logout', 'user', 'password_changed', 'password_reset', 'reuse_detected', 'admin')),
    CONSTRAINT auth_sessions_revoked_pair CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX idx_auth_sessions_principal_id ON auth_sessions (principal_id);
CREATE INDEX idx_auth_sessions_prev_token_hash ON auth_sessions (prev_token_hash) WHERE prev_token_hash IS NOT NULL;

CREATE TABLE auth_tokens (
    id         uuid PRIMARY KEY,
    purpose    text NOT NULL,
    owner_id   uuid NOT NULL,
    token_hash bytea NULL UNIQUE,
    ttl        interval NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX idx_auth_tokens_live_uniq ON auth_tokens (purpose, owner_id) WHERE used_at IS NULL AND revoked_at IS NULL;
CREATE INDEX idx_auth_tokens_purpose_owner_id ON auth_tokens (purpose, owner_id, created_at);

CREATE TABLE auth_events (
    id           uuid PRIMARY KEY,
    at           timestamptz NOT NULL,
    principal_id uuid NULL REFERENCES {{principals}} (id) ON DELETE SET NULL,
    session_id   uuid NULL REFERENCES auth_sessions (id) ON DELETE SET NULL,
    audience     text NOT NULL,
    scope_id     uuid NULL,
    login        text NOT NULL DEFAULT '',
    result       text NOT NULL,
    ip           text NOT NULL DEFAULT '',
    user_agent   text NOT NULL DEFAULT ''
);
CREATE INDEX idx_auth_events_principal_id_at ON auth_events (principal_id, at DESC) WHERE principal_id IS NOT NULL;
CREATE INDEX idx_auth_events_session_id ON auth_events (session_id) WHERE session_id IS NOT NULL;

CREATE TABLE auth_throttle (
    login        text NOT NULL,
    audience     text NOT NULL,
    failures     integer NOT NULL,
    window_start timestamptz NOT NULL,
    locked_until timestamptz NULL,
    PRIMARY KEY (login, audience)
);
