CREATE TABLE auth_second_factors (
    principal_id uuid NOT NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('totp', 'email')),
    secret       bytea NULL,
    last_step    bigint NULL,
    created_at   timestamptz NOT NULL,
    confirmed_at timestamptz NULL,
    PRIMARY KEY (principal_id, kind),
    CONSTRAINT auth_second_factors_secret CHECK ((kind = 'totp') = (secret IS NOT NULL))
);

CREATE TABLE auth_recovery_codes (
    id           uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    code_hash    bytea NOT NULL,
    used_at      timestamptz NULL,
    created_at   timestamptz NOT NULL,
    CONSTRAINT auth_recovery_codes_code UNIQUE (principal_id, code_hash)
);

CREATE TABLE auth_second_step_challenges (
    id             uuid PRIMARY KEY,
    challenge_hash bytea NOT NULL UNIQUE,
    principal_id   uuid NOT NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    audience       text NOT NULL,
    origin         text NOT NULL CHECK (origin IN ('login', 'reset')),
    throttle_key   text NOT NULL,
    tries          integer NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz NULL
);
CREATE INDEX idx_auth_second_step_challenges_principal_id ON auth_second_step_challenges (principal_id);
CREATE INDEX idx_auth_second_step_challenges_expires_at ON auth_second_step_challenges (expires_at);

CREATE TABLE auth_email_codes (
    id           uuid NOT NULL UNIQUE,
    principal_id uuid NOT NULL REFERENCES {{principals}} (id) ON DELETE CASCADE,
    purpose      text NOT NULL CHECK (purpose IN ('sign_in', 'enable', 'proof')),
    code_hash    bytea NULL,
    tries        integer NOT NULL DEFAULT 0,
    sends        integer NOT NULL DEFAULT 1,
    last_sent_at timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    PRIMARY KEY (principal_id, purpose)
);

ALTER TABLE auth_sessions ADD COLUMN second_factor text NOT NULL DEFAULT '' CONSTRAINT auth_sessions_second_factor CHECK (second_factor IN ('', 'totp', 'email', 'recovery', 'passkey'));
ALTER TABLE auth_events ADD COLUMN second_factor text NOT NULL DEFAULT '' CONSTRAINT auth_events_second_factor CHECK (second_factor IN ('', 'totp', 'email', 'recovery', 'passkey'));
UPDATE auth_schema SET version = 4;
