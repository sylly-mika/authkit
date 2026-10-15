CREATE TABLE auth_registrations (
    id         uuid PRIMARY KEY,
    audience   text NOT NULL,
    email      text NOT NULL,
    payload    jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    UNIQUE (audience, email)
);

CREATE TABLE auth_mail_counts (
    audience          text NOT NULL,
    email_key         bytea NOT NULL CHECK (octet_length(email_key) = 32),
    window_started_at timestamptz NOT NULL,
    sent              integer NOT NULL,
    PRIMARY KEY (audience, email_key)
);
UPDATE auth_schema SET version = 6;
