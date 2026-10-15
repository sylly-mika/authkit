ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_revoke_reason;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_revoke_reason CHECK (revoke_reason IS NULL OR revoke_reason IN ('logout', 'user', 'password_changed', 'password_reset', 'reuse_detected', 'admin', 'passkey_removed'));
ALTER TABLE auth_events DROP CONSTRAINT auth_events_second_factor;
ALTER TABLE auth_events ADD CONSTRAINT auth_events_second_factor CHECK (second_factor IN ('', 'totp', 'email', 'recovery', 'passkey'));
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_second_factor;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_second_factor CHECK (second_factor IN ('', 'totp', 'email', 'recovery', 'passkey'));
DROP TABLE auth_identities;
DROP TABLE auth_ceremonies;
UPDATE auth_schema SET version = 4;
