UPDATE auth_sessions SET revoke_reason = 'user' WHERE revoke_reason = 'passkey_removed';
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_revoke_reason;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_revoke_reason CHECK (revoke_reason IS NULL OR revoke_reason IN ('logout', 'user', 'password_changed', 'password_reset', 'reuse_detected', 'admin'));
ALTER TABLE auth_events DROP COLUMN source;
DROP TABLE auth_passkey_ceremonies;
DROP TABLE auth_passkeys;
UPDATE auth_schema SET version = 2;
