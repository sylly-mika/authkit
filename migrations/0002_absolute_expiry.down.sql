ALTER TABLE auth_sessions DROP COLUMN absolute_expires_at;
UPDATE auth_schema SET version = 1;
