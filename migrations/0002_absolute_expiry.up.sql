-- A session's absolute cap (spec §3.5): set at sign-in when the app has one
-- and never moved. Every expires_at write is clamped to it, so the existing
-- expires_at predicates enforce it unchanged.

ALTER TABLE auth_sessions ADD COLUMN absolute_expires_at timestamptz NULL;
UPDATE auth_schema SET version = 2;
