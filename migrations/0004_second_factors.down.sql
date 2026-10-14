ALTER TABLE auth_events DROP COLUMN second_factor;
ALTER TABLE auth_sessions DROP COLUMN second_factor;
DROP TABLE auth_email_codes;
DROP TABLE auth_second_step_challenges;
DROP TABLE auth_recovery_codes;
DROP TABLE auth_second_factors;
UPDATE auth_schema SET version = 3;
