CREATE TABLE invites (
    id       uuid PRIMARY KEY,
    scope_id uuid NOT NULL
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE  ROW LEVEL SECURITY;
CREATE POLICY users_auth ON users FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY users_self ON users FOR SELECT
    USING (id = NULLIF(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE invites FORCE  ROW LEVEL SECURITY;
CREATE POLICY invites_auth ON invites FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY invites_staff ON invites FOR ALL
    USING (scope_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
           AND NULLIF(current_setting('app.principal', true), '') IN ('staff', 'system'))
    WITH CHECK (scope_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid
                AND NULLIF(current_setting('app.principal', true), '') IN ('staff', 'system'));

ALTER TABLE auth_schema ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_schema FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_schema_auth ON auth_schema FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

ALTER TABLE auth_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_credentials FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_credentials_auth ON auth_credentials FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_credentials_self ON auth_credentials FOR ALL
    USING (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
    WITH CHECK (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_sessions_auth ON auth_sessions FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_sessions_self ON auth_sessions FOR ALL
    USING (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
    WITH CHECK (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
CREATE POLICY auth_sessions_system ON auth_sessions FOR SELECT
    USING (NULLIF(current_setting('app.principal', true), '') = 'system');

ALTER TABLE auth_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_tokens FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_tokens_auth ON auth_tokens FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_tokens_invite ON auth_tokens FOR ALL
    USING (NULLIF(current_setting('app.principal', true), '') IN ('staff', 'system')
           AND purpose = 'invite' AND EXISTS (SELECT 1 FROM invites i WHERE i.id = auth_tokens.owner_id))
    WITH CHECK (NULLIF(current_setting('app.principal', true), '') IN ('staff', 'system')
                AND purpose = 'invite' AND EXISTS (SELECT 1 FROM invites i WHERE i.id = auth_tokens.owner_id));

ALTER TABLE auth_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_events FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_events_auth ON auth_events FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_events_self ON auth_events FOR SELECT
    USING (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
CREATE POLICY auth_events_self_insert ON auth_events FOR INSERT
    WITH CHECK (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE auth_throttle ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_throttle FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_throttle_auth ON auth_throttle FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

ALTER TABLE auth_passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_passkeys FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_passkeys_auth ON auth_passkeys FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_passkeys_self ON auth_passkeys FOR ALL
    USING (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
    WITH CHECK (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE auth_passkey_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_passkey_ceremonies FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_passkey_ceremonies_auth ON auth_passkey_ceremonies FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_passkey_ceremonies_self ON auth_passkey_ceremonies FOR ALL
    USING (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
    WITH CHECK (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE auth_second_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_second_factors FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_second_factors_auth ON auth_second_factors FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_second_factors_self ON auth_second_factors FOR ALL
    USING (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
    WITH CHECK (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE auth_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_recovery_codes FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_recovery_codes_auth ON auth_recovery_codes FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_recovery_codes_self ON auth_recovery_codes FOR ALL
    USING (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
    WITH CHECK (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE auth_second_step_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_second_step_challenges FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_second_step_challenges_auth ON auth_second_step_challenges FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

ALTER TABLE auth_email_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_email_codes FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_email_codes_auth ON auth_email_codes FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);
CREATE POLICY auth_email_codes_self ON auth_email_codes FOR ALL
    USING (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid)
    WITH CHECK (principal_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE auth_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_ceremonies FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_ceremonies_auth ON auth_ceremonies FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

ALTER TABLE auth_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_identities FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_identities_auth ON auth_identities FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

ALTER TABLE auth_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_registrations FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_registrations_auth ON auth_registrations FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

ALTER TABLE auth_mail_counts ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_mail_counts FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_mail_counts_auth ON auth_mail_counts FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

ALTER TABLE auth_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_invites FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_invites_auth ON auth_invites FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

ALTER TABLE auth_email_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_email_changes FORCE  ROW LEVEL SECURITY;
CREATE POLICY auth_email_changes_auth ON auth_email_changes FOR ALL
    USING (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL)
    WITH CHECK (NULLIF(current_setting('app.workspace_id', true), '')::uuid IS NULL);

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authkit_app;
