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

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authkit_app;
