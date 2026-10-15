package nsql

import (
	"strings"
	"testing"
)

const K = "kit_ns"

func TestRewriteLeavesNames(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"CREATE INDEX auth_sessions_principal_idx ON auth_sessions (principal_id);",
			"CREATE INDEX auth_sessions_principal_idx ON kit_ns.auth_sessions (principal_id);",
		},
		{
			"CONSTRAINT auth_sessions_revoke_reason CHECK (revoke_reason IN ('user'))",
			"CONSTRAINT auth_sessions_revoke_reason CHECK (revoke_reason IN ('user'))",
		},
		{
			"SELECT to_regclass('auth_sessions')",
			"SELECT to_regclass('auth_sessions')",
		},
		{
			"SELECT x.auth_sessions FROM t x",
			"SELECT x.auth_sessions FROM t x",
		},
		{
			"CREATE POLICY auth_schema_auth ON auth_schema FOR ALL",
			"CREATE POLICY auth_schema_auth ON kit_ns.auth_schema FOR ALL",
		},
		{
			"SELECT myauth_sessions, auth_other FROM auth_tokens",
			"SELECT myauth_sessions, auth_other FROM kit_ns.auth_tokens",
		},
	}
	for _, c := range cases {
		if got := Rewrite(K, c.in); got != c.want {
			t.Errorf("Rewrite(%q):\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestRewriteQualifiesEveryTable(t *testing.T) {
	names := []string{
		"schema", "sessions", "tokens", "events", "throttle", "credentials", "passkeys",
		"passkey_ceremonies", "second_factors", "recovery_codes", "second_step_challenges",
		"email_codes", "ceremonies", "identities",
	}
	for _, n := range names {
		in := "DELETE FROM auth_" + n + " WHERE true"
		want := "DELETE FROM kit_ns.auth_" + n + " WHERE true"
		if got := Rewrite(K, in); got != want {
			t.Errorf("Rewrite(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRewriteIsIdempotent(t *testing.T) {
	once := Rewrite(K, "UPDATE auth_sessions SET x = 1 WHERE auth_sessions.id = $1")
	if want := "UPDATE kit_ns.auth_sessions SET x = 1 WHERE kit_ns.auth_sessions.id = $1"; once != want {
		t.Fatalf("Rewrite once = %q, want %q", once, want)
	}
	if twice := Rewrite(K, once); twice != once {
		t.Errorf("Rewrite is not idempotent: %q became %q", once, twice)
	}
}

func TestRewriteSkipsLiteralsAndComments(t *testing.T) {
	in := "-- the app's auth_sessions\nSELECT 'it''s auth_tokens', auth_tokens.id FROM auth_tokens;\n"
	want := "-- the app's auth_sessions\nSELECT 'it''s auth_tokens', kit_ns.auth_tokens.id FROM kit_ns.auth_tokens;\n"
	if got := Rewrite(K, in); got != want {
		t.Errorf("Rewrite:\n got %q\nwant %q", got, want)
	}
	if got := Rewrite("", in); got != in {
		t.Errorf("Rewrite with an empty schema changed the SQL: %q", got)
	}
}

func TestCheckSchemaNames(t *testing.T) {
	for _, s := range []string{"kit_ns", "_x", "customer_auth", "a" + strings.Repeat("b", 62)} {
		if err := Check(s); err != nil {
			t.Errorf("Check(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"", "Kit", "1a", "a-b", "a" + strings.Repeat("b", 63)} {
		want := `authkit: schema "` + s + `" is not a lower-case identifier of at most 63 bytes`
		if err := Check(s); err == nil || err.Error() != want {
			t.Errorf("Check(%q) = %v, want %q", s, err, want)
		}
	}
	for _, s := range []string{"public", "information_schema", "pg_temp", "pg_catalog"} {
		want := `authkit: schema "` + s + `" is reserved by PostgreSQL`
		if err := Check(s); err == nil || err.Error() != want {
			t.Errorf("Check(%q) = %v, want %q", s, err, want)
		}
	}
}
