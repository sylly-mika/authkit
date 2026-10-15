package authkittest_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/migrations"
)

const kitSchema = "kit_ns"

var authTables = []string{"auth_schema", "auth_credentials", "auth_sessions", "auth_tokens", "auth_events", "auth_throttle", "auth_passkeys", "auth_passkey_ceremonies", "auth_second_factors", "auth_recovery_codes", "auth_second_step_challenges", "auth_email_codes", "auth_ceremonies", "auth_identities", "auth_registrations", "auth_mail_counts"}

func TestTheAppRoleIsANonOwnerThatCannotBypassRLS(t *testing.T) {
	d := authkittest.NewDB(t)
	var user, owner string
	var bypass bool
	if err := d.App.QueryRow(`SELECT current_user, rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&user, &bypass); err != nil {
		t.Fatal(err)
	}
	if err := d.App.QueryRow(`SELECT tableowner FROM pg_tables WHERE tablename = 'auth_sessions'`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if user != authkittest.AppRole || bypass || owner != authkittest.OwnerRole {
		t.Fatalf("app role %q (bypass %v), auth_sessions owned by %q; want %q, false, %q", user, bypass, owner, authkittest.AppRole, authkittest.OwnerRole)
	}
}

func TestEveryAuthTableHasForcedRLSAndAPrimaryKey(t *testing.T) {
	d := authkittest.NewDB(t)
	for _, table := range authTables {
		var forced, pk bool
		if err := d.Owner.QueryRow(`
			SELECT c.relrowsecurity AND c.relforcerowsecurity,
			       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary)
			  FROM pg_class c WHERE c.oid = $1::regclass`, table).Scan(&forced, &pk); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if !forced || !pk {
			t.Errorf("%s: forced RLS %v, primary key %v; want both", table, forced, pk)
		}
	}
}

const fkIndexCheck = `
WITH fks AS (
    SELECT c.conrelid, c.conname, c.conkey,
           (SELECT a.attname FROM pg_attribute a
             WHERE a.attrelid = c.conrelid AND a.attnum = c.conkey[cardinality(c.conkey)]) AS last_column
      FROM pg_constraint c
     WHERE c.contype = 'f' AND c.connamespace = 'public'::regnamespace
)
SELECT f.conrelid::regclass::text, f.conname
  FROM fks f
 WHERE NOT EXISTS (
     SELECT 1 FROM pg_index i
      WHERE i.indrelid = f.conrelid AND i.indisvalid AND i.indnkeyatts >= cardinality(f.conkey)
        AND NOT EXISTS (SELECT 1 FROM generate_subscripts(f.conkey, 1) s WHERE i.indkey[s - 1] <> f.conkey[s])
        AND (i.indpred IS NULL OR pg_get_expr(i.indpred, i.indrelid) = '(' || quote_ident(f.last_column) || ' IS NOT NULL)'))`

func TestEveryForeignKeyHasALeadingIndex(t *testing.T) {
	d := authkittest.NewDB(t)
	var fks int
	if err := d.Owner.QueryRow(`SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND conrelid::regclass::text LIKE 'auth\_%'`).Scan(&fks); err != nil || fks != 13 {
		t.Fatalf("authkit declares %d foreign keys (%v), want 13:the check below would pass vacuously", fks, err)
	}
	rows, err := d.Owner.Query(fkIndexCheck)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, fk string
		if err := rows.Scan(&table, &fk); err != nil {
			t.Fatal(err)
		}
		t.Errorf("foreign key %s on %s has no leading index (spec §6, ino-tasks sql_gates_test)", fk, table)
	}
}

func TestTokenHashesAreIndexedForEqualityLookups(t *testing.T) {
	d := authkittest.NewDB(t)
	for _, want := range []struct {
		table, column string
		unique        bool
	}{
		{"auth_sessions", "token_hash", true},
		{"auth_tokens", "token_hash", true},
		{"auth_sessions", "prev_token_hash", false},
		{"auth_passkey_ceremonies", "ceremony_hash", true},
		{"auth_passkeys", "credential_id", true},
		{"auth_second_step_challenges", "challenge_hash", true},
		{"auth_ceremonies", "state_hash", true},
	} {
		var found bool
		if err := d.Owner.QueryRow(`
			SELECT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
			                WHERE i.indrelid = $1::regclass AND a.attname = $2 AND (i.indisunique OR NOT $3))`,
			want.table, want.column, want.unique).Scan(&found); err != nil || !found {
			t.Errorf("%s(%s): no leading index (unique %v) (%v); spec §8.6 needs indexed sha256 equality", want.table, want.column, want.unique, err)
		}
	}
}

func TestAPinnedPrincipalSeesOnlyItsOwnSessions(t *testing.T) {
	d := authkittest.NewDB(t)
	scope := uuid.New()
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	insert := `INSERT INTO auth_sessions (id, principal_id, audience, scope_id, token_hash, authenticated_at, created_at, expires_at)
	           VALUES ($1, $2, 'staff', $3, $4, now(), now(), now() + interval '1 day')`
	sa, sb := uuid.New(), uuid.New()
	d.Exec(t, insert, sa, a, scope, []byte("token-a"))
	d.Exec(t, insert, sb, b, scope, []byte("token-b"))
	conn := d.Pinned(t, a, scope, "staff")
	for id, want := range map[uuid.UUID]int{sa: 1, sb: 0} {
		var n int
		if err := conn.QueryRowContext(context.Background(), `SELECT count(*) FROM auth_sessions WHERE id = $1`, id).Scan(&n); err != nil || n != want {
			t.Errorf("A counts %d of session %s (%v), want %d", n, id, err, want)
		}
	}
}

func TestTheDownMigrationsRemoveEverything(t *testing.T) {
	d := authkittest.NewDB(t)
	all := migrations.All()
	for i := len(all) - 1; i >= 0; i-- {
		down, err := migrations.Render(all[i].Down, "users")
		if err != nil {
			t.Fatal(err)
		}
		d.Exec(t, down)
	}
	var left int
	if err := d.Owner.QueryRow(`SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'auth\_%'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d auth_* tables survive the down migrations (%v)", left, err)
	}
}

const insertPasskeySQL = `INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, $4, '{}', now())`

const insertCeremonySQL = `INSERT INTO auth_passkey_ceremonies (id, ceremony_hash, kind, audience, principal_id, session_id, data, expires_at) VALUES ($1, $2, $3, 'staff', $4, $5, '{}', now() + interval '2 minutes')`

const insertFactorSQL = `INSERT INTO auth_second_factors (principal_id, kind, secret, created_at) VALUES ($1, $2, $3, now())`

const insertRecoveryCodeSQL = `INSERT INTO auth_recovery_codes (id, principal_id, code_hash, created_at) VALUES ($1, $2, $3, now())`

const insertChallengeSQL = `INSERT INTO auth_second_step_challenges (id, challenge_hash, principal_id, audience, origin, throttle_key, created_at, expires_at) VALUES ($1, $2, $3, 'staff', $4, 'a@example.invalid', now(), now() + interval '10 minutes')`

const insertEmailCodeSQL = `INSERT INTO auth_email_codes (id, principal_id, purpose, last_sent_at, expires_at) VALUES ($1, $2, $3, now(), now() + interval '10 minutes')`

const insertOIDCCeremonySQL = `INSERT INTO auth_ceremonies (id, kind, provider, audience, state_hash, binding_hash, nonce_hash, principal_id, created_at, expires_at) VALUES ($1, $2, 'google', 'staff', $3, $4, $5, $6, now(), now() + interval '10 minutes')`

const insertIdentitySQL = `INSERT INTO auth_identities (id, principal_id, provider, subject, email, created_at) VALUES ($1, $2, $3, $4, 'a@example.invalid', now())`

const insertRegistrationSQL = `INSERT INTO auth_registrations (id, audience, email, created_at, expires_at) VALUES ($1, 'staff', $2, now(), now() + interval '1 day')`

const upsertMailCountSQL = `INSERT INTO auth_mail_counts (audience, email_key, window_started_at, sent) VALUES ('staff', $1, now(), 1) ON CONFLICT (audience, email_key) DO UPDATE SET sent = auth_mail_counts.sent + 1`

var secondFactorTables = []string{"auth_second_factors", "auth_recovery_codes", "auth_second_step_challenges", "auth_email_codes"}

func seedSecondFactorRows(t *testing.T, d *authkittest.DB, p uuid.UUID) {
	t.Helper()
	wantOK(t, "a factor", exec(d, insertFactorSQL, p, "totp", []byte("sealed")))
	wantOK(t, "a recovery code", exec(d, insertRecoveryCodeSQL, uuid.New(), p, hash()))
	wantOK(t, "a challenge", exec(d, insertChallengeSQL, uuid.New(), hash(), p, "login"))
	wantOK(t, "an email code", exec(d, insertEmailCodeSQL, uuid.New(), p, "sign_in"))
}

func pgCode(err error) string {
	var pe *pq.Error
	if errors.As(err, &pe) {
		return string(pe.Code)
	}
	return ""
}

func exec(d *authkittest.DB, q string, args ...any) error {
	_, err := d.Owner.ExecContext(context.Background(), q, args...)
	return err
}

func wantOK(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: SQLSTATE %q, want no error", what, pgCode(err))
	}
}

func wantCode(t *testing.T, what string, err error, want string) {
	t.Helper()
	if got := pgCode(err); got != want {
		t.Errorf("%s: SQLSTATE %q, want %q", what, got, want)
	}
}

func count(t *testing.T, d *authkittest.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := d.Row(t, q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func hash() []byte {
	h := uuid.New()
	return h[:]
}

func hash32() []byte {
	h := sha256.Sum256([]byte(uuid.NewString()))
	return h[:]
}

func pgConstraint(err error) string {
	var pe *pq.Error
	if errors.As(err, &pe) {
		return pe.Constraint
	}
	return ""
}

func migrationByID(t *testing.T, id int) migrations.Migration {
	t.Helper()
	for _, m := range migrations.All() {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("no migration %04d", id)
	return migrations.Migration{}
}

func newSession(t *testing.T, d *authkittest.DB, principal uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	d.Exec(t, `INSERT INTO auth_sessions (id, principal_id, audience, scope_id, token_hash, authenticated_at, created_at, expires_at)
	           VALUES ($1, $2, 'staff', $3, $4, now(), now(), now() + interval '1 day')`, id, principal, uuid.New(), id[:])
	return id
}

func TestPasskeyRowsKeepTheirShape(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	wantCode(t, "an empty label", exec(d, insertPasskeySQL, uuid.New(), a, []byte("cred-0"), ""), "23514")
	wantCode(t, "a 65-character label", exec(d, insertPasskeySQL, uuid.New(), a, []byte("cred-65"), strings.Repeat("é", 65)), "23514")
	wantOK(t, "a 64-character label", exec(d, insertPasskeySQL, uuid.New(), a, []byte("cred-1"), strings.Repeat("é", 64)))
	wantCode(t, "a second passkey with the same credential", exec(d, insertPasskeySQL, uuid.New(), a, []byte("cred-1"), "Laptop"), "23505")
	if n := count(t, d, `SELECT count(*) FROM auth_passkeys`); n != 1 {
		t.Errorf("auth_passkeys holds %d rows, want 1", n)
	}
}

func TestCeremonyRowsBindKindToOwner(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	s := newSession(t, d, a)
	loginHash := hash()
	wantOK(t, "a login ceremony", exec(d, insertCeremonySQL, uuid.New(), loginHash, "login", nil, nil))
	wantOK(t, "a register ceremony", exec(d, insertCeremonySQL, uuid.New(), hash(), "register", a, s))
	for _, c := range []struct {
		what, kind         string
		principal, session any
	}{
		{"a login with a principal", "login", a, nil},
		{"a login with a session", "login", nil, s},
		{"a register without a session", "register", a, nil},
		{"a register without a principal", "register", nil, s},
		{"an unknown kind", "other", nil, nil},
	} {
		wantCode(t, c.what, exec(d, insertCeremonySQL, uuid.New(), hash(), c.kind, c.principal, c.session), "23514")
	}
	wantCode(t, "a second ceremony with the same hash", exec(d, insertCeremonySQL, uuid.New(), loginHash, "login", nil, nil), "23505")
	if n := count(t, d, `SELECT count(*) FROM auth_passkey_ceremonies`); n != 2 {
		t.Errorf("auth_passkey_ceremonies holds %d rows, want 2", n)
	}
}

func TestPasskeyRowsGoWithTheirOwner(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	s1, s2 := newSession(t, d, a), newSession(t, d, a)
	wantOK(t, "a passkey", exec(d, insertPasskeySQL, uuid.New(), a, []byte("cred-cascade"), "Laptop"))
	c1, c2 := uuid.New(), uuid.New()
	wantOK(t, "ceremony c1", exec(d, insertCeremonySQL, c1, hash(), "register", a, s1))
	wantOK(t, "ceremony c2", exec(d, insertCeremonySQL, c2, hash(), "register", a, s2))
	d.Exec(t, `DELETE FROM auth_sessions WHERE id = $1`, s1)
	if n := count(t, d, `SELECT count(*) FROM auth_passkey_ceremonies WHERE id = $1`, c1); n != 0 {
		t.Errorf("ceremony of a deleted session survives (%d rows)", n)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_passkey_ceremonies WHERE id = $1`, c2); n != 1 {
		t.Errorf("ceremony of another session has %d rows, want 1", n)
	}
	d.Exec(t, `DELETE FROM users WHERE id = $1`, a)
	if n := count(t, d, `SELECT count(*) FROM auth_passkeys`); n != 0 {
		t.Errorf("auth_passkeys holds %d rows after the principal is deleted, want 0", n)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_passkey_ceremonies`); n != 0 {
		t.Errorf("auth_passkey_ceremonies holds %d rows after the principal is deleted, want 0", n)
	}
}

func TestASessionMayBeRevokedForARemovedPasskey(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	s1, s2, s3 := newSession(t, d, a), newSession(t, d, a), newSession(t, d, a)
	const revoke = `UPDATE auth_sessions SET revoked_at = now(), revoke_reason = $2 WHERE id = $1`
	wantOK(t, "a session revoked for a removed passkey", exec(d, revoke, s1, "passkey_removed"))
	var reason string
	if err := d.Row(t, `SELECT revoke_reason FROM auth_sessions WHERE id = $1`, s1).Scan(&reason); err != nil || reason != "passkey_removed" {
		t.Errorf("revoke_reason = %q (%v), want passkey_removed", reason, err)
	}
	wantOK(t, "a session revoked by an admin", exec(d, revoke, s2, "admin"))
	wantCode(t, "an unknown revoke reason", exec(d, revoke, s3, "bogus"), "23514")
}

func TestAuthEventsSourceDefaultsToEmpty(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	wantOK(t, "an event without a source", exec(d, `INSERT INTO auth_events (id, at, principal_id, audience, result) VALUES ($1, now(), $2, 'staff', 'signed_in')`, uuid.New(), a))
	var source string
	if err := d.Row(t, `SELECT source FROM auth_events WHERE principal_id = $1 AND source = ''`, a).Scan(&source); err != nil {
		t.Errorf("the event without a source reads %v, want an empty source", err)
	}
	named := uuid.New()
	wantOK(t, "an event with a source", exec(d, `INSERT INTO auth_events (id, at, principal_id, audience, result, source) VALUES ($1, now(), $2, 'staff', 'signed_in', 'passkey_login')`, named, a))
	if err := d.Row(t, `SELECT source FROM auth_events WHERE id = $1`, named).Scan(&source); err != nil || source != "passkey_login" {
		t.Errorf("source = %q (%v), want passkey_login", source, err)
	}
}

func TestAPinnedPrincipalSeesOnlyItsOwnPasskeys(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	pa, pb := uuid.New(), uuid.New()
	wantOK(t, "a's passkey", exec(d, insertPasskeySQL, pa, a, []byte("cred-a"), "Laptop"))
	wantOK(t, "b's passkey", exec(d, insertPasskeySQL, pb, b, []byte("cred-b"), "Laptop"))
	conn := d.Pinned(t, a, uuid.New(), "staff")
	ctx := context.Background()
	for id, want := range map[uuid.UUID]int{pa: 1, pb: 0} {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM auth_passkeys WHERE id = $1`, id).Scan(&n); err != nil || n != want {
			t.Errorf("A counts %d of passkey %s (%v), want %d", n, id, err, want)
		}
	}
	res, err := conn.ExecContext(ctx, `UPDATE auth_passkeys SET label = 'x' WHERE id = $1`, pb)
	if err != nil {
		t.Fatalf("A updates B's passkey: SQLSTATE %q", pgCode(err))
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("A updated %d of B's passkeys, want 0", n)
	}
	_, err = conn.ExecContext(ctx, insertPasskeySQL, uuid.New(), b, []byte("cred-b2"), "Phone")
	wantCode(t, "A adds a passkey for B", err, "42501")
	var label string
	if err := d.Row(t, `SELECT label FROM auth_passkeys WHERE id = $1`, pb).Scan(&label); err != nil || label != "Laptop" {
		t.Errorf("B's passkey label = %q (%v), want Laptop", label, err)
	}
}

func TestAPinnedPrincipalSeesOnlyItsOwnCeremonies(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	sa, sb := newSession(t, d, a), newSession(t, d, b)
	ca, cb, cl := uuid.New(), uuid.New(), uuid.New()
	wantOK(t, "A's ceremony", exec(d, insertCeremonySQL, ca, hash(), "register", a, sa))
	wantOK(t, "B's ceremony", exec(d, insertCeremonySQL, cb, hash(), "register", b, sb))
	wantOK(t, "a login ceremony", exec(d, insertCeremonySQL, cl, hash(), "login", nil, nil))
	conn := d.Pinned(t, a, uuid.New(), "staff")
	ctx := context.Background()
	for id, want := range map[uuid.UUID]int{ca: 1, cb: 0, cl: 0} {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM auth_passkey_ceremonies WHERE id = $1`, id).Scan(&n); err != nil || n != want {
			t.Errorf("A counts %d of ceremony %s (%v), want %d", n, id, err, want)
		}
	}
	res, err := conn.ExecContext(ctx, `UPDATE auth_passkey_ceremonies SET used_at = now() WHERE id = $1`, cb)
	if err != nil {
		t.Fatalf("A updates B's ceremony: SQLSTATE %q", pgCode(err))
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("A updated %d of B's ceremonies, want 0", n)
	}
}

func TestTheAppRoleWithoutAWorkspaceReachesPasskeys(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	ctx := context.Background()
	_, err := d.App.ExecContext(ctx, insertPasskeySQL, uuid.New(), a, []byte("cred-app"), "Laptop")
	wantOK(t, "the app adds a passkey", err)
	if n := count(t, d, `SELECT count(*) FROM auth_passkeys WHERE credential_id = $1`, []byte("cred-app")); n != 1 {
		t.Errorf("the app sees %d passkeys of the new credential, want 1", n)
	}
	res, err := d.App.ExecContext(ctx, `UPDATE auth_passkeys SET last_used_at = now() WHERE credential_id = $1`, []byte("cred-app"))
	wantOK(t, "the app marks the passkey used", err)
	if n, _ := res.RowsAffected(); n != 1 {
		t.Errorf("the app marked %d passkeys used, want 1", n)
	}
}

func TestTheAppRoleWithoutAWorkspaceReachesCeremonies(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	h := hash()
	_, err := d.App.ExecContext(ctx, insertCeremonySQL, uuid.New(), h, "login", nil, nil)
	wantOK(t, "the app begins a login ceremony", err)
	res, err := d.App.ExecContext(ctx, `UPDATE auth_passkey_ceremonies SET used_at = now() WHERE ceremony_hash = $1 AND used_at IS NULL`, h)
	wantOK(t, "the app finishes the ceremony", err)
	if n, _ := res.RowsAffected(); n != 1 {
		t.Errorf("the first finish marked %d ceremonies used, want 1", n)
	}
	res, err = d.App.ExecContext(ctx, `UPDATE auth_passkey_ceremonies SET used_at = now() WHERE ceremony_hash = $1 AND used_at IS NULL`, h)
	wantOK(t, "the app finishes the ceremony again", err)
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("the second finish marked %d ceremonies used, want 0", n)
	}
}

func TestTheDownMigration0003RestoresVersion2(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	s := newSession(t, d, a)
	d.Exec(t, `UPDATE auth_sessions SET revoked_at = now(), revoke_reason = 'passkey_removed' WHERE id = $1`, s)
	wantOK(t, "a passkey", exec(d, insertPasskeySQL, uuid.New(), a, []byte("cred-down"), "Laptop"))
	var m3 migrations.Migration
	found := false
	for _, m := range migrations.All() {
		if m.ID == 3 {
			m3, found = m, true
		}
	}
	if !found {
		t.Fatal("no migration 0003")
	}
	down, err := migrations.Render(m3.Down, "users")
	if err != nil {
		t.Fatal(err)
	}
	d.Exec(t, down)
	var passkeysGone, ceremoniesGone bool
	if err := d.Row(t, `SELECT to_regclass('auth_passkeys') IS NULL, to_regclass('auth_passkey_ceremonies') IS NULL`).Scan(&passkeysGone, &ceremoniesGone); err != nil || !passkeysGone || !ceremoniesGone {
		t.Errorf("after the down: passkey tables gone %v and %v (%v), want both", passkeysGone, ceremoniesGone, err)
	}
	if n := count(t, d, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'auth_events' AND column_name = 'source'`); n != 0 {
		t.Errorf("auth_events.source survives the down (%d columns)", n)
	}
	var reason string
	if err := d.Row(t, `SELECT revoke_reason FROM auth_sessions WHERE id = $1`, s).Scan(&reason); err != nil || reason != "user" {
		t.Errorf("the passkey_removed session reads %q (%v) after the down, want user", reason, err)
	}
	wantCode(t, "passkey_removed after the down", exec(d, `UPDATE auth_sessions SET revoke_reason = 'passkey_removed' WHERE id = $1`, s), "23514")
	if n := count(t, d, `SELECT version FROM auth_schema`); n != 2 {
		t.Errorf("schema version after the down = %d, want 2", n)
	}
	up, err := migrations.Render(m3.Up, "users")
	if err != nil {
		t.Fatal(err)
	}
	d.Exec(t, up)
	if n := count(t, d, `SELECT version FROM auth_schema`); n != 3 {
		t.Errorf("schema version after the up = %d, want 3", n)
	}
	if err := d.Row(t, `SELECT to_regclass('auth_passkeys') IS NOT NULL, to_regclass('auth_passkey_ceremonies') IS NOT NULL`).Scan(&passkeysGone, &ceremoniesGone); err != nil || !passkeysGone || !ceremoniesGone {
		t.Errorf("after the up: passkey tables present %v and %v (%v), want both", passkeysGone, ceremoniesGone, err)
	}
}

func TestSecondFactorRowsKeepTheirShape(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	wantOK(t, "a totp factor with a secret", exec(d, insertFactorSQL, a, "totp", []byte("sealed")))
	wantOK(t, "an email factor without a secret", exec(d, insertFactorSQL, a, "email", nil))
	wantCode(t, "a totp factor without a secret", exec(d, insertFactorSQL, b, "totp", nil), "23514")
	wantCode(t, "an email factor with a secret", exec(d, insertFactorSQL, b, "email", []byte("sealed")), "23514")
	wantCode(t, "an unknown kind", exec(d, insertFactorSQL, b, "sms", nil), "23514")
	wantCode(t, "a second totp factor for A", exec(d, insertFactorSQL, a, "totp", []byte("other")), "23505")
	if n := count(t, d, `SELECT count(*) FROM auth_second_factors`); n != 2 {
		t.Errorf("auth_second_factors holds %d rows, want 2", n)
	}
}

func TestRecoveryCodeHashesAreUniquePerPrincipal(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	h := hash()
	wantOK(t, "A's recovery code", exec(d, insertRecoveryCodeSQL, uuid.New(), a, h))
	wantCode(t, "A's recovery code again", exec(d, insertRecoveryCodeSQL, uuid.New(), a, h), "23505")
	wantOK(t, "B's recovery code with the same hash", exec(d, insertRecoveryCodeSQL, uuid.New(), b, h))
	if n := count(t, d, `SELECT count(*) FROM auth_recovery_codes`); n != 2 {
		t.Errorf("auth_recovery_codes holds %d rows, want 2", n)
	}
}

func TestSecondStepChallengeRowsKeepTheirShape(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	c1, h1 := uuid.New(), hash()
	wantOK(t, "a login challenge", exec(d, insertChallengeSQL, c1, h1, a, "login"))
	wantOK(t, "a reset challenge", exec(d, insertChallengeSQL, uuid.New(), hash(), a, "reset"))
	wantCode(t, "a challenge for a passkey", exec(d, insertChallengeSQL, uuid.New(), hash(), a, "passkey"), "23514")
	wantCode(t, "a challenge with a used hash", exec(d, insertChallengeSQL, uuid.New(), h1, b, "login"), "23505")
	var tries int
	if err := d.Row(t, `SELECT tries FROM auth_second_step_challenges WHERE id = $1`, c1).Scan(&tries); err != nil || tries != 0 {
		t.Errorf("tries = %d (%v), want 0", tries, err)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_second_step_challenges`); n != 2 {
		t.Errorf("auth_second_step_challenges holds %d rows, want 2", n)
	}
}

func TestEmailCodeRowsKeepOnePerPurpose(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	e1 := uuid.New()
	wantOK(t, "a sign-in code", exec(d, insertEmailCodeSQL, e1, a, "sign_in"))
	var noHash bool
	var tries, sends int
	if err := d.Row(t, `SELECT code_hash IS NULL, tries, sends FROM auth_email_codes WHERE id = $1`, e1).Scan(&noHash, &tries, &sends); err != nil || !noHash || tries != 0 || sends != 1 {
		t.Errorf("new code reads hash-less %v, tries %d, sends %d (%v), want true, 0, 1", noHash, tries, sends, err)
	}
	wantCode(t, "a second sign-in code", exec(d, insertEmailCodeSQL, uuid.New(), a, "sign_in"), "23505")
	wantOK(t, "an enable code", exec(d, insertEmailCodeSQL, uuid.New(), a, "enable"))
	wantCode(t, "a code for an unknown purpose", exec(d, insertEmailCodeSQL, uuid.New(), a, "reset"), "23514")
	wantCode(t, "a proof code with the first code's id", exec(d, insertEmailCodeSQL, e1, a, "proof"), "23505")
	if n := count(t, d, `SELECT count(*) FROM auth_email_codes`); n != 2 {
		t.Errorf("auth_email_codes holds %d rows, want 2", n)
	}
}

func TestSessionsAndEventsRecordTheSecondFactor(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	s := newSession(t, d, a)
	var factor string
	if err := d.Row(t, `SELECT second_factor FROM auth_sessions WHERE id = $1`, s).Scan(&factor); err != nil || factor != "" {
		t.Errorf("a new session's second_factor = %q (%v), want empty", factor, err)
	}
	for _, f := range []string{"totp", "email", "recovery", "passkey"} {
		wantOK(t, "a session with "+f, exec(d, `UPDATE auth_sessions SET second_factor = $2 WHERE id = $1`, s, f))
	}
	wantCode(t, "a session with sms", exec(d, `UPDATE auth_sessions SET second_factor = $2 WHERE id = $1`, s, "sms"), "23514")
	const insertEvent = `INSERT INTO auth_events (id, at, principal_id, audience, result) VALUES ($1, now(), $2, 'staff', 'signed_in')`
	plain := uuid.New()
	wantOK(t, "an event without a factor", exec(d, insertEvent, plain, a))
	if err := d.Row(t, `SELECT second_factor FROM auth_events WHERE id = $1`, plain).Scan(&factor); err != nil || factor != "" {
		t.Errorf("an event without a factor reads %q (%v), want empty", factor, err)
	}
	wantOK(t, "an event with recovery", exec(d, `INSERT INTO auth_events (id, at, principal_id, audience, result, second_factor) VALUES ($1, now(), $2, 'staff', 'signed_in', 'recovery')`, uuid.New(), a))
	wantCode(t, "an event with sms", exec(d, `INSERT INTO auth_events (id, at, principal_id, audience, result, second_factor) VALUES ($1, now(), $2, 'staff', 'signed_in', 'sms')`, uuid.New(), a), "23514")
}

func TestSecondFactorTablesHoldNoPlaintextColumn(t *testing.T) {
	d := authkittest.NewDB(t)
	rows, err := d.Owner.Query(`
		SELECT concat_ws(' ', table_name || '.' || column_name, data_type, is_nullable, column_default)
		  FROM information_schema.columns
		 WHERE table_schema = 'public' AND (table_name = ANY($1) OR column_name = 'second_factor')
		 ORDER BY table_name COLLATE "C", ordinal_position`, pq.Array(secondFactorTables))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		got = append(got, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"auth_email_codes.id uuid NO",
		"auth_email_codes.principal_id uuid NO",
		"auth_email_codes.purpose text NO",
		"auth_email_codes.code_hash bytea YES",
		"auth_email_codes.tries integer NO 0",
		"auth_email_codes.sends integer NO 1",
		"auth_email_codes.last_sent_at timestamp with time zone NO",
		"auth_email_codes.expires_at timestamp with time zone NO",
		"auth_events.second_factor text NO ''::text",
		"auth_recovery_codes.id uuid NO",
		"auth_recovery_codes.principal_id uuid NO",
		"auth_recovery_codes.code_hash bytea NO",
		"auth_recovery_codes.used_at timestamp with time zone YES",
		"auth_recovery_codes.created_at timestamp with time zone NO",
		"auth_second_factors.principal_id uuid NO",
		"auth_second_factors.kind text NO",
		"auth_second_factors.secret bytea YES",
		"auth_second_factors.last_step bigint YES",
		"auth_second_factors.created_at timestamp with time zone NO",
		"auth_second_factors.confirmed_at timestamp with time zone YES",
		"auth_second_step_challenges.id uuid NO",
		"auth_second_step_challenges.challenge_hash bytea NO",
		"auth_second_step_challenges.principal_id uuid NO",
		"auth_second_step_challenges.audience text NO",
		"auth_second_step_challenges.origin text NO",
		"auth_second_step_challenges.throttle_key text NO",
		"auth_second_step_challenges.tries integer NO 0",
		"auth_second_step_challenges.created_at timestamp with time zone NO",
		"auth_second_step_challenges.expires_at timestamp with time zone NO",
		"auth_second_step_challenges.used_at timestamp with time zone YES",
		"auth_sessions.second_factor text NO ''::text",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the second-factor columns are\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSecondFactorRowsGoWithTheirOwner(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	seedSecondFactorRows(t, d, a)
	seedSecondFactorRows(t, d, b)
	d.Exec(t, `DELETE FROM users WHERE id = $1`, a)
	for _, table := range secondFactorTables {
		if n := count(t, d, `SELECT count(*) FROM `+table+` WHERE principal_id = $1`, a); n != 0 {
			t.Errorf("%s holds %d rows of the deleted principal, want 0", table, n)
		}
		if n := count(t, d, `SELECT count(*) FROM `+table); n != 1 {
			t.Errorf("%s holds %d rows after the delete, want 1", table, n)
		}
	}
}

func TestAPinnedPrincipalSeesOnlyItsOwnSecondFactors(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	seedSecondFactorRows(t, d, a)
	seedSecondFactorRows(t, d, b)
	conn := d.Pinned(t, a, uuid.New(), "staff")
	ctx := context.Background()
	for _, c := range []struct {
		table string
		owner uuid.UUID
		want  int
	}{
		{"auth_second_factors", a, 1},
		{"auth_second_factors", b, 0},
		{"auth_recovery_codes", a, 1},
		{"auth_recovery_codes", b, 0},
		{"auth_second_step_challenges", a, 0},
		{"auth_second_step_challenges", b, 0},
		{"auth_email_codes", a, 1},
		{"auth_email_codes", b, 0},
	} {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM `+c.table+` WHERE principal_id = $1`, c.owner).Scan(&n); err != nil || n != c.want {
			t.Errorf("A counts %d rows of %s for %s (%v), want %d", n, c.table, c.owner, err, c.want)
		}
	}
	res, err := conn.ExecContext(ctx, `UPDATE auth_second_factors SET last_step = 1 WHERE principal_id = $1`, b)
	if err != nil {
		t.Fatalf("A updates B's factor: SQLSTATE %q", pgCode(err))
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("A updated %d of B's factors, want 0", n)
	}
	_, err = conn.ExecContext(ctx, insertFactorSQL, b, "email", nil)
	wantCode(t, "A adds a factor for B", err, "42501")
	_, err = conn.ExecContext(ctx, insertRecoveryCodeSQL, uuid.New(), b, hash())
	wantCode(t, "A adds a recovery code for B", err, "42501")
	var lastStepNull bool
	if err := d.Row(t, `SELECT last_step IS NULL FROM auth_second_factors WHERE principal_id = $1`, b).Scan(&lastStepNull); err != nil || !lastStepNull {
		t.Errorf("B's factor has last_step NULL = %v (%v), want true", lastStepNull, err)
	}
}

func TestTheAppRoleWithoutAWorkspaceReachesSecondFactorTables(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	ctx := context.Background()
	h, e := hash(), uuid.New()
	_, err := d.App.ExecContext(ctx, insertFactorSQL, a, "totp", []byte("sealed"))
	wantOK(t, "the app adds a factor", err)
	_, err = d.App.ExecContext(ctx, insertRecoveryCodeSQL, uuid.New(), a, hash())
	wantOK(t, "the app adds a recovery code", err)
	_, err = d.App.ExecContext(ctx, insertChallengeSQL, uuid.New(), h, a, "login")
	wantOK(t, "the app adds a challenge", err)
	_, err = d.App.ExecContext(ctx, insertEmailCodeSQL, e, a, "sign_in")
	wantOK(t, "the app adds an email code", err)
	res, err := d.App.ExecContext(ctx, `UPDATE auth_second_step_challenges SET tries = tries + 1 WHERE challenge_hash = $1`, h)
	wantOK(t, "the app counts a challenge try", err)
	if n, _ := res.RowsAffected(); n != 1 {
		t.Errorf("the app counted tries on %d challenges, want 1", n)
	}
	res, err = d.App.ExecContext(ctx, `UPDATE auth_email_codes SET code_hash = $2 WHERE id = $1`, e, hash())
	wantOK(t, "the app stores an email code hash", err)
	if n, _ := res.RowsAffected(); n != 1 {
		t.Errorf("the app stored %d email code hashes, want 1", n)
	}
	res, err = d.App.ExecContext(ctx, `DELETE FROM auth_recovery_codes WHERE principal_id = $1`, a)
	wantOK(t, "the app deletes a recovery code", err)
	if n, _ := res.RowsAffected(); n != 1 {
		t.Errorf("the app deleted %d recovery codes, want 1", n)
	}
}

func TestTheDownMigration0004RestoresVersion3(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	seedSecondFactorRows(t, d, a)
	s := newSession(t, d, a)
	d.Exec(t, `UPDATE auth_sessions SET second_factor = 'totp' WHERE id = $1`, s)
	wantOK(t, "an event with a factor", exec(d, `INSERT INTO auth_events (id, at, principal_id, audience, result, second_factor) VALUES ($1, now(), $2, 'staff', 'signed_in', 'email')`, uuid.New(), a))
	var m4 migrations.Migration
	found := false
	for _, m := range migrations.All() {
		if m.ID == 4 {
			m4, found = m, true
		}
	}
	if !found {
		t.Fatal("no migration 0004")
	}
	down, err := migrations.Render(m4.Down, "users")
	if err != nil {
		t.Fatal(err)
	}
	d.Exec(t, down)
	for _, table := range secondFactorTables {
		var gone bool
		if err := d.Row(t, `SELECT to_regclass($1) IS NULL`, table).Scan(&gone); err != nil || !gone {
			t.Errorf("after the down: %s present (gone %v, %v), want absent", table, gone, err)
		}
	}
	if n := count(t, d, `SELECT count(*) FROM information_schema.columns WHERE column_name = 'second_factor' AND table_name IN ('auth_sessions', 'auth_events')`); n != 0 {
		t.Errorf("second_factor survives the down on %d tables", n)
	}
	if n := count(t, d, `SELECT version FROM auth_schema`); n != 3 {
		t.Errorf("schema version after the down = %d, want 3", n)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_sessions WHERE id = $1`, s); n != 1 {
		t.Errorf("the session survives the down %d times, want 1", n)
	}
	up, err := migrations.Render(m4.Up, "users")
	if err != nil {
		t.Fatal(err)
	}
	d.Exec(t, up)
	if n := count(t, d, `SELECT version FROM auth_schema`); n != 4 {
		t.Errorf("schema version after the up = %d, want 4", n)
	}
	for _, table := range secondFactorTables {
		var present bool
		if err := d.Row(t, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present); err != nil || !present {
			t.Errorf("after the up: %s absent (present %v, %v), want present", table, present, err)
		}
	}
	var factor string
	if err := d.Row(t, `SELECT second_factor FROM auth_sessions WHERE id = $1`, s).Scan(&factor); err != nil || factor != "" {
		t.Errorf("the session's second_factor after the up = %q (%v), want empty", factor, err)
	}
}

func TestSessionsAndEventsAcceptOIDC(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	s1, s2 := newSession(t, d, a), newSession(t, d, a)
	wantOK(t, "a session with oidc", exec(d, `UPDATE auth_sessions SET second_factor = $2 WHERE id = $1`, s1, "oidc"))
	var factor string
	if err := d.Row(t, `SELECT second_factor FROM auth_sessions WHERE id = $1`, s1).Scan(&factor); err != nil || factor != "oidc" {
		t.Errorf("the oidc session reads %q (%v), want oidc", factor, err)
	}
	const insertEvent = `INSERT INTO auth_events (id, at, principal_id, audience, result, second_factor) VALUES ($1, now(), $2, 'staff', 'signed_in', $3)`
	wantOK(t, "an event with oidc", exec(d, insertEvent, uuid.New(), a, "oidc"))
	wantOK(t, "a session revoked for a removed identity", exec(d, `UPDATE auth_sessions SET revoked_at = now(), revoke_reason = $2 WHERE id = $1`, s2, "identity_removed"))
	var reason string
	if err := d.Row(t, `SELECT revoke_reason FROM auth_sessions WHERE id = $1`, s2).Scan(&reason); err != nil || reason != "identity_removed" {
		t.Errorf("the identity_removed session reads %q (%v), want identity_removed", reason, err)
	}
	wantCode(t, "a session revoked for a removed provider", exec(d, `UPDATE auth_sessions SET revoked_at = now(), revoke_reason = $2 WHERE id = $1`, s1, "provider_removed"), "23514")
	wantCode(t, "an event with google", exec(d, insertEvent, uuid.New(), a, "google"), "23514")
}

func TestOIDCCeremonyRowsKeepTheirShape(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	ins := func(kind string, state, binding, nonce, principal any) error {
		return exec(d, insertOIDCCeremonySQL, uuid.New(), kind, state, binding, nonce, principal)
	}
	st := hash32()
	wantOK(t, "a signin ceremony", ins("signin", st, hash32(), hash32(), nil))
	wantOK(t, "a signup ceremony", ins("signup", hash32(), nil, nil, nil))
	wantOK(t, "a link ceremony", ins("link", hash32(), hash32(), hash32(), a))
	wantCode(t, "a kind outside the three", ins("login", hash32(), hash32(), hash32(), nil), "23514")
	wantCode(t, "a 16-byte state", ins("signin", hash(), hash32(), hash32(), nil), "23514")
	wantCode(t, "a 16-byte binding", ins("signin", hash32(), hash(), hash32(), nil), "23514")
	wantCode(t, "a 16-byte nonce", ins("signin", hash32(), hash32(), hash(), nil), "23514")
	wantCode(t, "a link without a principal", ins("link", hash32(), hash32(), hash32(), nil), "23514")
	wantCode(t, "a signin with a principal", ins("signin", hash32(), hash32(), hash32(), a), "23514")
	err := ins("signin", st, hash32(), hash32(), nil)
	wantCode(t, "a second ceremony for one state", err, "23505")
	if got := pgConstraint(err); got != "auth_ceremonies_state_hash_key" {
		t.Errorf("the duplicate state hit %q, want auth_ceremonies_state_hash_key", got)
	}
	var profile string
	if err := d.Row(t, `SELECT profile::text FROM auth_ceremonies WHERE kind = 'signup'`).Scan(&profile); err != nil || profile != "{}" {
		t.Errorf("the signup ceremony's profile = %q (%v), want {}", profile, err)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_ceremonies`); n != 3 {
		t.Errorf("%d ceremonies, want 3", n)
	}
}

func TestIdentitiesAreUniquePerSubjectAndPerProvider(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	wantOK(t, "a's google identity", exec(d, insertIdentitySQL, uuid.New(), a, "google", "sub-1"))
	err := exec(d, insertIdentitySQL, uuid.New(), b, "google", "sub-1")
	wantCode(t, "a google subject for a second principal", err, "23505")
	if got := pgConstraint(err); got != "auth_identities_subject" {
		t.Errorf("the shared subject hit %q, want auth_identities_subject", got)
	}
	err = exec(d, insertIdentitySQL, uuid.New(), a, "google", "sub-2")
	wantCode(t, "a second google identity for a", err, "23505")
	if got := pgConstraint(err); got != "auth_identities_principal" {
		t.Errorf("the second google identity hit %q, want auth_identities_principal", got)
	}
	wantOK(t, "a's apple identity", exec(d, insertIdentitySQL, uuid.New(), a, "apple", "sub-1"))
	wantOK(t, "b's google identity", exec(d, insertIdentitySQL, uuid.New(), b, "google", "sub-2"))
	if n := count(t, d, `SELECT count(*) FROM auth_identities`); n != 3 {
		t.Errorf("%d identities, want 3", n)
	}
}

func TestRegistrationsAndMailCountsKeepOneRowPerKey(t *testing.T) {
	d := authkittest.NewDB(t)
	wantOK(t, "a registration", exec(d, insertRegistrationSQL, uuid.New(), "a@example.invalid"))
	wantCode(t, "a second registration for the address", exec(d, insertRegistrationSQL, uuid.New(), "a@example.invalid"), "23505")
	wantOK(t, "a registration for another address", exec(d, insertRegistrationSQL, uuid.New(), "b@example.invalid"))
	if n := count(t, d, `SELECT count(*) FROM auth_registrations`); n != 2 {
		t.Errorf("%d registrations, want 2", n)
	}
	k := hash32()
	wantOK(t, "a mail count", exec(d, upsertMailCountSQL, k))
	wantOK(t, "a second mail count", exec(d, upsertMailCountSQL, k))
	wantCode(t, "a 16-byte mail key", exec(d, upsertMailCountSQL, hash()), "23514")
	var sent int
	if err := d.Row(t, `SELECT sent FROM auth_mail_counts WHERE email_key = $1`, k).Scan(&sent); err != nil || sent != 2 {
		t.Errorf("the key's count = %d (%v), want 2", sent, err)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_mail_counts`); n != 1 {
		t.Errorf("%d mail count rows, want 1", n)
	}
}

func TestOIDCRowsGoWithTheirOwner(t *testing.T) {
	d := authkittest.NewDB(t)
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	wantOK(t, "a's identity", exec(d, insertIdentitySQL, uuid.New(), a, "google", "sub-a"))
	wantOK(t, "b's identity", exec(d, insertIdentitySQL, uuid.New(), b, "google", "sub-b"))
	wantOK(t, "a's link ceremony", exec(d, insertOIDCCeremonySQL, uuid.New(), "link", hash32(), hash32(), hash32(), a))
	wantOK(t, "a signin ceremony", exec(d, insertOIDCCeremonySQL, uuid.New(), "signin", hash32(), hash32(), hash32(), nil))
	d.Exec(t, `DELETE FROM users WHERE id = $1`, a)
	if n := count(t, d, `SELECT count(*) FROM auth_identities WHERE principal_id = $1`, a); n != 0 {
		t.Errorf("a keeps %d identities after the delete, want 0", n)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_identities WHERE principal_id = $1`, b); n != 1 {
		t.Errorf("b has %d identities, want 1", n)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_ceremonies WHERE kind = 'link'`); n != 0 {
		t.Errorf("%d link ceremonies survive the delete, want 0", n)
	}
	if n := count(t, d, `SELECT count(*) FROM auth_ceremonies WHERE kind = 'signin'`); n != 1 {
		t.Errorf("%d signin ceremonies, want 1", n)
	}
}

func TestTheAppRoleWithoutAWorkspaceReachesTheOIDCAndRegisterTables(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	ctx := context.Background()
	st := hash32()
	const spend = `UPDATE auth_ceremonies SET spent_at = now() WHERE state_hash = $1 AND spent_at IS NULL`
	var first, second int64
	err := d.InAuthTx(ctx, func(q db.Querier) error {
		if _, err := q.Exec(ctx, insertOIDCCeremonySQL, uuid.New(), "signin", st, hash32(), hash32(), nil); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, insertIdentitySQL, uuid.New(), a, "google", "sub-app"); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, insertRegistrationSQL, uuid.New(), "a@example.invalid"); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, upsertMailCountSQL, hash32()); err != nil {
			return err
		}
		var err error
		if first, err = q.Exec(ctx, spend, st); err != nil {
			return err
		}
		second, err = q.Exec(ctx, spend, st)
		return err
	})
	wantOK(t, "the app writes its OIDC and register rows", err)
	if first != 1 || second != 0 {
		t.Errorf("the spend marked %d then %d ceremonies, want 1 then 0", first, second)
	}
	for _, table := range []string{"auth_ceremonies", "auth_identities", "auth_registrations", "auth_mail_counts"} {
		var seen int
		err := d.InSystemTx(ctx, uuid.New(), func(q db.Querier) error {
			return q.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&seen)
		})
		wantOK(t, "the system role counts "+table, err)
		if seen != 0 {
			t.Errorf("the system role sees %d rows in %s, want 0", seen, table)
		}
		if n := count(t, d, "SELECT count(*) FROM "+table); n != 1 {
			t.Errorf("the owner sees %d rows in %s, want 1", n, table)
		}
	}
}

func TestTheDownMigrations0006And0005RestoreVersion4(t *testing.T) {
	for _, c := range []struct {
		name   string
		schema string
		opts   []authkittest.Option
	}{
		{"public", "", nil},
		{"kit_ns", kitSchema, []authkittest.Option{authkittest.Schema(kitSchema)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := authkittest.NewDB(t, c.opts...)
			a := d.NewPrincipal(t, "a@example.invalid")
			tbl := func(n string) string {
				if c.schema == "" {
					return n
				}
				return c.schema + "." + n
			}
			gone := func(table string) bool {
				var g bool
				if err := d.Row(t, `SELECT to_regclass($1) IS NULL`, tbl(table)).Scan(&g); err != nil {
					t.Fatal(err)
				}
				return g
			}
			render := func(id int, down bool) string {
				sql := migrationByID(t, id).Up
				if down {
					sql = migrationByID(t, id).Down
				}
				out, err := migrations.RenderIn(sql, "users", c.schema)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			d.Exec(t, render(6, true))
			if !gone("auth_registrations") || !gone("auth_mail_counts") {
				t.Error("after the 0006 down, a register table survives")
			}
			if n := count(t, d, `SELECT version FROM auth_schema`); n != 5 {
				t.Errorf("schema version after the 0006 down = %d, want 5", n)
			}
			d.Exec(t, render(5, true))
			if !gone("auth_ceremonies") || !gone("auth_identities") {
				t.Error("after the 0005 down, an OIDC table survives")
			}
			if n := count(t, d, `SELECT version FROM auth_schema`); n != 4 {
				t.Errorf("schema version after the 0005 down = %d, want 4", n)
			}
			s := newSession(t, d, a)
			wantCode(t, "oidc after the 0005 down", exec(d, d.SQL(`UPDATE auth_sessions SET second_factor = 'oidc' WHERE id = $1`), s), "23514")
			wantOK(t, "passkey after the 0005 down", exec(d, d.SQL(`UPDATE auth_sessions SET second_factor = 'passkey' WHERE id = $1`), s))
			d.Exec(t, render(5, false))
			d.Exec(t, render(6, false))
			for _, table := range []string{"auth_ceremonies", "auth_identities", "auth_registrations", "auth_mail_counts"} {
				if gone(table) {
					t.Errorf("after the ups, %s is absent", table)
				}
			}
			if n := count(t, d, `SELECT version FROM auth_schema`); n != 6 {
				t.Errorf("schema version after the ups = %d, want 6", n)
			}
			wantOK(t, "oidc after the ups", exec(d, d.SQL(`UPDATE auth_sessions SET second_factor = 'oidc' WHERE id = $1`), s))
		})
	}
}

func TestTheDownMigration0005RefusesOIDCRows(t *testing.T) {
	d := authkittest.NewDB(t)
	a := d.NewPrincipal(t, "a@example.invalid")
	s := newSession(t, d, a)
	d.Exec(t, `UPDATE auth_sessions SET second_factor = 'oidc' WHERE id = $1`, s)
	down6, err := migrations.Render(migrationByID(t, 6).Down, "users")
	if err != nil {
		t.Fatal(err)
	}
	d.Exec(t, down6)
	down5, err := migrations.Render(migrationByID(t, 5).Down, "users")
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, "the 0005 down with an oidc session", exec(d, down5), "23514")
	for _, table := range []string{"auth_ceremonies", "auth_identities"} {
		var present bool
		if err := d.Row(t, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present); err != nil || !present {
			t.Errorf("%s is gone after the refused down (present %v, %v)", table, present, err)
		}
	}
	if n := count(t, d, `SELECT version FROM auth_schema`); n != 5 {
		t.Errorf("schema version after the refused down = %d, want 5", n)
	}
	var factor string
	if err := d.Row(t, `SELECT second_factor FROM auth_sessions WHERE id = $1`, s).Scan(&factor); err != nil || factor != "oidc" {
		t.Errorf("the oidc session reads %q (%v) after the refused down, want oidc", factor, err)
	}
}

func TestSchemaBuildsTheAuthTablesInItOnly(t *testing.T) {
	d := authkittest.NewDB(t, authkittest.Schema(kitSchema))
	for _, table := range authTables {
		var inSchema, notPublic bool
		if err := d.Owner.QueryRow(`SELECT to_regclass('kit_ns.' || $1) IS NOT NULL, to_regclass('public.' || $1) IS NULL`, table).Scan(&inSchema, &notPublic); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if !inSchema || !notPublic {
			t.Errorf("%s: in kit_ns %v, not in public %v; want both", table, inSchema, notPublic)
		}
		var forced, pk bool
		if err := d.Owner.QueryRow(`
			SELECT c.relrowsecurity AND c.relforcerowsecurity,
			       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary)
			  FROM pg_class c WHERE c.oid = $1::regclass`, kitSchema+"."+table).Scan(&forced, &pk); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if !forced || !pk {
			t.Errorf("%s: forced RLS %v, primary key %v; want both", table, forced, pk)
		}
	}
	if n := count(t, d, `SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'auth\_%'`); n != 0 {
		t.Errorf("%d auth tables in public, want 0", n)
	}
	if n := count(t, d, `SELECT version FROM kit_ns.auth_schema`); n != migrations.Version {
		t.Errorf("schema version %d, want %d", n, migrations.Version)
	}
	var users bool
	if err := d.Owner.QueryRow(`SELECT to_regclass('public.users') IS NOT NULL`).Scan(&users); err != nil || !users {
		t.Errorf("public.users present %v (%v), want the app's principals table in public", users, err)
	}
}

func TestSchemaPoliciesBindTheAppRole(t *testing.T) {
	d := authkittest.NewDB(t, authkittest.Schema(kitSchema))
	ctx := context.Background()
	scope := uuid.New()
	a, b := d.NewPrincipal(t, "a@example.invalid"), d.NewPrincipal(t, "b@example.invalid")
	insert := `INSERT INTO kit_ns.auth_sessions (id, principal_id, audience, scope_id, token_hash, authenticated_at, created_at, expires_at)
	           VALUES ($1, $2, 'staff', $3, $4, now(), now(), now() + interval '1 day')`
	sa, sb := uuid.New(), uuid.New()
	d.Exec(t, insert, sa, a, scope, []byte("token-a"))
	d.Exec(t, insert, sb, b, scope, []byte("token-b"))
	conn := d.Pinned(t, a, scope, "staff")
	for id, want := range map[uuid.UUID]int{sa: 1, sb: 0} {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM kit_ns.auth_sessions WHERE id = $1`, id).Scan(&n); err != nil || n != want {
			t.Errorf("A counts %d of session %s (%v), want %d", n, id, err, want)
		}
	}
	var n int
	wantCode(t, "A reads auth_sessions outside kit_ns", conn.QueryRowContext(ctx, `SELECT count(*) FROM auth_sessions`).Scan(&n), "42P01")
	var v int
	if err := d.InAuthTx(ctx, func(q db.Querier) error {
		return q.QueryRow(ctx, `SELECT version FROM kit_ns.auth_schema`).Scan(&v)
	}); err != nil || v != migrations.Version {
		t.Errorf("App reads the schema version %d (%v), want %d", v, err, migrations.Version)
	}
}

func TestSchemaAndPlainDatabasesUseTheirOwnTemplates(t *testing.T) {
	p1 := authkittest.NewDB(t)
	ns := authkittest.NewDB(t, authkittest.Schema(kitSchema))
	p2 := authkittest.NewDB(t)
	for _, c := range []struct {
		what    string
		d       *authkittest.DB
		plain   bool
		schemas int
	}{{"first plain", p1, true, 0}, {"schema", ns, false, 1}, {"second plain", p2, true, 0}} {
		var public bool
		if err := c.d.Owner.QueryRow(`SELECT to_regclass('public.auth_sessions') IS NOT NULL`).Scan(&public); err != nil {
			t.Fatal(err)
		}
		if schemas := count(t, c.d, `SELECT count(*) FROM pg_namespace WHERE nspname = 'kit_ns'`); public != c.plain || schemas != c.schemas {
			t.Errorf("%s: public.auth_sessions %v, kit_ns schemas %d; want %v, %d", c.what, public, schemas, c.plain, c.schemas)
		}
	}
	if n := count(t, ns, `SELECT count(*) FROM pg_database WHERE datname LIKE 'authkit\_tpl\_%\_kit\_ns'`); n < 1 {
		t.Errorf("%d schema templates, want at least 1", n)
	}
}
