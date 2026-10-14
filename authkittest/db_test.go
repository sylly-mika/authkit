package authkittest_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/migrations"
)

var authTables = []string{"auth_schema", "auth_credentials", "auth_sessions", "auth_tokens", "auth_events", "auth_throttle", "auth_passkeys", "auth_passkey_ceremonies"}

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
	if err := d.Owner.QueryRow(`SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND conrelid::regclass::text LIKE 'auth\_%'`).Scan(&fks); err != nil || fks != 7 {
		t.Fatalf("authkit declares %d foreign keys (%v), want 7: the check below would pass vacuously", fks, err)
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
