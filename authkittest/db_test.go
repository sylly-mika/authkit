package authkittest_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/migrations"
)

var authTables = []string{"auth_schema", "auth_credentials", "auth_sessions", "auth_tokens", "auth_events", "auth_throttle"}

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

// fkIndexCheck is ino-tasks' scripts/fk_index_check.sql without its fleet-size
// guard: one row per foreign key whose columns lead no index.
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
	if err := d.Owner.QueryRow(`SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND conrelid::regclass::text LIKE 'auth\_%'`).Scan(&fks); err != nil || fks != 4 {
		t.Fatalf("authkit declares %d foreign keys (%v), want 4: the check below would pass vacuously", fks, err)
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
