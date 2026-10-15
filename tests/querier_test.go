package tests

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db/pgxdb"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/onetime"
)

func TestSchemaValidation(t *testing.T) {
	base := authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}
	for _, name := range []string{"Kit", "1kit", "kit-ns", strings.Repeat("a", 64)} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			cfg.Schema = name
			svc, err := authkit.New(cfg, authkittest.NewPrincipals())
			want := fmt.Sprintf("authkit: schema %q is not a lower-case identifier of at most 63 bytes", name)
			if svc != nil || err == nil || err.Error() != want {
				t.Fatalf("New with Schema %q = %v, %v; want the error %q", name, svc, err, want)
			}
		})
	}
	for _, name := range []string{"public", "information_schema", "pg_kit"} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			cfg.Schema = name
			svc, err := authkit.New(cfg, authkittest.NewPrincipals())
			want := fmt.Sprintf("authkit: schema %q is reserved by PostgreSQL", name)
			if svc != nil || err == nil || err.Error() != want {
				t.Fatalf("New with Schema %q = %v, %v; want the error %q", name, svc, err, want)
			}
		})
	}
	for _, name := range []string{"kit_ns", ""} {
		t.Run(fmt.Sprintf("accepts %q", name), func(t *testing.T) {
			cfg := base
			cfg.Schema = name
			svc, err := authkit.New(cfg, authkittest.NewPrincipals())
			if err != nil {
				t.Fatal(err)
			}
			core, err := svc.Attach("t")
			if err != nil {
				t.Fatal(err)
			}
			if got := core.Config().Schema; got != name {
				t.Fatalf("Config().Schema = %q; want %q", got, name)
			}
			if name == "" {
				q := sqldb.Tx(&sql.Tx{})
				if core.Q(q) != q {
					t.Fatal("Schema \"\" wrapped the querier")
				}
			}
		})
	}
	t.Run("onetime refuses a bad schema", func(t *testing.T) {
		st, err := onetime.NewIn("Kit", time.Now, rand.Reader)
		want := `authkit: schema "Kit" is not a lower-case identifier of at most 63 bytes`
		if st != nil || err == nil || err.Error() != want {
			t.Fatalf("NewIn(\"Kit\") = %v, %v; want the error %q", st, err, want)
		}
	})
	t.Run("onetime accepts a schema", func(t *testing.T) {
		st, err := onetime.NewIn("kit_ns", time.Now, rand.Reader)
		if st == nil || err != nil {
			t.Fatalf("NewIn(\"kit_ns\") = %v, %v; want a store", st, err)
		}
	})
}

func TestUnwrapThroughSchema(t *testing.T) {
	cfg := authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!"), Schema: "kit_ns"}
	svc, err := authkit.New(cfg, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	core, err := svc.Attach("t")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("sqldb", func(t *testing.T) {
		tx := &sql.Tx{}
		q := sqldb.Tx(tx)
		wrapped := core.Q(q)
		if wrapped == q {
			t.Fatal("Q did not wrap the querier")
		}
		got, ok := sqldb.Unwrap(wrapped)
		if !ok || got != tx {
			t.Fatalf("sqldb.Unwrap = %v, %v; want the *sql.Tx", got, ok)
		}
	})
	t.Run("pgxdb", func(t *testing.T) {
		type fakeTx struct{ pgx.Tx }
		ftx := &fakeTx{}
		q := pgxdb.Tx(ftx)
		wrapped := core.Q(q)
		if wrapped == q {
			t.Fatal("Q did not wrap the querier")
		}
		got, ok := pgxdb.Unwrap(wrapped)
		if !ok || got != pgx.Tx(ftx) {
			t.Fatalf("pgxdb.Unwrap = %v, %v; want the pgx.Tx", got, ok)
		}
	})
}
