package tests

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/pgxdb"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
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

func TestCheckSchemaReadsTheServicesSchema(t *testing.T) {
	t.Setenv("AUTHKIT_TEST_SCHEMA", "kit_ns")
	t.Run("schema", func(t *testing.T) {
		w := newWorld(t)
		check := func(fn func(q db.Querier) error) error {
			return w.D.InAuthTx(w.Ctx, fn)
		}
		if err := check(func(q db.Querier) error { return w.Svc.CheckSchema(w.Ctx, q) }); err != nil {
			t.Fatalf("Service.CheckSchema on a current schema = %v; want nil", err)
		}
		if err := check(func(q db.Querier) error { return authkit.CheckSchema(w.Ctx, q) }); !errors.Is(err, authkit.ErrSchemaBehind) {
			t.Fatalf("authkit.CheckSchema with the schema off the search path = %v; want ErrSchemaBehind", err)
		}
		w.D.Exec(t, "UPDATE auth_schema SET version = 1")
		if err := check(func(q db.Querier) error { return w.Svc.CheckSchema(w.Ctx, q) }); !errors.Is(err, authkit.ErrSchemaBehind) {
			t.Fatalf("Service.CheckSchema after the version drops = %v; want ErrSchemaBehind", err)
		}
	})
	t.Run("plain", func(t *testing.T) {
		t.Setenv("AUTHKIT_TEST_SCHEMA", "")
		w := newWorld(t)
		check := func(fn func(q db.Querier) error) error {
			return w.D.InAuthTx(w.Ctx, fn)
		}
		if err := check(func(q db.Querier) error { return authkit.CheckSchema(w.Ctx, q) }); err != nil {
			t.Fatalf("authkit.CheckSchema on the search path = %v; want nil", err)
		}
		if err := check(func(q db.Querier) error { return w.Svc.CheckSchema(w.Ctx, q) }); err != nil {
			t.Fatalf("Service.CheckSchema with Schema \"\" = %v; want nil", err)
		}
		w.D.Exec(t, "UPDATE auth_schema SET version = 1")
		if err := check(func(q db.Querier) error { return authkit.CheckSchema(w.Ctx, q) }); !errors.Is(err, authkit.ErrSchemaBehind) {
			t.Fatalf("authkit.CheckSchema after the version drops = %v; want ErrSchemaBehind", err)
		}
	})
}

type recordingPrincipals struct {
	authkit.Principals
	seen []db.Querier
}

func (r *recordingPrincipals) Admit(ctx context.Context, q db.Querier, p authkit.Proposal) (authkit.Admission, error) {
	r.seen = append(r.seen, q)
	return r.Principals.Admit(ctx, q, p)
}

func (r *recordingPrincipals) Lookup(ctx context.Context, q db.Querier, login string, aud authkit.Audience) (authkit.Principal, error) {
	r.seen = append(r.seen, q)
	return r.Principals.Lookup(ctx, q, login, aud)
}

func (r *recordingPrincipals) ByID(ctx context.Context, q db.Querier, id uuid.UUID, aud authkit.Audience) (authkit.Principal, error) {
	r.seen = append(r.seen, q)
	return r.Principals.ByID(ctx, q, id, aud)
}

func TestPrincipalsGetTheCallersQuerier(t *testing.T) {
	t.Setenv("AUTHKIT_TEST_SCHEMA", "kit_ns")
	w := newWorld(t)
	const login, pw = "ada@example.invalid", "the right password"
	p := authkit.Principal{ID: w.User(login, pw), Login: login}
	id := p.ID
	rec := &recordingPrincipals{Principals: w.P}
	k := w.BuildWith(w.Cfg, rec)
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		res, err := k.OpenSession(w.Ctx, q, p, "staff", authkit.Meta{})
		if err != nil {
			return err
		}
		if res.Refusal != nil {
			t.Fatalf("OpenSession refused: %v", res.Refusal)
		}
		if len(rec.seen) != 1 || rec.seen[0] != q {
			t.Fatalf("Admit got %d queriers; want the caller's one querier", len(rec.seen))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 1 {
		t.Fatalf("sessions written = %d; want 1", n)
	}

	rec.seen = nil
	var res authkit.Result
	err = w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		res, err = k.Password.Login(w.Ctx, q, "staff", login, pw, authkit.Meta{})
		if err != nil {
			return err
		}
		if len(rec.seen) == 0 {
			t.Fatal("Login made no principal call")
		}
		for _, got := range rec.seen {
			if got != q {
				t.Fatal("Login's Lookup or Admit got a querier other than the caller's")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Session == nil {
		t.Fatalf("Login refused: %v", res.Refusal)
	}

	rec.seen = nil
	err = w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		out, err := k.Password.ChangePassword(w.Ctx, q, w.Claims(res), pw, "another right password", authkit.Meta{})
		if err != nil {
			return err
		}
		if out.Refusal != nil {
			t.Fatalf("ChangePassword refused: %v", out.Refusal)
		}
		if len(rec.seen) == 0 {
			t.Fatal("ChangePassword made no principal call")
		}
		for _, got := range rec.seen {
			if got != q {
				t.Fatal("ChangePassword's ByID got a querier other than the caller's")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOnEventGetsTheCallersQuerier(t *testing.T) {
	t.Setenv("AUTHKIT_TEST_SCHEMA", "kit_ns")
	var seen []db.Querier
	w := newWorld(t, func(r *kittest.Rules) {
		r.OnEvent = func(ctx context.Context, q db.Querier, e authkit.Event) error {
			seen = append(seen, q)
			return nil
		}
	})
	p := authkit.Principal{ID: w.User("ada@example.invalid", ""), Login: "ada@example.invalid"}
	id := p.ID
	seen = nil
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		if _, err := w.Svc.OpenSession(w.Ctx, q, p, "staff", authkit.Meta{}); err != nil {
			return err
		}
		if len(seen) < 1 {
			t.Fatal("OnEvent was not called")
		}
		for _, got := range seen {
			if got != q {
				t.Fatal("OnEvent got a querier other than the caller's")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1", id); n != len(seen) {
		t.Fatalf("events written = %d; OnEvent calls = %d", n, len(seen))
	}
}
