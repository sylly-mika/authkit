package tests

import (
	crand "crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/internal/nsql"
	"github.com/sylly-mika/authkit/migrations"
	"github.com/sylly-mika/authkit/password"
)

func TestSchemaIsolation(t *testing.T) {
	const login, pw = "ada@example.invalid", "the right password"

	t.Run("a session on the world's install is ended on another", func(t *testing.T) {
		w := newWorld(t)
		id := w.User(login, pw)
		c := w.Claims(w.SignIn(login, pw))
		b := addInstall(w, "kit_iso")
		if res := authOn(w, b, id, c); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Fatalf("Authenticate on the other install = %v, want ErrSessionEnded", res.Refusal)
		}
		if res := authOn(w, w.Svc, id, c); res.Refusal != nil {
			t.Fatalf("Authenticate on the install that opened the session = %v, want no refusal", res.Refusal)
		}
		if n := countIn(w, "kit_iso", "SELECT count(*) FROM auth_sessions"); n != 0 {
			t.Fatalf("the other install holds %d sessions, want 0", n)
		}
		if n := countIn(w, "kit_iso", "SELECT count(*) FROM auth_events"); n != 0 {
			t.Fatalf("the other install holds %d events, want 0", n)
		}
	})

	t.Run("a session on another install is ended on the world's", func(t *testing.T) {
		w := newWorld(t)
		b := addInstall(w, "kit_iso")
		id := w.User(login, "")
		c := w.Claims(openOn(w, b, authkit.Principal{ID: id, Login: login}))
		if res := authOn(w, w.Svc, id, c); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Fatalf("Authenticate on the world's install = %v, want ErrSessionEnded", res.Refusal)
		}
		if res := authOn(w, b, id, c); res.Refusal != nil {
			t.Fatalf("Authenticate on the install that opened the session = %v, want no refusal", res.Refusal)
		}
		if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 0 {
			t.Fatalf("the world's install holds %d sessions, want 0", n)
		}
		if n := countIn(w, "kit_iso", "SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 1 {
			t.Fatalf("the other install holds %d sessions, want 1", n)
		}
	})

	t.Run("Prune on another install leaves the world's rows", func(t *testing.T) {
		w := newWorld(t)
		id := w.User(login, pw)
		w.SignIn(login, pw)
		w.Login("staff", login, "a wrong password")
		if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 1 {
			t.Fatalf("the world's install holds %d sessions before the prune, want 1", n)
		}
		if n := w.Count("SELECT count(*) FROM auth_throttle"); n != 1 {
			t.Fatalf("the world's install holds %d throttle rows before the prune, want 1", n)
		}
		b := addInstall(w, "kit_iso")
		w.Clock.Advance(40 * 24 * time.Hour)
		if err := w.D.InGlobalSystemTx(w.Ctx, func(q db.Querier) error { return b.Prune(w.Ctx, q) }); err != nil {
			t.Fatal(err)
		}
		if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 1 {
			t.Fatalf("the world's install holds %d sessions after the other install's prune, want 1", n)
		}
		if n := w.Count("SELECT count(*) FROM auth_throttle"); n != 1 {
			t.Fatalf("the world's install holds %d throttle rows after the other install's prune, want 1", n)
		}
		if err := w.D.InGlobalSystemTx(w.Ctx, func(q db.Querier) error { return w.Svc.Prune(w.Ctx, q) }); err != nil {
			t.Fatal(err)
		}
		if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 0 {
			t.Fatalf("the world's install holds %d sessions after its own prune, want 0", n)
		}
		if n := w.Count("SELECT count(*) FROM auth_throttle"); n != 0 {
			t.Fatalf("the world's install holds %d throttle rows after its own prune, want 0", n)
		}
	})

	t.Run("a lockout on the world's install does not lock another", func(t *testing.T) {
		w := newWorld(t)
		id := w.User(login, pw)
		b := addInstall(w, "kit_iso")
		hash, err := password.Encode(w.Cfg.Password.Hashing, crand.Reader, pw)
		if err != nil {
			t.Fatal(err)
		}
		w.D.Exec(t, nsql.Rewrite("kit_iso", "INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)"), id, hash, w.Clock.Now())
		for i := 0; i < w.Cfg.Throttle.Failures+1; i++ {
			w.Login("staff", login, "a wrong password")
		}
		if n := countIn(w, "kit_iso", "SELECT count(*) FROM auth_throttle"); n != 0 {
			t.Fatalf("the other install holds %d throttle rows, want 0", n)
		}
		var locked authkit.ErrLocked
		if res := w.Login("staff", login, pw); !errors.As(res.Refusal, &locked) {
			t.Fatalf("the world's install after the failures = %v, want ErrLocked", res.Refusal)
		}
		res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
			return b.Password.Login(w.Ctx, q, "staff", login, pw, authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"})
		})
		if res.Refusal != nil || res.Session == nil {
			t.Fatalf("the other install's login = refusal %v, session present %v; want a session and no refusal", res.Refusal, res.Session != nil)
		}
		if n := countIn(w, "kit_iso", "SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 1 {
			t.Fatalf("the other install holds %d sessions, want 1", n)
		}
		if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 0 {
			t.Fatalf("the world's install holds %d sessions, want 0", n)
		}
	})

	t.Run("two schema installs share no rewrite", func(t *testing.T) {
		w := newWorld(t)
		b := addInstall(w, "kit_iso")
		cc := addInstall(w, "kit_iso2")
		id := w.User(login, "")
		p := authkit.Principal{ID: id, Login: login}
		openOn(w, b, p)
		rc := openOn(w, cc, p)
		if n := countIn(w, "kit_iso", "SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 1 {
			t.Fatalf("the first install holds %d sessions, want 1", n)
		}
		if n := countIn(w, "kit_iso2", "SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 1 {
			t.Fatalf("the second install holds %d sessions, want 1", n)
		}
		if res := authOn(w, cc, id, w.Claims(rc)); res.Refusal != nil {
			t.Fatalf("Authenticate on the second install = %v, want no refusal", res.Refusal)
		}
		if res := authOn(w, b, id, w.Claims(rc)); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Fatalf("Authenticate on the first install = %v, want ErrSessionEnded", res.Refusal)
		}
	})
}

func addInstall(w *world, schema string) *kittest.Kit {
	w.T.Helper()
	if schema == w.Cfg.Schema {
		w.T.Fatalf("install schema %q is the world's own", schema)
	}
	parts := []string{"CREATE SCHEMA " + schema + ";"}
	for _, m := range migrations.All() {
		up, err := migrations.RenderIn(m.Up, "users", schema)
		if err != nil {
			w.T.Fatal(err)
		}
		parts = append(parts, up)
	}
	parts = append(parts,
		"GRANT USAGE ON SCHEMA "+schema+" TO "+authkittest.AppRole+";",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "+schema+" TO "+authkittest.AppRole+";")
	w.D.Exec(w.T, strings.Join(parts, "\n"))
	r := w.Cfg
	r.Schema = schema
	return w.BuildWith(r, w.P)
}

func countIn(w *world, schema, query string, args ...any) int {
	w.T.Helper()
	var n int
	if err := w.D.Row(w.T, nsql.Rewrite(schema, query), args...).Scan(&n); err != nil {
		w.T.Fatal(err)
	}
	return n
}

func openOn(w *world, k *kittest.Kit, p authkit.Principal) authkit.Result {
	w.T.Helper()
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return k.OpenSession(w.Ctx, q, p, "staff", authkit.Meta{IP: "192.0.2.7", UserAgent: "authkit-test"})
	})
	if res.Refusal != nil {
		w.T.Fatalf("OpenSession refused: %v", res.Refusal)
	}
	if res.Session == nil {
		w.T.Fatal("OpenSession returned no session")
	}
	return res
}

func authOn(w *world, k *kittest.Kit, id uuid.UUID, c *authkit.Claims) authkit.Result {
	w.T.Helper()
	res, err := k.Authenticate(w.Ctx, sqldb.Conn(w.Pinned(id)), c)
	if err != nil {
		w.T.Fatalf("Authenticate: %v", err)
	}
	return res
}

func TestCoreMethodsQualifyTheirStatements(t *testing.T) {
	const login = "ada@example.invalid"
	w := newWorld(t)
	b := addInstall(w, "kit_iso")
	core, err := b.Attach("fixc")
	if err != nil {
		t.Fatal(err)
	}
	id := w.User(login, "")
	p := authkit.Principal{ID: id, Login: login}
	openOn(w, w.Svc, p)
	c := w.Claims(openOn(w, b, p))
	now := w.Clock.Now()
	if err := authkittest.InConnTx(w.Ctx, w.Pinned(id), func(q db.Querier) error {
		_, fresh, err := core.Fresh(w.Ctx, q, c, time.Hour, now)
		if err != nil {
			return err
		}
		if !fresh {
			t.Fatal("Fresh on the other install = not fresh, want the open session")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := authkittest.InConnTx(w.Ctx, w.Pinned(id), func(q db.Querier) error {
		return core.RevokeAll(w.Ctx, q, id, authkit.ReasonPasswordChanged, now)
	}); err != nil {
		t.Fatal(err)
	}
	if n := countIn(w, "kit_iso", "SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL", id); n != 0 {
		t.Fatalf("the other install holds %d open sessions after RevokeAll, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL", id); n != 1 {
		t.Fatalf("the world's install holds %d open sessions after the other install's RevokeAll, want 1", n)
	}
}

func TestOneTimePruneStaysInItsInstall(t *testing.T) {
	const login = "ada@example.invalid"
	w := newWorld(t)
	b := addInstall(w, "kit_iso")
	id := w.User(login, "")
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		if _, err := w.Svc.OneTime().Create(w.Ctx, q, authkit.PurposeReset, id, time.Hour); err != nil {
			return err
		}
		_, err := b.OneTime().Create(w.Ctx, q, authkit.PurposeReset, id, time.Hour)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w.Clock.Advance(40 * 24 * time.Hour)
	var pruned int64
	if err := w.D.InGlobalSystemTx(w.Ctx, func(q db.Querier) error {
		var err error
		pruned, err = b.OneTime().Prune(w.Ctx, q, w.Clock.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("Prune on the other install deleted %d rows, want its 1 expired row", pruned)
	}
	if n := countIn(w, "kit_iso", "SELECT count(*) FROM auth_tokens"); n != 0 {
		t.Fatalf("the other install holds %d tokens after its prune, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_tokens"); n != 1 {
		t.Fatalf("the world's install holds %d tokens after the other install's prune, want 1", n)
	}
}
