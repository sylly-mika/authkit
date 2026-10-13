package authkit_test

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/password"
)

// WHY: cheap hashing keeps -race runs fast.
var cheap = password.Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

type world struct {
	t     *testing.T
	ctx   context.Context
	d     *authkittest.DB
	p     *authkittest.Principals
	clock *authkittest.Clock
	cfg   authkit.Config
	svc   *authkit.Service
}

func newWorld(t *testing.T, tweaks ...func(*authkit.Config)) *world {
	t.Helper()
	w := &world{t: t, ctx: context.Background(), d: authkittest.NewDB(t), p: authkittest.NewPrincipals(), clock: authkittest.NewClock()}
	w.cfg = authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!"), Hashing: cheap,
		HashWait: 200 * time.Millisecond, Clock: w.clock, Rand: authkittest.Rand(7)}
	pinned(&w.cfg)
	for _, f := range tweaks {
		f(&w.cfg)
	}
	w.svc = w.service(w.cfg)
	return w
}

func pinned(c *authkit.Config) {
	c.Session = authkit.SessionRules{IdleTTL: 7 * 24 * time.Hour, AbsoluteTTL: -1}
	c.Throttle = authkit.Throttle{Failures: 10, Window: 15 * time.Minute, Lockout: 15 * time.Minute, CountAfterVerify: true, PlainLoginKey: true}
	c.Events.ChangeLogsReset = true
	c.Reset.MayCreateCredential = true
	c.EventRetention = -1
}

func defaults(c *authkit.Config) {
	c.Session, c.Throttle, c.Events, c.Reset, c.EventRetention = authkit.SessionRules{}, authkit.Throttle{}, authkit.EventRules{}, authkit.ResetRules{}, 0
}

func (w *world) service(cfg authkit.Config) *authkit.Service {
	w.t.Helper()
	svc, err := authkit.New(cfg, w.p)
	if err != nil {
		w.t.Fatal(err)
	}
	return svc
}

func (w *world) user(login, pw string) uuid.UUID {
	w.t.Helper()
	id := w.d.NewPrincipal(w.t, login)
	if pw != "" {
		hash, err := password.Encode(w.cfg.Hashing, crand.Reader, pw)
		if err != nil {
			w.t.Fatal(err)
		}
		w.d.Exec(w.t, `INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)`, id, hash, w.clock.Now())
	}
	return id
}

// WHY: a refusal is a value, not an error, so its writes must commit; the helper commits whatever fn wrote.
func (w *world) inAuth(fn func(q db.Querier) (authkit.Result, error)) authkit.Result {
	w.t.Helper()
	var res authkit.Result
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		res, err = fn(q)
		return err
	}); err != nil {
		w.t.Fatalf("authkit failed: %v", err)
	}
	return res
}

func (w *world) inConn(conn *sql.Conn, fn func(q db.Querier) (authkit.Result, error)) authkit.Result {
	w.t.Helper()
	var res authkit.Result
	if err := authkittest.InConnTx(w.ctx, conn, func(q db.Querier) error {
		var err error
		res, err = fn(q)
		return err
	}); err != nil {
		w.t.Fatalf("authkit failed: %v", err)
	}
	return res
}

func (w *world) login(aud authkit.Audience, login, pw string) authkit.Result {
	w.t.Helper()
	return w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.Login(w.ctx, q, aud, login, pw, authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"})
	})
}

func (w *world) signIn(login, pw string) authkit.Result {
	w.t.Helper()
	res := w.login("staff", login, pw)
	if res.Refusal != nil {
		w.t.Fatalf("sign-in refused: %v", res.Refusal)
	}
	return res
}

func (w *world) claims(res authkit.Result) *authkit.Claims {
	w.t.Helper()
	c, err := w.svc.Codec().Parse(res.Tokens.AccessToken, res.Session.Audience)
	if err != nil {
		w.t.Fatalf("parse the access token: %v", err)
	}
	return c
}

func (w *world) pinned(id uuid.UUID) *sql.Conn { return w.d.Pinned(w.t, id, w.p.Scope, "staff") }

func (w *world) count(query string, args ...any) int {
	w.t.Helper()
	var n int
	if err := w.d.Row(w.t, query, args...).Scan(&n); err != nil {
		w.t.Fatal(err)
	}
	return n
}

func (w *world) storedHash(id uuid.UUID) string {
	w.t.Helper()
	var hash string
	if err := w.d.Row(w.t, `SELECT password_hash FROM auth_credentials WHERE principal_id = $1`, id).Scan(&hash); err != nil {
		w.t.Fatal(err)
	}
	return hash
}

func (w *world) results(id uuid.UUID) []string {
	w.t.Helper()
	rows, err := w.d.Owner.Query(`SELECT result FROM auth_events WHERE principal_id = $1 ORDER BY at, result`, id)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			w.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}
