// Package kittest is the setup the black-box tests share: a Service over a
// throwaway database, its clock and principals, and the helpers that sign a
// principal in.
package kittest

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/password"
)

// Cheap is the argon2id cost the tests hash with.
// WHY: cheap hashing keeps -race runs fast.
var Cheap = password.Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

// Rules is the configuration a World builds its Kit from.
type Rules struct {
	authkit.Config
	Password password.Config
}

// Kit is the Service under test and its password module.
type Kit struct {
	*authkit.Service
	Password *password.Module
}

// World is one test's Kit and the fixtures it runs over.
type World struct {
	T     *testing.T              // the test the world belongs to
	Ctx   context.Context         // the context every call runs under
	D     *authkittest.DB         // the throwaway database
	P     *authkittest.Principals // the principal fixture
	Clock *authkittest.Clock      // the clock the Service reads
	Cfg   Rules                   // the rules Svc was built from
	Svc   *Kit                    // the Kit under test
}

// New builds a World on a throwaway database with PinnedRules applied, then
// each tweak in order.
func New(t *testing.T, tweaks ...func(*Rules)) *World {
	t.Helper()
	w := &World{T: t, Ctx: context.Background(), D: authkittest.NewDB(t), P: authkittest.NewPrincipals(), Clock: authkittest.NewClock()}
	w.Cfg = Rules{Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!"), Clock: w.Clock, Rand: authkittest.Rand(7)},
		Password: password.Config{Hashing: Cheap, HashWait: 200 * time.Millisecond}}
	PinnedRules(&w.Cfg)
	for _, f := range tweaks {
		f(&w.Cfg)
	}
	w.Svc = w.Build(w.Cfg)
	return w
}

// PinnedRules sets the session, throttle, event and reset rules the tests
// pin to fixed values.
func PinnedRules(c *Rules) {
	c.Session = authkit.SessionRules{IdleTTL: 7 * 24 * time.Hour, AbsoluteTTL: -1}
	c.Throttle = authkit.Throttle{Failures: 10, Window: 15 * time.Minute, Lockout: 15 * time.Minute, CountAfterVerify: true, PlainLoginKey: true}
	c.Events.ChangeLogsReset = true
	c.Password.Reset.MayCreateCredential = true
	c.EventRetention = -1
}

// DefaultRules clears the rules PinnedRules sets, so the Service runs on
// their zero values.
func DefaultRules(c *Rules) {
	c.Session, c.Throttle, c.Events, c.Password.Reset, c.EventRetention = authkit.SessionRules{}, authkit.Throttle{}, authkit.EventRules{}, authkit.ResetRules{}, 0
}

// Build builds a Kit from r over the world's principals.
func (w *World) Build(r Rules) *Kit {
	w.T.Helper()
	return w.BuildWith(r, w.P)
}

// BuildWith builds a Kit from r over the principals p.
func (w *World) BuildWith(r Rules, p authkit.Principals) *Kit {
	w.T.Helper()
	kit, err := NewKit(r, p)
	if err != nil {
		w.T.Fatal(err)
	}
	return kit
}

// NewKit builds a Kit from r over the principals p.
func NewKit(r Rules, p authkit.Principals) (*Kit, error) {
	svc, err := authkit.New(r.Config, p)
	if err != nil {
		return nil, err
	}
	pw, err := password.New(svc, r.Password)
	if err != nil {
		return nil, err
	}
	return &Kit{Service: svc, Password: pw}, nil
}

// User creates a principal with the login and, when pw is not empty, a
// password hash of pw.
func (w *World) User(login, pw string) uuid.UUID {
	w.T.Helper()
	id := w.D.NewPrincipal(w.T, login)
	if pw != "" {
		hash, err := password.Encode(w.Cfg.Password.Hashing, crand.Reader, pw)
		if err != nil {
			w.T.Fatal(err)
		}
		w.D.Exec(w.T, `INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)`, id, hash, w.Clock.Now())
	}
	return id
}

// WHY: a refusal is a value, not an error, so its writes must commit; the helper commits whatever fn wrote.
//
// InAuth runs fn in an auth transaction and commits it, returning fn's Result.
func (w *World) InAuth(fn func(q db.Querier) (authkit.Result, error)) authkit.Result {
	w.T.Helper()
	var res authkit.Result
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		res, err = fn(q)
		return err
	}); err != nil {
		w.T.Fatalf("authkit failed: %v", err)
	}
	return res
}

// InConn runs fn in a transaction on conn and commits it, returning fn's
// Result.
func (w *World) InConn(conn *sql.Conn, fn func(q db.Querier) (authkit.Result, error)) authkit.Result {
	w.T.Helper()
	var res authkit.Result
	if err := authkittest.InConnTx(w.Ctx, conn, func(q db.Querier) error {
		var err error
		res, err = fn(q)
		return err
	}); err != nil {
		w.T.Fatalf("authkit failed: %v", err)
	}
	return res
}

// Login signs login in with pw for aud, from 192.0.2.1.
func (w *World) Login(aud authkit.Audience, login, pw string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.Login(w.Ctx, q, aud, login, pw, authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"})
	})
}

// SignIn signs login in as staff and fails the test on a refusal.
func (w *World) SignIn(login, pw string) authkit.Result {
	w.T.Helper()
	res := w.Login("staff", login, pw)
	if res.Refusal != nil {
		w.T.Fatalf("sign-in refused: %v", res.Refusal)
	}
	return res
}

// Claims parses the access token of res.
func (w *World) Claims(res authkit.Result) *authkit.Claims {
	w.T.Helper()
	c, err := w.Svc.Codec().Parse(res.Tokens.AccessToken, res.Session.Audience)
	if err != nil {
		w.T.Fatalf("parse the access token: %v", err)
	}
	return c
}

// Pinned returns a connection pinned to id's scope and the staff audience.
func (w *World) Pinned(id uuid.UUID) *sql.Conn { return w.D.Pinned(w.T, id, w.P.Scope, "staff") }

// Count runs a query that returns one integer and returns it.
func (w *World) Count(query string, args ...any) int {
	w.T.Helper()
	var n int
	if err := w.D.Row(w.T, query, args...).Scan(&n); err != nil {
		w.T.Fatal(err)
	}
	return n
}

// StoredHash returns the password hash stored for id.
func (w *World) StoredHash(id uuid.UUID) string {
	w.T.Helper()
	var hash string
	if err := w.D.Row(w.T, `SELECT password_hash FROM auth_credentials WHERE principal_id = $1`, id).Scan(&hash); err != nil {
		w.T.Fatal(err)
	}
	return hash
}

// Results lists the result of each auth event of id, oldest first.
func (w *World) Results(id uuid.UUID) []string {
	w.T.Helper()
	rows, err := w.D.Owner.Query(`SELECT result FROM auth_events WHERE principal_id = $1 ORDER BY at, result`, id)
	if err != nil {
		w.T.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			w.T.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// HashedKey returns the auth_throttle key for login: the hex SHA-256 of the login.
func HashedKey(login string) string {
	sum := sha256.Sum256([]byte(login))
	return hex.EncodeToString(sum[:])
}
