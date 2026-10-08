package echov5_test

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/echov5"
	"github.com/sylly-mika/authkit/password"
)

type fixture struct {
	d   *authkittest.DB
	p   *authkittest.Principals
	svc *authkit.Service
}

var cheap = password.Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{d: authkittest.NewDB(t), p: authkittest.NewPrincipals()}
	svc, err := authkit.New(authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!"),
		Hashing: cheap, Clock: authkittest.NewClock(), Rand: authkittest.Rand(3)}, f.p)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

func (f *fixture) signIn(t *testing.T) (uuid.UUID, authkit.Result) {
	t.Helper()
	id := f.d.NewPrincipal(t, "ada@example.invalid")
	hash, err := password.Encode(cheap, crand.Reader, "the right password")
	if err != nil {
		t.Fatal(err)
	}
	f.d.Exec(t, `INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, now())`, id, hash)
	var res authkit.Result
	if err := f.d.InAuthTx(context.Background(), func(q db.Querier) error {
		var err error
		res, err = f.svc.Login(context.Background(), q, "staff", "ada@example.invalid", "the right password", authkit.Meta{})
		return err
	}); err != nil || res.Refusal != nil {
		t.Fatalf("sign in: %v %v", err, res.Refusal)
	}
	return id, res
}

// run builds the chain by hand, as echo does, and returns its error.
func run(header string, chain []echo.MiddlewareFunc, last echo.HandlerFunc) error {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	h := last
	for i := len(chain) - 1; i >= 0; i-- {
		h = chain[i](h)
	}
	return h(e.NewContext(req, httptest.NewRecorder()))
}

func TestParseBearerPutsTheClaimsOnTheContext(t *testing.T) {
	f := setup(t)
	id, res := f.signIn(t)
	var got *authkit.Claims
	err := run("Bearer "+res.Tokens.AccessToken, []echo.MiddlewareFunc{echov5.ParseBearer(f.svc, "staff")},
		func(c *echo.Context) error { got = echov5.Claims(c); return nil })
	if err != nil || got == nil || got.Subject != id || got.SessionID != res.Session.ID {
		t.Fatalf("ParseBearer = %v, claims %+v", err, got)
	}
}

func TestParseBearerRefusals(t *testing.T) {
	f := setup(t)
	id, res := f.signIn(t)
	client, _, err := f.svc.Codec().Mint(id, res.Session.ID, "client", map[string]any{"role": "member"})
	if err != nil {
		t.Fatal(err)
	}
	for header, want := range map[string]error{
		"":                   authkit.ErrMissingToken,
		"Basic abc":          authkit.ErrMissingToken,
		"Bearer not.a.token": authkit.ErrInvalidToken,
		"Bearer " + client:   authkit.ErrWrongAudience,
	} {
		err := run(header, []echo.MiddlewareFunc{echov5.ParseBearer(f.svc, "staff")}, func(*echo.Context) error {
			t.Errorf("%q reached the handler", header)
			return nil
		})
		if err != want {
			t.Errorf("%q: %v, want %v", header, err, want)
		}
	}
}

func (f *fixture) guarded(t *testing.T, conn *sql.Conn, token string) (authkit.Admission, error) {
	t.Helper()
	var adm authkit.Admission
	err := run("Bearer "+token, []echo.MiddlewareFunc{
		echov5.ParseBearer(f.svc, "staff"),
		echov5.Guard(f.svc, func(*echo.Context) db.Querier { return sqldb.Conn(conn) }),
	}, func(c *echo.Context) error {
		var ok bool
		if adm, ok = echov5.Admission(c); !ok {
			t.Error("Guard admitted without an Admission on the context")
		}
		return nil
	})
	return adm, err
}

func TestGuardAdmitsOnTheAppsQuerier(t *testing.T) {
	f := setup(t)
	id, res := f.signIn(t)
	adm, err := f.guarded(t, f.d.Pinned(t, id, f.p.Scope, "staff"), res.Tokens.AccessToken)
	if err != nil || adm.Context != "member" {
		t.Fatalf("Guard = %v, admission %+v", err, adm)
	}
}

// TestGuardRefusesEndedAndStaleSessions is spec §8.5 through the middleware.
// The refusals are the bare sentinels, not wraps of them.
func TestGuardRefusesEndedAndStaleSessions(t *testing.T) {
	f := setup(t)
	id, res := f.signIn(t)
	conn := f.d.Pinned(t, id, f.p.Scope, "staff")
	f.p.SetRole(id, "admin")
	if _, err := f.guarded(t, conn, res.Tokens.AccessToken); err != authkit.ErrStale {
		t.Fatalf("a changed role = %v, want ErrStale", err)
	}
	f.d.Exec(t, `UPDATE auth_sessions SET revoked_at = now(), revoke_reason = 'user' WHERE id = $1`, res.Session.ID)
	if _, err := f.guarded(t, conn, res.Tokens.AccessToken); err != authkit.ErrSessionEnded {
		t.Fatalf("a revoked session = %v, want ErrSessionEnded", err)
	}
}

// TestGuardNeedsParseBearerBeforeIt: with a working querier, a chain without
// ParseBearer is a server error, never a refusal (a 401 signs the SPA out).
func TestGuardNeedsParseBearerBeforeIt(t *testing.T) {
	f := setup(t)
	id, res := f.signIn(t)
	conn := f.d.Pinned(t, id, f.p.Scope, "staff")
	err := run("Bearer "+res.Tokens.AccessToken, []echo.MiddlewareFunc{
		echov5.Guard(f.svc, func(*echo.Context) db.Querier { return sqldb.Conn(conn) }),
	}, func(*echo.Context) error { t.Error("Guard without ParseBearer reached the handler"); return nil })
	if !serverError(err) {
		t.Fatalf("Guard without claims = %v, want a wiring error", err)
	}
}

// serverError reports whether err is a plain server error: none of the
// middleware refusals, and nothing echo would render with a status of its own.
func serverError(err error) bool {
	for _, refusal := range []error{authkit.ErrMissingToken, authkit.ErrInvalidToken, authkit.ErrWrongAudience,
		authkit.ErrSessionEnded, authkit.ErrStale} {
		if errors.Is(err, refusal) {
			return false
		}
	}
	var sc echo.HTTPStatusCoder
	return err != nil && !errors.As(err, &sc)
}

func (f *fixture) token(t *testing.T, aud string) string {
	t.Helper()
	token, _, err := f.svc.Codec().Mint(uuid.New(), uuid.New(), aud, map[string]any{"role": "member"})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestParseBearerChecksItsOwnAudience(t *testing.T) {
	f := setup(t)
	var got *authkit.Claims
	err := run("Bearer "+f.token(t, "client"), []echo.MiddlewareFunc{echov5.ParseBearer(f.svc, "client")},
		func(c *echo.Context) error { got = echov5.Claims(c); return nil })
	if err != nil || got == nil || got.Audience != "client" {
		t.Fatalf("a client token on the client surface = %v, claims %+v", err, got)
	}
	err = run("Bearer "+f.token(t, "staff"), []echo.MiddlewareFunc{echov5.ParseBearer(f.svc, "client")},
		func(*echo.Context) error { t.Error("a staff token reached the client surface"); return nil })
	if err != authkit.ErrWrongAudience {
		t.Fatalf("a staff token on the client surface = %v, want ErrWrongAudience", err)
	}
}

func TestGuardNeedsAQuerier(t *testing.T) {
	f := setup(t)
	err := run("Bearer "+f.token(t, "staff"), []echo.MiddlewareFunc{
		echov5.ParseBearer(f.svc, "staff"),
		echov5.Guard(f.svc, func(*echo.Context) db.Querier { return nil }),
	}, func(*echo.Context) error { t.Error("Guard without a querier reached the handler"); return nil })
	if !serverError(err) {
		t.Fatalf("Guard without a querier = %v, want a wiring error", err)
	}
}

type failing struct {
	err   error
	calls int
}

func (q *failing) Exec(context.Context, string, ...any) (int64, error) { q.calls++; return 0, q.err }
func (q *failing) Query(context.Context, string, ...any) (db.Rows, error) {
	q.calls++
	return nil, q.err
}
func (q *failing) QueryRow(context.Context, string, ...any) db.Row {
	q.calls++
	return failingRow{q.err}
}
func (q *failing) InTx() bool { return false }

type failingRow struct{ err error }

func (r failingRow) Scan(...any) error { return r.err }

// TestGuardWrapsInfrastructureErrors: a failing database is neither a refusal
// (the SPA signs out on 401) nor a pass, and echo renders it as a bare 500.
func TestGuardWrapsInfrastructureErrors(t *testing.T) {
	f := setup(t)
	token := f.token(t, "staff")
	down := errors.New("pq: the database at 192.0.2.10 is down")
	q := &failing{err: down}
	chain := []echo.MiddlewareFunc{
		echov5.ParseBearer(f.svc, "staff"),
		echov5.Guard(f.svc, func(*echo.Context) db.Querier { return q }),
	}
	err := run("Bearer "+token, chain, func(*echo.Context) error {
		t.Error("a failed session check reached the handler")
		return nil
	})
	if !errors.Is(err, down) || !serverError(err) || q.calls == 0 {
		t.Fatalf("Guard on a failing database = %v after %d queries, want the failure wrapped", err, q.calls)
	}
	e := echo.New()
	e.GET("/", ok, chain...)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "192.0.2.10") {
		t.Fatalf("echo rendered %d %s", rec.Code, rec.Body)
	}
}

func TestAdmissionIsAbsentBeforeGuard(t *testing.T) {
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	if adm, ok := echov5.Admission(c); ok || adm.Context != nil || echov5.Claims(c) != nil {
		t.Fatalf("an empty context = %+v, %v, claims %v", adm, ok, echov5.Claims(c))
	}
}

func TestGuardOnAnUnboundConnection(t *testing.T) {
	f := setup(t)
	var unbound *sql.Conn
	err := run("Bearer "+f.token(t, "staff"), []echo.MiddlewareFunc{
		echov5.ParseBearer(f.svc, "staff"),
		echov5.Guard(f.svc, func(*echo.Context) db.Querier { return sqldb.Conn(unbound) }),
	}, func(*echo.Context) error { t.Error("Guard on an unbound connection reached the handler"); return nil })
	if !serverError(err) {
		t.Fatalf("Guard on sqldb.Conn(nil) = %v, want a wiring error", err)
	}
}
