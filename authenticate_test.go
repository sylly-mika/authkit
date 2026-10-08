package authkit_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
)

func (w *world) authenticate(conn *sql.Conn, c *authkit.Claims) authkit.Result {
	w.t.Helper()
	res, err := w.svc.Authenticate(w.ctx, sqldb.Conn(conn), c)
	if err != nil {
		w.t.Fatalf("Authenticate: %v", err)
	}
	return res
}

func TestAuthenticateAdmitsAnOpenSessionOnAPinnedConnection(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.authenticate(w.pinned(id), w.claims(w.signIn("ada@example.invalid", "the right password")))
	if res.Refusal != nil || res.Admission == nil || res.Admission.Context != "member" {
		t.Fatalf("Authenticate = %+v", res)
	}
}

// The four refusals below are spec §8.5 (†): no request through Guard
// succeeds after its session is revoked or expired, or once Admit refuses it
// or its claims go stale.
func TestAuthenticateRefusesARevokedSession(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	w.d.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'user' WHERE id = $1`, res.Session.ID, w.clock.Now())
	if got := w.authenticate(w.pinned(id), w.claims(res)); !errors.Is(got.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a revoked session = %v, want ErrSessionEnded", got.Refusal)
	}
}

func TestAuthenticateRefusesAnExpiredSession(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	c := w.claims(res)
	w.d.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, res.Session.ID, w.clock.Now().Add(time.Minute))
	w.clock.Advance(time.Minute)
	if got := w.authenticate(w.pinned(id), c); !errors.Is(got.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("an expired session = %v, want ErrSessionEnded", got.Refusal)
	}
}

func TestAuthenticateRefusesWhenAdmitRefuses(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.p.Refuse(id, errors.New("app: deactivated"))
	if got := w.authenticate(w.pinned(id), c); !errors.Is(got.Refusal, authkit.ErrStale) {
		t.Fatalf("an Admit refusal = %v, want ErrStale (ino-tasks token_stale)", got.Refusal)
	}
}

func TestAuthenticateRefusesStaleClaims(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	conn := w.pinned(id)
	if got := w.authenticate(conn, c); got.Refusal != nil {
		t.Fatalf("unchanged claims with a uuid ws = %v: the JSON round trip failed", got.Refusal)
	}
	w.p.SetRole(id, "admin")
	if got := w.authenticate(conn, c); !errors.Is(got.Refusal, authkit.ErrStale) {
		t.Fatalf("a changed role = %v, want ErrStale", got.Refusal)
	}
}

// Refresh and Guard ask Admit about the session's own scope (spec §7), not
// whatever scope the app would pick for a fresh login.
func TestRefreshAndAuthenticateAdmitTheSessionsScope(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	bound, conn := *first.Session.ScopeID, w.pinned(id)
	w.p.Scope = uuid.New()
	if got := w.authenticate(conn, w.claims(first)); got.Refusal != nil {
		t.Fatalf("Authenticate after the app's login scope moved = %v, want the session's scope admitted", got.Refusal)
	}
	if ws := w.claims(w.refresh("staff", first.Tokens.RefreshToken)).App["ws"]; ws != bound.String() {
		t.Fatalf("refreshed ws = %v, want the session's scope %v", ws, bound)
	}
}

func TestAuthenticateRefusesAnotherPrincipalsSession(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	other := w.user("bob@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	c.Subject = other
	if got := w.authenticate(w.pinned(other), c); !errors.Is(got.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("someone else's session id = %v, want ErrSessionEnded", got.Refusal)
	}
}

// Where RLS shows every session (the auth policy here, an app without RLS in
// the fleet), only the library's principal predicate keeps a token's subject
// to its own sessions.
func TestAnotherPrincipalsSessionWithoutRLS(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	other := w.user("bob@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	c := w.claims(res)
	c.Subject = other
	if got := w.inAuth(func(q db.Querier) (authkit.Result, error) { return w.svc.Authenticate(w.ctx, q, c) }); !errors.Is(got.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("Authenticate of another principal's session = %v, want ErrSessionEnded", got.Refusal)
	}
	if got := w.inAuth(func(q db.Querier) (authkit.Result, error) { return w.svc.Logout(w.ctx, q, c, authkit.Meta{}) }); got.Session != nil {
		t.Fatalf("Logout of another principal's session ended %v", got.Session.ID)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, res.Session.ID) != 1 ||
		w.count(`SELECT count(*) FROM auth_events WHERE result = 'signed_out'`) != 0 {
		t.Fatal("another principal's claims ended or logged the session")
	}
}

func TestAuthenticateRefusesAnotherAudience(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	c.Audience = "client"
	if got := w.authenticate(w.pinned(id), c); !errors.Is(got.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a staff session under client claims = %v, want ErrSessionEnded", got.Refusal)
	}
}

func TestAuthenticateTouchesAtMostOnceAMinute(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	c, conn := w.claims(res), w.pinned(id)
	seen := func() time.Time {
		var at time.Time
		if err := w.d.Row(t, `SELECT last_seen_at FROM auth_sessions WHERE id = $1`, res.Session.ID).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	t0 := w.clock.Now()
	w.authenticate(conn, c)
	w.clock.Advance(30 * time.Second)
	w.authenticate(conn, c)
	if !seen().Equal(t0) {
		t.Fatal("touched twice within a minute")
	}
	w.clock.Advance(31 * time.Second)
	w.authenticate(conn, c)
	if !seen().Equal(w.clock.Now()) {
		t.Fatal("not touched after a minute")
	}
}

type countingQuerier struct {
	db.Querier
	execs int
}

func (q *countingQuerier) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	q.execs++
	return q.Querier.Exec(ctx, query, args...)
}

// Guard's read path writes once a minute at most, not a no-op UPDATE per request.
func TestAuthenticateWritesAtMostOnceAMinute(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	q, c := &countingQuerier{Querier: sqldb.Conn(w.pinned(id))}, w.claims(res)
	for range 2 {
		if got, err := w.svc.Authenticate(w.ctx, q, c); err != nil || got.Refusal != nil {
			t.Fatalf("Authenticate = %+v, %v", got, err)
		}
	}
	if q.execs != 1 {
		t.Fatalf("%d statements written for two requests in one minute, want 1 (the first touch)", q.execs)
	}
}

func (w *world) logout(conn *sql.Conn, c *authkit.Claims) {
	w.t.Helper()
	w.inConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.svc.Logout(w.ctx, q, c, authkit.Meta{IP: "192.0.2.2"})
	})
}

func TestLogoutRevokesAndLogsOnce(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	c, conn := w.claims(res), w.pinned(id)
	w.clock.Advance(time.Second)
	w.logout(conn, c)
	w.logout(conn, c)
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'logout'`, res.Session.ID) != 1 {
		t.Fatal("logout did not revoke with reason logout")
	}
	if got := w.results(id); !slices.Equal(got, []string{"signed_in", "signed_out"}) {
		t.Fatalf("log = %v, want one signed_out: a repeated logout logs nothing", got)
	}
	if got := w.authenticate(conn, c); !errors.Is(got.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("after logout = %v", got.Refusal)
	}
}

func TestLogoutOfAnExpiredSessionLogsNothing(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	w.d.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, res.Session.ID, w.clock.Now())
	w.logout(w.pinned(id), w.claims(res))
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, res.Session.ID) != 1 || len(w.results(id)) != 1 {
		t.Fatal("logging out of an expired session revoked or logged")
	}
}

func TestConcurrentLogoutsLogOnce(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	c := w.claims(res)
	const n = 8
	conns := make([]*sql.Conn, n)
	for i := range conns {
		conns[i] = w.pinned(id)
	}
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.ctx, `SELECT 1 FROM auth_sessions WHERE id = $1 FOR UPDATE`, res.Session.ID); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Go(func() {
			errs <- authkittest.InConnTx(w.ctx, conn, func(q db.Querier) error {
				_, err := w.svc.Logout(w.ctx, q, c, authkit.Meta{})
				return err
			})
		})
	}
	w.d.WaitForLockWaiters(t, n)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := w.results(id); !slices.Equal(got, []string{"signed_in", "signed_out"}) {
		t.Fatalf("log = %v, want one signed_out for %d concurrent logouts", got, n)
	}
}

// TestRefreshAndLogoutCleanMeta: the reuse branch and Logout log the request's
// metadata, so a NUL or invalid UTF-8 in it must not turn their result into an
// error, as it does not Login's.
func TestRefreshAndLogoutCleanMeta(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	dirty := authkit.Meta{IP: "192.0.2.3\x00", UserAgent: "authkit-\xfftest\x00"}
	first := w.signIn("ada@example.invalid", "the right password")
	w.refresh("staff", first.Tokens.RefreshToken)
	w.clock.Advance(31 * time.Second)
	replay := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.Refresh(w.ctx, q, "staff", first.Tokens.RefreshToken, dirty)
	})
	if !errors.Is(replay.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a replay with a NUL in its metadata = %v, want ErrSessionEnded", replay.Refusal)
	}
	other := w.signIn("ada@example.invalid", "the right password")
	if out := w.inConn(w.pinned(id), func(q db.Querier) (authkit.Result, error) {
		return w.svc.Logout(w.ctx, q, w.claims(other), dirty)
	}); out.Refusal != nil || out.Session == nil {
		t.Fatalf("a logout with a NUL in its metadata = %+v", out)
	}
	cleaned := `SELECT count(*) FROM auth_events WHERE result = $1 AND session_id = $2 AND ip = '192.0.2.3' AND user_agent = 'authkit-test'`
	if w.count(cleaned, "reuse_detected", first.Session.ID) != 1 || w.count(cleaned, "signed_out", other.Session.ID) != 1 {
		t.Fatal("the reuse_detected or signed_out event does not hold the cleaned IP and user agent")
	}
}
