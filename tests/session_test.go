package tests

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
)

func sessionWorld(t *testing.T, tweaks ...func(*kittest.Rules)) *world {
	t.Helper()
	session := func(c *kittest.Rules) { c.Transport, c.Issuer, c.Secret = authkit.TransportSession, "", nil }
	return newWorld(t, append([]func(*kittest.Rules){kittest.DefaultRules, session}, tweaks...)...)
}

func (w *world) authenticateSession(aud authkit.Audience, raw string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.AuthenticateSession(w.Ctx, q, aud, raw, authkit.Meta{IP: "192.0.2.4", UserAgent: "authkit-test"})
	})
}

type sessionRow struct {
	token, prev []byte
	expires     time.Time
	rotated     *time.Time
	reason      *string
}

func (w *world) sessionRow(res authkit.Result) sessionRow {
	w.T.Helper()
	var r sessionRow
	if err := w.D.Row(w.T, `SELECT token_hash, prev_token_hash, expires_at, rotated_at, revoke_reason FROM auth_sessions WHERE id = $1`,
		res.Session.ID).Scan(&r.token, &r.prev, &r.expires, &r.rotated, &r.reason); err != nil {
		w.T.Fatal(err)
	}
	return r
}

func TestSessionModeLoginIssuesASessionToken(t *testing.T) {
	w := sessionWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	res := w.SignIn("ada@example.invalid", "the right password")
	if res.SessionToken == "" || res.Tokens != nil || res.Principal.ID != id || res.Admission == nil {
		t.Fatalf("Session-mode Login = %+v; want a session token and no access token", res)
	}
	if row := w.sessionRow(res); !slices.Equal(row.token, authkit.HashToken(res.SessionToken)) {
		t.Fatal("the session does not store the session token's sha256")
	}
	if c := res.Claims(); c == nil || c.Subject != id || c.SessionID != res.Session.ID || c.Audience != "staff" {
		t.Fatalf("Claims() = %+v", c)
	}
	if (authkit.Result{}).Claims() != nil {
		t.Fatal("a Result without a session has Claims")
	}
}

func TestAuthenticateSessionAdmitsTheCurrentToken(t *testing.T) {
	w := sessionWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	signed := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(10 * time.Second)
	res := w.authenticateSession("staff", signed.SessionToken)
	if res.Refusal != nil || res.Principal.ID != id || res.Session.ID != signed.Session.ID || res.Admission == nil ||
		res.Admission.Context != "member" || res.SessionToken != "" {
		t.Fatalf("AuthenticateSession = %+v", res)
	}
	if c := res.Claims(); c.Subject != id || c.SessionID != signed.Session.ID {
		t.Fatalf("Claims() = %+v", c)
	}
}

func TestAuthenticateSessionRefusals(t *testing.T) {
	w := sessionWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	revoked := w.SignIn("ada@example.invalid", "the right password")
	expired := w.SignIn("ada@example.invalid", "the right password")
	other := w.SignIn("ada@example.invalid", "the right password")
	refused := w.SignIn("ada@example.invalid", "the right password")
	w.D.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, revoked.Session.ID, w.Clock.Now())
	w.D.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, expired.Session.ID, w.Clock.Now())
	before := w.Count(`SELECT count(*) FROM auth_events`)
	for name, tc := range map[string]struct {
		aud authkit.Audience
		raw string
	}{
		"unknown":        {"staff", "not-a-token"},
		"revoked":        {"staff", revoked.SessionToken},
		"expired":        {"staff", expired.SessionToken},
		"other audience": {"client", other.SessionToken},
	} {
		if res := w.authenticateSession(tc.aud, tc.raw); !errors.Is(res.Refusal, authkit.ErrSessionEnded) || res.Session != nil {
			t.Errorf("%s: %+v, want ErrSessionEnded", name, res)
		}
	}
	w.P.Refuse(id, errors.New("app: deactivated"))
	if res := w.authenticateSession("staff", refused.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Errorf("an Admit refusal = %v, want ErrSessionEnded: cookie mode has no ErrStale", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_events`) != before || w.Count(`SELECT count(*) FROM auth_sessions WHERE last_seen_at IS NOT NULL`) != 0 {
		t.Fatal("a refused request logged or touched a session")
	}
}

func TestAuthenticateSessionSlidesAtMostOnceAMinute(t *testing.T) {
	w := sessionWorld(t)
	w.User("ada@example.invalid", "the right password")
	signed := w.SignIn("ada@example.invalid", "the right password")
	conn := w.Pinned(signed.Principal.ID)
	t0 := w.Clock.Now()
	authenticate := func() int {
		var execs int
		w.InConn(conn, func(q db.Querier) (authkit.Result, error) {
			cq := &countingQuerier{Querier: q}
			res, err := w.Svc.AuthenticateSession(w.Ctx, cq, "staff", signed.SessionToken, authkit.Meta{})
			execs = cq.execs
			return res, err
		})
		return execs
	}
	w.Clock.Advance(10 * time.Second)
	if n := authenticate(); n != 1 || !w.sessionRow(signed).expires.Equal(t0.Add(30*time.Minute+10*time.Second)) {
		t.Fatalf("the first request wrote %d statements, expiry %v; want one slide to t0+30m10s", n, w.sessionRow(signed).expires)
	}
	w.Clock.Advance(30 * time.Second)
	if n := authenticate(); n != 0 || !w.sessionRow(signed).expires.Equal(t0.Add(30*time.Minute+10*time.Second)) {
		t.Fatalf("a request 30s later wrote %d statements; want none", n)
	}
	w.Clock.Advance(31 * time.Second)
	if n := authenticate(); n != 1 || !w.sessionRow(signed).expires.Equal(t0.Add(31*time.Minute+11*time.Second)) {
		t.Fatalf("a request a minute after the slide wrote %d statements, expiry %v; want one slide to t0+31m11s", n, w.sessionRow(signed).expires)
	}
}

func TestAnIdleSessionEndsAndABusyOneEndsAtTheCap(t *testing.T) {
	w := sessionWorld(t)
	w.User("ada@example.invalid", "the right password")
	idle := w.SignIn("ada@example.invalid", "the right password")
	busy := w.SignIn("ada@example.invalid", "the right password")
	t0, raw := w.Clock.Now(), busy.SessionToken
	for w.Clock.Now().Before(t0.Add(12*time.Hour - 20*time.Minute)) {
		w.Clock.Advance(20 * time.Minute)
		res := w.authenticateSession("staff", raw)
		if res.Refusal != nil {
			t.Fatalf("a request %v after the sign-in = %v", w.Clock.Now().Sub(t0), res.Refusal)
		}
		if res.SessionToken != "" {
			raw = res.SessionToken
		}
	}
	if row := w.sessionRow(busy); !row.expires.Equal(t0.Add(12 * time.Hour)) {
		t.Fatalf("a busy session's expiry = %v, want the cap t0+12h", row.expires)
	}
	if res := w.authenticateSession("staff", idle.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a session idle for 12h = %v, want ErrSessionEnded", res.Refusal)
	}
	w.Clock.Advance(20 * time.Minute)
	if res := w.authenticateSession("staff", raw); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a busy session past its cap = %v, want ErrSessionEnded", res.Refusal)
	}
}

func TestRotationSwapsTheTokenAfterRotateEvery(t *testing.T) {
	w := sessionWorld(t)
	w.User("ada@example.invalid", "the right password")
	signed := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(15*time.Minute - time.Second)
	if res := w.authenticateSession("staff", signed.SessionToken); res.Refusal != nil || res.SessionToken != "" {
		t.Fatalf("a token a second short of RotateEvery = %+v; want it kept", res)
	}
	w.Clock.Advance(time.Second)
	res := w.authenticateSession("staff", signed.SessionToken)
	if res.Refusal != nil || res.SessionToken == "" || res.SessionToken == signed.SessionToken {
		t.Fatalf("a token RotateEvery old = %+v; want a new one", res)
	}
	now := w.Clock.Now()
	if row := w.sessionRow(signed); !slices.Equal(row.token, authkit.HashToken(res.SessionToken)) ||
		!slices.Equal(row.prev, authkit.HashToken(signed.SessionToken)) || row.rotated == nil || !row.rotated.Equal(now) ||
		!row.expires.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("after the rotation: %+v; want the new hash, the old one as previous, rotated_at now and the expiry slid", row)
	}
	w.Clock.Advance(14 * time.Minute)
	if next := w.authenticateSession("staff", res.SessionToken); next.Refusal != nil || next.SessionToken != "" {
		t.Fatalf("the new token 14 minutes on = %+v; want it admitted and kept: its age counts from rotated_at", next)
	}
}

func TestANegativeRotateEveryNeverRotates(t *testing.T) {
	w := sessionWorld(t, func(c *kittest.Rules) { c.Session.RotateEvery = -1 })
	w.User("ada@example.invalid", "the right password")
	signed := w.SignIn("ada@example.invalid", "the right password")
	for range 3 {
		w.Clock.Advance(20 * time.Minute)
		if res := w.authenticateSession("staff", signed.SessionToken); res.Refusal != nil || res.SessionToken != "" {
			t.Fatalf("with rotation off = %+v; want the token kept", res)
		}
	}
}

func TestThePreviousTokenWithinTheGrace(t *testing.T) {
	w := sessionWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	signed := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(15 * time.Minute)
	rotated := w.authenticateSession("staff", signed.SessionToken)
	w.Clock.Advance(30 * time.Second)
	var execs int
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		cq := &countingQuerier{Querier: q}
		res, err := w.Svc.AuthenticateSession(w.Ctx, cq, "staff", signed.SessionToken, authkit.Meta{})
		execs = cq.execs
		return res, err
	})
	if res.Refusal != nil || res.SessionToken != "" || res.Session.ID != signed.Session.ID || execs != 0 {
		t.Fatalf("the previous token ReuseGrace after the rotation = %+v with %d writes; want admitted, kept, nothing written", res, execs)
	}
	if res := w.authenticateSession("client", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the previous token for another audience = %v, want ErrSessionEnded", res.Refusal)
	}
	w.P.Refuse(id, errors.New("app: deactivated"))
	if res := w.authenticateSession("staff", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the previous token of a refused principal = %v, want ErrSessionEnded", res.Refusal)
	}
	w.P.Allow(id)
	w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Logout(w.Ctx, q, rotated.Claims(), authkit.Meta{})
	})
	if res := w.authenticateSession("staff", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the previous token of a signed-out session = %v, want ErrSessionEnded", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE result = 'reuse_detected'`) != 0 {
		t.Fatal("a previous token within the grace was taken for a replay")
	}
}

func TestThePreviousTokenPastTheGraceRevokes(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *kittest.Rules) { cfg.OnEvent = c.onEvent })
	id := w.User("ada@example.invalid", "the right password")
	signed := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(15 * time.Minute)
	rotated := w.authenticateSession("staff", signed.SessionToken)
	w.Clock.Advance(30*time.Second + time.Microsecond)
	if res := w.authenticateSession("staff", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the previous token past the grace = %v, want ErrSessionEnded", res.Refusal)
	}
	if row := w.sessionRow(signed); row.reason == nil || *row.reason != "reuse_detected" {
		t.Fatalf("the session's revoke reason = %v, want reuse_detected, committed with the refusal", row.reason)
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'reuse_detected' AND session_id = $2 AND ip = '192.0.2.4'`,
		id, signed.Session.ID) != 1 || !slices.Contains(c.pairs, "authenticate_session/reuse_detected") {
		t.Fatalf("the reuse was not logged from authenticate_session: %v", c.pairs)
	}
	if res := w.authenticateSession("staff", rotated.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the current token after a reuse = %v, want ErrSessionEnded", res.Refusal)
	}
}

// WHY: a holder keeps the row locked until every request waits at the swap, so the burst contends at once.
func TestConcurrentRotationsHaveOneWinner(t *testing.T) {
	w := sessionWorld(t)
	w.User("ada@example.invalid", "the right password")
	signed := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(15 * time.Minute)
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.Ctx, `SELECT 1 FROM auth_sessions WHERE id = $1 FOR UPDATE`, signed.Session.ID); err != nil {
		t.Fatal(err)
	}
	const n = 8
	type outcome struct {
		res authkit.Result
		err error
	}
	out := make(chan outcome, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			var res authkit.Result
			err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
				var err error
				res, err = w.Svc.AuthenticateSession(w.Ctx, q, "staff", signed.SessionToken, authkit.Meta{})
				return err
			})
			out <- outcome{res, err}
		})
	}
	w.D.WaitForLockWaiters(t, n)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(out)
	var winners []string
	for o := range out {
		switch {
		case o.err != nil || o.res.Refusal != nil:
			t.Errorf("a request of the burst = %v, %v", o.res.Refusal, o.err)
		case o.res.SessionToken != "":
			winners = append(winners, o.res.SessionToken)
		}
	}
	if len(winners) != 1 || !slices.Equal(w.sessionRow(signed).token, authkit.HashToken(winners[0])) {
		t.Fatalf("%d requests swapped the token, want exactly 1, the one stored", len(winners))
	}
}

func TestEachTransportRefusesTheOthersMethods(t *testing.T) {
	sw := sessionWorld(t)
	id := sw.User("ada@example.invalid", "the right password")
	signed := sw.SignIn("ada@example.invalid", "the right password")
	if err := sw.D.InAuthTx(sw.Ctx, func(q db.Querier) error {
		_, err := sw.Svc.Refresh(sw.Ctx, q, "staff", signed.SessionToken, authkit.Meta{})
		return err
	}); err == nil {
		t.Error("Refresh on a Session-mode Service = nil error")
	}
	if _, err := sw.Svc.Authenticate(sw.Ctx, sqldb.Conn(sw.Pinned(id)), signed.Claims()); err == nil {
		t.Error("Authenticate on a Session-mode Service = nil error")
	}
	bw := newWorld(t, kittest.DefaultRules)
	bw.User("ada@example.invalid", "the right password")
	bearer := bw.SignIn("ada@example.invalid", "the right password")
	if err := bw.D.InAuthTx(bw.Ctx, func(q db.Querier) error {
		_, err := bw.Svc.AuthenticateSession(bw.Ctx, q, "staff", bearer.Tokens.RefreshToken, authkit.Meta{})
		return err
	}); err == nil {
		t.Error("AuthenticateSession on a Bearer Service = nil error")
	}
}

func TestTheAccountMethodsTakeResultClaims(t *testing.T) {
	w := sessionWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	other := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(time.Minute)
	signed := w.SignIn("ada@example.invalid", "the right password")
	current := w.authenticateSession("staff", signed.SessionToken)
	conn := w.Pinned(id)
	list, total, err := w.Svc.ListSessions(w.Ctx, sqldb.Conn(conn), current.Claims(), 10, 0)
	if err != nil || total != 2 || !list[0].Current || list[0].ID != current.Session.ID {
		t.Fatalf("ListSessions = %+v, %d (%v)", list, total, err)
	}
	w.Clock.Advance(time.Second)
	if res := w.InConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.Svc.RevokeSession(w.Ctx, q, current.Claims(), other.Session.ID, authkit.Meta{})
	}); res.Refusal != nil {
		t.Fatalf("RevokeSession = %v", res.Refusal)
	}
	w.Clock.Advance(time.Second)
	w.logout(conn, current.Claims())
	if got := w.Results(id); !slices.Equal(got[len(got)-2:], []string{"revoked", "signed_out"}) {
		t.Fatalf("log = %v, want revoked, then signed_out", got)
	}
	if res := w.authenticateSession("staff", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("after the logout = %v", res.Refusal)
	}
}
