package authkit_test

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
)

// sessionWorld is a Session-mode world at the v0.2 defaults, as BMParts runs
// it: no issuer, no secret, 30 minutes idle, a 12-hour cap, a 15-minute
// rotation.
func sessionWorld(t *testing.T, tweaks ...func(*authkit.Config)) *world {
	t.Helper()
	session := func(c *authkit.Config) { c.Transport, c.Issuer, c.Secret = authkit.TransportSession, "", nil }
	return newWorld(t, append([]func(*authkit.Config){defaults, session}, tweaks...)...)
}

func (w *world) authenticateSession(aud authkit.Audience, raw string) authkit.Result {
	w.t.Helper()
	return w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.AuthenticateSession(w.ctx, q, aud, raw, authkit.Meta{IP: "192.0.2.4", UserAgent: "authkit-test"})
	})
}

// sessionRow is a session's token hashes and expiry as stored.
type sessionRow struct {
	token, prev []byte
	expires     time.Time
	rotated     *time.Time
	reason      *string
}

func (w *world) sessionRow(res authkit.Result) sessionRow {
	w.t.Helper()
	var r sessionRow
	if err := w.d.Row(w.t, `SELECT token_hash, prev_token_hash, expires_at, rotated_at, revoke_reason FROM auth_sessions WHERE id = $1`,
		res.Session.ID).Scan(&r.token, &r.prev, &r.expires, &r.rotated, &r.reason); err != nil {
		w.t.Fatal(err)
	}
	return r
}

func TestSessionModeLoginIssuesASessionToken(t *testing.T) {
	w := sessionWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
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
	id := w.user("ada@example.invalid", "the right password")
	signed := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(10 * time.Second)
	res := w.authenticateSession("staff", signed.SessionToken)
	if res.Refusal != nil || res.Principal.ID != id || res.Session.ID != signed.Session.ID || res.Admission == nil ||
		res.Admission.Context != "member" || res.SessionToken != "" {
		t.Fatalf("AuthenticateSession = %+v", res)
	}
	if c := res.Claims(); c.Subject != id || c.SessionID != signed.Session.ID {
		t.Fatalf("Claims() = %+v", c)
	}
}

// TestAuthenticateSessionRefusals is spec §3.5 rules 4 and 5: each is
// ErrSessionEnded, and none writes.
func TestAuthenticateSessionRefusals(t *testing.T) {
	w := sessionWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	revoked := w.signIn("ada@example.invalid", "the right password")
	expired := w.signIn("ada@example.invalid", "the right password")
	other := w.signIn("ada@example.invalid", "the right password")
	refused := w.signIn("ada@example.invalid", "the right password")
	w.d.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, revoked.Session.ID, w.clock.Now())
	w.d.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, expired.Session.ID, w.clock.Now())
	before := w.count(`SELECT count(*) FROM auth_events`)
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
	w.p.Refuse(id, errors.New("app: deactivated"))
	if res := w.authenticateSession("staff", refused.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Errorf("an Admit refusal = %v, want ErrSessionEnded: cookie mode has no ErrStale", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_events`) != before || w.count(`SELECT count(*) FROM auth_sessions WHERE last_seen_at IS NOT NULL`) != 0 {
		t.Fatal("a refused request logged or touched a session")
	}
}

// TestAuthenticateSessionSlidesAtMostOnceAMinute is spec §3.5 rule 6: the
// idle expiry and last_seen_at move together, in one UPDATE, at most once a
// minute.
func TestAuthenticateSessionSlidesAtMostOnceAMinute(t *testing.T) {
	w := sessionWorld(t)
	w.user("ada@example.invalid", "the right password")
	signed := w.signIn("ada@example.invalid", "the right password")
	conn := w.pinned(signed.Principal.ID)
	t0 := w.clock.Now()
	authenticate := func() int {
		var execs int
		w.inConn(conn, func(q db.Querier) (authkit.Result, error) {
			cq := &countingQuerier{Querier: q}
			res, err := w.svc.AuthenticateSession(w.ctx, cq, "staff", signed.SessionToken, authkit.Meta{})
			execs = cq.execs
			return res, err
		})
		return execs
	}
	w.clock.Advance(10 * time.Second)
	if n := authenticate(); n != 1 || !w.sessionRow(signed).expires.Equal(t0.Add(30*time.Minute+10*time.Second)) {
		t.Fatalf("the first request wrote %d statements, expiry %v; want one slide to t0+30m10s", n, w.sessionRow(signed).expires)
	}
	w.clock.Advance(30 * time.Second)
	if n := authenticate(); n != 0 || !w.sessionRow(signed).expires.Equal(t0.Add(30*time.Minute+10*time.Second)) {
		t.Fatalf("a request 30s later wrote %d statements; want none", n)
	}
	w.clock.Advance(31 * time.Second)
	if n := authenticate(); n != 1 || !w.sessionRow(signed).expires.Equal(t0.Add(31*time.Minute+11*time.Second)) {
		t.Fatalf("a request a minute after the slide wrote %d statements, expiry %v; want one slide to t0+31m11s", n, w.sessionRow(signed).expires)
	}
}

// TestAnIdleSessionEndsAndABusyOneEndsAtTheCap: 30 minutes without a
// request end a session; a session used every 20 minutes lives until its
// 12-hour cap and no longer, its rotations included.
func TestAnIdleSessionEndsAndABusyOneEndsAtTheCap(t *testing.T) {
	w := sessionWorld(t)
	w.user("ada@example.invalid", "the right password")
	idle := w.signIn("ada@example.invalid", "the right password")
	busy := w.signIn("ada@example.invalid", "the right password")
	t0, raw := w.clock.Now(), busy.SessionToken
	for w.clock.Now().Before(t0.Add(12*time.Hour - 20*time.Minute)) {
		w.clock.Advance(20 * time.Minute)
		res := w.authenticateSession("staff", raw)
		if res.Refusal != nil {
			t.Fatalf("a request %v after the sign-in = %v", w.clock.Now().Sub(t0), res.Refusal)
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
	w.clock.Advance(20 * time.Minute)
	if res := w.authenticateSession("staff", raw); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a busy session past its cap = %v, want ErrSessionEnded", res.Refusal)
	}
}

// TestRotationSwapsTheTokenAfterRotateEvery is spec §3.5 rule 7.
func TestRotationSwapsTheTokenAfterRotateEvery(t *testing.T) {
	w := sessionWorld(t)
	w.user("ada@example.invalid", "the right password")
	signed := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(15*time.Minute - time.Second)
	if res := w.authenticateSession("staff", signed.SessionToken); res.Refusal != nil || res.SessionToken != "" {
		t.Fatalf("a token a second short of RotateEvery = %+v; want it kept", res)
	}
	w.clock.Advance(time.Second)
	res := w.authenticateSession("staff", signed.SessionToken)
	if res.Refusal != nil || res.SessionToken == "" || res.SessionToken == signed.SessionToken {
		t.Fatalf("a token RotateEvery old = %+v; want a new one", res)
	}
	now := w.clock.Now()
	if row := w.sessionRow(signed); !slices.Equal(row.token, authkit.HashToken(res.SessionToken)) ||
		!slices.Equal(row.prev, authkit.HashToken(signed.SessionToken)) || row.rotated == nil || !row.rotated.Equal(now) ||
		!row.expires.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("after the rotation: %+v; want the new hash, the old one as previous, rotated_at now and the expiry slid", row)
	}
	w.clock.Advance(14 * time.Minute)
	if next := w.authenticateSession("staff", res.SessionToken); next.Refusal != nil || next.SessionToken != "" {
		t.Fatalf("the new token 14 minutes on = %+v; want it admitted and kept: its age counts from rotated_at", next)
	}
}

func TestANegativeRotateEveryNeverRotates(t *testing.T) {
	w := sessionWorld(t, func(c *authkit.Config) { c.Session.RotateEvery = -1 })
	w.user("ada@example.invalid", "the right password")
	signed := w.signIn("ada@example.invalid", "the right password")
	for range 3 {
		w.clock.Advance(20 * time.Minute)
		if res := w.authenticateSession("staff", signed.SessionToken); res.Refusal != nil || res.SessionToken != "" {
			t.Fatalf("with rotation off = %+v; want the token kept", res)
		}
	}
}

// TestThePreviousTokenWithinTheGrace is spec §3.5 rule 2: a request that
// started before a rotation is admitted, with nothing written; a revoked
// session or a refused principal still ends it.
func TestThePreviousTokenWithinTheGrace(t *testing.T) {
	w := sessionWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	signed := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(15 * time.Minute)
	rotated := w.authenticateSession("staff", signed.SessionToken)
	w.clock.Advance(30 * time.Second)
	var execs int
	res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		cq := &countingQuerier{Querier: q}
		res, err := w.svc.AuthenticateSession(w.ctx, cq, "staff", signed.SessionToken, authkit.Meta{})
		execs = cq.execs
		return res, err
	})
	if res.Refusal != nil || res.SessionToken != "" || res.Session.ID != signed.Session.ID || execs != 0 {
		t.Fatalf("the previous token ReuseGrace after the rotation = %+v with %d writes; want admitted, kept, nothing written", res, execs)
	}
	if res := w.authenticateSession("client", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the previous token for another audience = %v, want ErrSessionEnded", res.Refusal)
	}
	w.p.Refuse(id, errors.New("app: deactivated"))
	if res := w.authenticateSession("staff", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the previous token of a refused principal = %v, want ErrSessionEnded", res.Refusal)
	}
	w.p.Allow(id)
	w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.Logout(w.ctx, q, rotated.Claims(), authkit.Meta{})
	})
	if res := w.authenticateSession("staff", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the previous token of a signed-out session = %v, want ErrSessionEnded", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE result = 'reuse_detected'`) != 0 {
		t.Fatal("a previous token within the grace was taken for a replay")
	}
}

// TestThePreviousTokenPastTheGraceRevokes is spec §3.5 rule 3: reuse
// revokes the session and logs it, and the refusal's writes commit.
func TestThePreviousTokenPastTheGraceRevokes(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.user("ada@example.invalid", "the right password")
	signed := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(15 * time.Minute)
	rotated := w.authenticateSession("staff", signed.SessionToken)
	w.clock.Advance(30*time.Second + time.Microsecond)
	if res := w.authenticateSession("staff", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the previous token past the grace = %v, want ErrSessionEnded", res.Refusal)
	}
	if row := w.sessionRow(signed); row.reason == nil || *row.reason != "reuse_detected" {
		t.Fatalf("the session's revoke reason = %v, want reuse_detected, committed with the refusal", row.reason)
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'reuse_detected' AND session_id = $2 AND ip = '192.0.2.4'`,
		id, signed.Session.ID) != 1 || !slices.Contains(c.pairs, "authenticate_session/reuse_detected") {
		t.Fatalf("the reuse was not logged from authenticate_session: %v", c.pairs)
	}
	if res := w.authenticateSession("staff", rotated.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the current token after a reuse = %v, want ErrSessionEnded", res.Refusal)
	}
}

// TestConcurrentRotationsHaveOneWinner: every request of a burst at the
// rotation age is admitted, exactly one swaps the token, and the losers
// fail nothing (spec §3.5 rule 7, then rule 2). A holder keeps the row
// locked until every request waits at the swap.
func TestConcurrentRotationsHaveOneWinner(t *testing.T) {
	w := sessionWorld(t)
	w.user("ada@example.invalid", "the right password")
	signed := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(15 * time.Minute)
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.ctx, `SELECT 1 FROM auth_sessions WHERE id = $1 FOR UPDATE`, signed.Session.ID); err != nil {
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
			err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
				var err error
				res, err = w.svc.AuthenticateSession(w.ctx, q, "staff", signed.SessionToken, authkit.Meta{})
				return err
			})
			out <- outcome{res, err}
		})
	}
	w.d.WaitForLockWaiters(t, n)
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

// TestEachTransportRefusesTheOthersMethods: calling a method of the other
// transport is a wiring error, never a refusal.
func TestEachTransportRefusesTheOthersMethods(t *testing.T) {
	sw := sessionWorld(t)
	id := sw.user("ada@example.invalid", "the right password")
	signed := sw.signIn("ada@example.invalid", "the right password")
	if err := sw.d.InAuthTx(sw.ctx, func(q db.Querier) error {
		_, err := sw.svc.Refresh(sw.ctx, q, "staff", signed.SessionToken, authkit.Meta{})
		return err
	}); err == nil {
		t.Error("Refresh on a Session-mode Service = nil error")
	}
	if _, err := sw.svc.Authenticate(sw.ctx, sqldb.Conn(sw.pinned(id)), signed.Claims()); err == nil {
		t.Error("Authenticate on a Session-mode Service = nil error")
	}
	bw := newWorld(t, defaults)
	bw.user("ada@example.invalid", "the right password")
	bearer := bw.signIn("ada@example.invalid", "the right password")
	if err := bw.d.InAuthTx(bw.ctx, func(q db.Querier) error {
		_, err := bw.svc.AuthenticateSession(bw.ctx, q, "staff", bearer.Tokens.RefreshToken, authkit.Meta{})
		return err
	}); err == nil {
		t.Error("AuthenticateSession on a Bearer Service = nil error")
	}
}

// TestTheAccountMethodsTakeResultClaims: Logout, ListSessions and
// RevokeSession run in Session mode on Result.Claims().
func TestTheAccountMethodsTakeResultClaims(t *testing.T) {
	w := sessionWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	other := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(time.Minute)
	signed := w.signIn("ada@example.invalid", "the right password")
	current := w.authenticateSession("staff", signed.SessionToken)
	conn := w.pinned(id)
	list, total, err := w.svc.ListSessions(w.ctx, sqldb.Conn(conn), current.Claims(), 10, 0)
	if err != nil || total != 2 || !list[0].Current || list[0].ID != current.Session.ID {
		t.Fatalf("ListSessions = %+v, %d (%v)", list, total, err)
	}
	w.clock.Advance(time.Second)
	if res := w.inConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.svc.RevokeSession(w.ctx, q, current.Claims(), other.Session.ID, authkit.Meta{})
	}); res.Refusal != nil {
		t.Fatalf("RevokeSession = %v", res.Refusal)
	}
	w.clock.Advance(time.Second)
	w.logout(conn, current.Claims())
	if got := w.results(id); !slices.Equal(got[len(got)-2:], []string{"revoked", "signed_out"}) {
		t.Fatalf("log = %v, want revoked, then signed_out", got)
	}
	if res := w.authenticateSession("staff", signed.SessionToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("after the logout = %v", res.Refusal)
	}
}
