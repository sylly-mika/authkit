package authkit_test

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

func (w *world) refresh(aud authkit.Audience, raw string) authkit.Result {
	w.t.Helper()
	return w.inAuth(func(q db.Querier) (authkit.Result, error) { return w.svc.Refresh(w.ctx, q, aud, raw, authkit.Meta{}) })
}

func TestRefreshRotatesAndSlidesTheExpiry(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(24 * time.Hour)
	next := w.refresh("staff", first.Tokens.RefreshToken)
	if next.Refusal != nil || next.Tokens.RefreshToken == first.Tokens.RefreshToken {
		t.Fatalf("refresh = %+v", next)
	}
	now := w.clock.Now()
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND token_hash = $2 AND prev_token_hash = $3 AND rotated_at = $4 AND expires_at = $5`,
		first.Session.ID, authkit.HashToken(next.Tokens.RefreshToken), authkit.HashToken(first.Tokens.RefreshToken), now, now.Add(7*24*time.Hour)) != 1 {
		t.Fatal("the rotation did not keep the old hash, stamp rotated_at and slide expires_at (spec §8.1)")
	}
	if c := w.claims(next); c.Subject != id || c.SessionID != first.Session.ID {
		t.Fatalf("refreshed claims = %+v", c)
	}
}

func TestRefreshSlidesByTheAudiencesTTL(t *testing.T) {
	w := newWorld(t, func(c *authkit.Config) {
		c.RefreshTTLFor = map[authkit.Audience]time.Duration{"staff": time.Hour}
	})
	w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(time.Minute)
	next := w.refresh("staff", first.Tokens.RefreshToken)
	want := w.clock.Now().Add(time.Hour)
	if next.Refusal != nil || !next.Session.ExpiresAt.Equal(want) ||
		w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND expires_at = $2`, first.Session.ID, want) != 1 {
		t.Fatalf("refresh = %+v; want the session to slide to now + RefreshTTLFor[staff] = %v", next, want)
	}
}

// TestRefreshConcurrentOneWinner is spec §8.1 (†). A holder locks the
// session row first, so all 16 refreshes are in flight before any can win:
// with the lock they queue at LockForRefresh; without it (M1) they all read
// the row and queue at Rotate, and the losers fail.
func TestRefreshConcurrentOneWinner(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.ctx, `SELECT 1 FROM auth_sessions WHERE id = $1 FOR UPDATE`, first.Session.ID); err != nil {
		t.Fatal(err)
	}
	const n = 16
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
				res, err = w.svc.Refresh(w.ctx, q, "staff", first.Tokens.RefreshToken, authkit.Meta{})
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
	var winners []authkit.Result
	losers := 0
	for o := range out {
		switch {
		case o.err != nil:
			t.Errorf("a refresh failed: %v", o.err)
		case o.res.Refusal == nil:
			winners = append(winners, o.res)
		case errors.Is(o.res.Refusal, authkit.ErrSessionEnded):
			losers++
		default:
			t.Errorf("a refresh was refused with %v", o.res.Refusal)
		}
	}
	if len(winners) != 1 || losers != n-1 {
		t.Fatalf("%d refreshes won and %d lost, want 1 and %d", len(winners), losers, n-1)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, first.Session.ID) != 1 {
		t.Fatal("losers inside the grace revoked the session")
	}
	if got := w.results(id); !slices.Equal(got, []string{"signed_in"}) {
		t.Fatalf("log = %v, want the %d losers to log nothing", got, n-1)
	}
	if res := w.refresh("staff", winners[0].Tokens.RefreshToken); res.Refusal != nil {
		t.Fatalf("the winner's token = %v", res.Refusal)
	}
}

func TestALoserInsideTheGraceKeepsTheSession(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	next := w.refresh("staff", first.Tokens.RefreshToken)
	w.clock.Advance(10 * time.Second)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the rotated-away token = %v, want ErrSessionEnded", res.Refusal)
	}
	if res := w.refresh("staff", next.Tokens.RefreshToken); res.Refusal != nil {
		t.Fatalf("the current token after a loser = %v", res.Refusal)
	}
}

// The grace is inclusive (spec §8.1 "within ReuseGrace", §8.3 "older than"):
// a token rotated away exactly ReuseGrace ago is a loser that writes nothing;
// a microsecond later it is a replay.
func TestTheGraceIsInclusive(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	w.refresh("staff", first.Tokens.RefreshToken)
	w.clock.Advance(30 * time.Second)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a token rotated away exactly ReuseGrace ago = %v, want ErrSessionEnded", res.Refusal)
	}
	if got := w.results(id); !slices.Equal(got, []string{"signed_in"}) || w.count(`SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL`) != 1 {
		t.Fatalf("a loser at exactly ReuseGrace wrote: log %v; want nothing written and the session alive", got)
	}
	w.clock.Advance(time.Microsecond)
	w.refresh("staff", first.Tokens.RefreshToken)
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'reuse_detected'`, first.Session.ID) != 1 {
		t.Fatal("a microsecond past ReuseGrace is not a replay")
	}
}

// TestRefreshReuseAfterGraceRevokes is spec §8.3 (†).
func TestRefreshReuseAfterGraceRevokes(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	next := w.refresh("staff", first.Tokens.RefreshToken)
	w.clock.Advance(31 * time.Second)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a replayed token = %v, want ErrSessionEnded", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'reuse_detected'`, first.Session.ID) != 1 {
		t.Fatal("the replay did not revoke the session")
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'reuse_detected' AND session_id = $2`, id, first.Session.ID) != 1 {
		t.Fatal("the replay was not logged")
	}
	if res := w.refresh("staff", next.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the thief's or the owner's current token still works: %v", res.Refusal)
	}
}

// Concurrent replays of one rotated-away token queue on LockByPrevious's row
// lock: one revokes and logs, the rest find the session ended.
func TestConcurrentReplaysRevokeAndLogOnce(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	w.refresh("staff", first.Tokens.RefreshToken)
	w.clock.Advance(31 * time.Second)
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.ctx, `SELECT 1 FROM auth_sessions WHERE id = $1 FOR UPDATE`, first.Session.ID); err != nil {
		t.Fatal(err)
	}
	const n = 16
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			errs <- w.d.InAuthTx(w.ctx, func(q db.Querier) error {
				res, err := w.svc.Refresh(w.ctx, q, "staff", first.Tokens.RefreshToken, authkit.Meta{})
				if err == nil && !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
					return fmt.Errorf("a replay = %v, want ErrSessionEnded", res.Refusal)
				}
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
	if got := w.results(id); !slices.Equal(got, []string{"signed_in", "reuse_detected"}) {
		t.Fatalf("log = %v, want one reuse_detected for %d concurrent replays", got, n)
	}
}

// A replay of a session that reuse detection already revoked is a plain
// refusal: it neither revokes again nor logs a second reuse_detected.
func TestAReplayOfARevokedSessionWritesNothing(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	w.refresh("staff", first.Tokens.RefreshToken)
	w.clock.Advance(31 * time.Second)
	w.refresh("staff", first.Tokens.RefreshToken)
	w.clock.Advance(time.Minute)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a second replay = %v, want ErrSessionEnded", res.Refusal)
	}
	if got := w.results(id); !slices.Equal(got, []string{"signed_in", "reuse_detected"}) {
		t.Fatalf("log = %v, want one reuse_detected: the second replay finds no open session", got)
	}
}

func TestATokenTwoRotationsOldIsAPlainRefusal(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	second := w.refresh("staff", first.Tokens.RefreshToken)
	w.clock.Advance(time.Minute)
	w.refresh("staff", second.Tokens.RefreshToken)
	w.clock.Advance(time.Minute)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a token two rotations old = %v", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL`) != 0 {
		t.Fatal("only the immediately previous token is detected; an older one must not revoke (spec §8.3)")
	}
}

func TestRefreshIsBoundToTheAudience(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	if res := w.refresh("client", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a staff token refreshed as client = %v", res.Refusal)
	}
	if res := w.refresh("staff", first.Tokens.RefreshToken); res.Refusal != nil {
		t.Fatalf("the wrong-audience attempt spent the token: %v", res.Refusal)
	}
}

func TestARefreshAdmitRefusesWritesNothing(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	errNoMembership := errors.New("app: no membership")
	w.p.Refuse(id, errNoMembership)
	if res := w.refresh("staff", first.Tokens.RefreshToken); res.Refusal != errNoMembership {
		t.Fatalf("refresh = %v, want the app's refusal unchanged (ino-tasks 403)", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE token_hash = $1 AND revoked_at IS NULL`, authkit.HashToken(first.Tokens.RefreshToken)) != 1 {
		t.Fatal("a refused refresh rotated or revoked")
	}
	w.p.Allow(id)
	if res := w.refresh("staff", first.Tokens.RefreshToken); res.Refusal != nil {
		t.Fatalf("the same token after reactivation = %v", res.Refusal)
	}
}

func TestRefreshMintsTheCurrentClaims(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	w.p.SetRole(id, "admin")
	if c := w.claims(w.refresh("staff", first.Tokens.RefreshToken)); c.App["role"] != "admin" {
		t.Fatalf("refreshed role = %v, want admin: a changed role is minted, never stale", c.App["role"])
	}
}

func TestRefreshOfAnEndedSession(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	revoked := w.signIn("ada@example.invalid", "the right password")
	expired := w.signIn("ada@example.invalid", "the right password")
	w.d.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, revoked.Session.ID, w.clock.Now())
	w.d.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, expired.Session.ID, w.clock.Now())
	for name, raw := range map[string]string{"revoked": revoked.Tokens.RefreshToken, "expired": expired.Tokens.RefreshToken, "unknown": "not-a-token"} {
		if res := w.refresh("staff", raw); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Errorf("%s: refresh = %v, want ErrSessionEnded", name, res.Refusal)
		}
	}
}
