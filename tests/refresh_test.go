package tests

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
)

func (w *world) refresh(aud authkit.Audience, raw string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) { return w.Svc.Refresh(w.Ctx, q, aud, raw, authkit.Meta{}) })
}

func TestRefreshRotatesAndSlidesTheExpiry(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(24 * time.Hour)
	next := w.refresh("staff", first.Tokens.RefreshToken)
	if next.Refusal != nil || next.Tokens.RefreshToken == first.Tokens.RefreshToken {
		t.Fatalf("refresh = %+v", next)
	}
	now := w.Clock.Now()
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND token_hash = $2 AND prev_token_hash = $3 AND rotated_at = $4 AND expires_at = $5`,
		first.Session.ID, authkit.HashToken(next.Tokens.RefreshToken), authkit.HashToken(first.Tokens.RefreshToken), now, now.Add(7*24*time.Hour)) != 1 {
		t.Fatal("the rotation did not keep the old hash, stamp rotated_at and slide expires_at (spec §8.1)")
	}
	if c := w.Claims(next); c.Subject != id || c.SessionID != first.Session.ID {
		t.Fatalf("refreshed claims = %+v", c)
	}
}

func TestRefreshSlidesByTheAudiencesTTL(t *testing.T) {
	w := newWorld(t, func(c *kittest.Rules) {
		c.RefreshTTLFor = map[authkit.Audience]time.Duration{"staff": time.Hour}
	})
	w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(time.Minute)
	next := w.refresh("staff", first.Tokens.RefreshToken)
	want := w.Clock.Now().Add(time.Hour)
	if next.Refusal != nil || !next.Session.ExpiresAt.Equal(want) ||
		w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND expires_at = $2`, first.Session.ID, want) != 1 {
		t.Fatalf("refresh = %+v; want the session to slide to now + RefreshTTLFor[staff] = %v", next, want)
	}
}

// WHY: a holder locks the session row first, so all 16 refreshes are in flight before any can win.
func TestRefreshConcurrentOneWinner(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.Ctx, w.D.SQL(`SELECT 1 FROM auth_sessions WHERE id = $1 FOR UPDATE`), first.Session.ID); err != nil {
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
			err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
				var err error
				res, err = w.Svc.Refresh(w.Ctx, q, "staff", first.Tokens.RefreshToken, authkit.Meta{})
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
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, first.Session.ID) != 1 {
		t.Fatal("losers inside the grace revoked the session")
	}
	if got := w.Results(id); !slices.Equal(got, []string{"signed_in"}) {
		t.Fatalf("log = %v, want the %d losers to log nothing", got, n-1)
	}
	if res := w.refresh("staff", winners[0].Tokens.RefreshToken); res.Refusal != nil {
		t.Fatalf("the winner's token = %v", res.Refusal)
	}
}

func TestALoserInsideTheGraceKeepsTheSession(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	next := w.refresh("staff", first.Tokens.RefreshToken)
	w.Clock.Advance(10 * time.Second)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the rotated-away token = %v, want ErrSessionEnded", res.Refusal)
	}
	if res := w.refresh("staff", next.Tokens.RefreshToken); res.Refusal != nil {
		t.Fatalf("the current token after a loser = %v", res.Refusal)
	}
}

func TestTheGraceIsInclusive(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	w.refresh("staff", first.Tokens.RefreshToken)
	w.Clock.Advance(30 * time.Second)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a token rotated away exactly ReuseGrace ago = %v, want ErrSessionEnded", res.Refusal)
	}
	if got := w.Results(id); !slices.Equal(got, []string{"signed_in"}) || w.Count(`SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL`) != 1 {
		t.Fatalf("a loser at exactly ReuseGrace wrote: log %v; want nothing written and the session alive", got)
	}
	w.Clock.Advance(time.Microsecond)
	w.refresh("staff", first.Tokens.RefreshToken)
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'reuse_detected'`, first.Session.ID) != 1 {
		t.Fatal("a microsecond past ReuseGrace is not a replay")
	}
}

func TestRefreshReuseAfterGraceRevokes(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	next := w.refresh("staff", first.Tokens.RefreshToken)
	w.Clock.Advance(31 * time.Second)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a replayed token = %v, want ErrSessionEnded", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'reuse_detected'`, first.Session.ID) != 1 {
		t.Fatal("the replay did not revoke the session")
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'reuse_detected' AND session_id = $2`, id, first.Session.ID) != 1 {
		t.Fatal("the replay was not logged")
	}
	if res := w.refresh("staff", next.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("the thief's or the owner's current token still works: %v", res.Refusal)
	}
}

func TestConcurrentReplaysRevokeAndLogOnce(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	w.refresh("staff", first.Tokens.RefreshToken)
	w.Clock.Advance(31 * time.Second)
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.Ctx, w.D.SQL(`SELECT 1 FROM auth_sessions WHERE id = $1 FOR UPDATE`), first.Session.ID); err != nil {
		t.Fatal(err)
	}
	const n = 16
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			errs <- w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
				res, err := w.Svc.Refresh(w.Ctx, q, "staff", first.Tokens.RefreshToken, authkit.Meta{})
				if err == nil && !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
					return fmt.Errorf("a replay = %v, want ErrSessionEnded", res.Refusal)
				}
				return err
			})
		})
	}
	w.D.WaitForLockWaiters(t, n)
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
	if got := w.Results(id); !slices.Equal(got, []string{"signed_in", "reuse_detected"}) {
		t.Fatalf("log = %v, want one reuse_detected for %d concurrent replays", got, n)
	}
}

func TestAReplayOfARevokedSessionWritesNothing(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	w.refresh("staff", first.Tokens.RefreshToken)
	w.Clock.Advance(31 * time.Second)
	w.refresh("staff", first.Tokens.RefreshToken)
	w.Clock.Advance(time.Minute)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a second replay = %v, want ErrSessionEnded", res.Refusal)
	}
	if got := w.Results(id); !slices.Equal(got, []string{"signed_in", "reuse_detected"}) {
		t.Fatalf("log = %v, want one reuse_detected: the second replay finds no open session", got)
	}
}

func TestATokenTwoRotationsOldIsAPlainRefusal(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	second := w.refresh("staff", first.Tokens.RefreshToken)
	w.Clock.Advance(time.Minute)
	w.refresh("staff", second.Tokens.RefreshToken)
	w.Clock.Advance(time.Minute)
	if res := w.refresh("staff", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a token two rotations old = %v", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL`) != 0 {
		t.Fatal("only the immediately previous token is detected; an older one must not revoke (spec §8.3)")
	}
}

func TestRefreshIsBoundToTheAudience(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	if res := w.refresh("client", first.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a staff token refreshed as client = %v", res.Refusal)
	}
	if res := w.refresh("staff", first.Tokens.RefreshToken); res.Refusal != nil {
		t.Fatalf("the wrong-audience attempt spent the token: %v", res.Refusal)
	}
}

func TestARefreshAdmitRefusesWritesNothing(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	errNoMembership := errors.New("app: no membership")
	w.P.Refuse(id, errNoMembership)
	if res := w.refresh("staff", first.Tokens.RefreshToken); res.Refusal != errNoMembership {
		t.Fatalf("refresh = %v, want the app's refusal unchanged (ino-tasks 403)", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE token_hash = $1 AND revoked_at IS NULL`, authkit.HashToken(first.Tokens.RefreshToken)) != 1 {
		t.Fatal("a refused refresh rotated or revoked")
	}
	w.P.Allow(id)
	if res := w.refresh("staff", first.Tokens.RefreshToken); res.Refusal != nil {
		t.Fatalf("the same token after reactivation = %v", res.Refusal)
	}
}

func TestRefreshMintsTheCurrentClaims(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	w.P.SetRole(id, "admin")
	if c := w.Claims(w.refresh("staff", first.Tokens.RefreshToken)); c.App["role"] != "admin" {
		t.Fatalf("refreshed role = %v, want admin: a changed role is minted, never stale", c.App["role"])
	}
}

func TestRefreshOfAnEndedSession(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	revoked := w.SignIn("ada@example.invalid", "the right password")
	expired := w.SignIn("ada@example.invalid", "the right password")
	w.D.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, revoked.Session.ID, w.Clock.Now())
	w.D.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, expired.Session.ID, w.Clock.Now())
	for name, raw := range map[string]string{"revoked": revoked.Tokens.RefreshToken, "expired": expired.Tokens.RefreshToken, "unknown": "not-a-token"} {
		if res := w.refresh("staff", raw); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Errorf("%s: refresh = %v, want ErrSessionEnded", name, res.Refusal)
		}
	}
}

func TestACopiedHexHashedSessionRefreshesWithItsOldToken(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	secret := make([]byte, 32)
	if _, err := crand.Read(secret); err != nil {
		t.Fatal(err)
	}
	raw := hex.EncodeToString(secret)
	sum := sha256.Sum256([]byte(raw))
	sid := uuid.New()
	now := w.Clock.Now()
	w.D.Exec(t, `INSERT INTO auth_sessions (id, principal_id, audience, scope_id, token_hash, authenticated_at, ip, user_agent, created_at, last_seen_at, expires_at, absolute_expires_at) VALUES ($1, $2, 'staff', $3, decode($4, 'hex'), $5, '', '', $5, $5, $6, $7)`,
		sid, id, w.P.Scope, hex.EncodeToString(sum[:]), now, now.Add(time.Hour), now.Add(12*time.Hour))
	next := w.refresh("staff", raw)
	if next.Refusal != nil || next.Tokens.RefreshToken == raw {
		t.Fatalf("refresh of a copied session = %+v, want a rotated token", next)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND token_hash = $2 AND prev_token_hash = $3`,
		sid, authkit.HashToken(next.Tokens.RefreshToken), sum[:]) != 1 {
		t.Fatal("the rotation did not keep the copied hash as prev_token_hash")
	}
	if c := w.Claims(next); c.Subject != id {
		t.Fatalf("refreshed claims subject = %v, want %v", c.Subject, id)
	}
}
