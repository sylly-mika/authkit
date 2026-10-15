package tests

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/onetime"
)

func (w *world) requestReset(login string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.RequestReset(w.Ctx, q, "staff", login)
	})
}

func (w *world) mintLink(id uuid.UUID) string {
	w.T.Helper()
	var raw string
	if err := w.D.InGlobalSystemTx(w.Ctx, func(q db.Querier) error {
		m, err := w.Svc.OneTime().Mint(w.Ctx, q, id)
		raw = m.Raw
		return err
	}); err != nil {
		w.T.Fatalf("mint: %v", err)
	}
	return raw
}

func (w *world) completeReset(raw, pw string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.CompleteReset(w.Ctx, q, "staff", raw, pw, authkit.Meta{})
	})
}

func TestRequestResetCreatesAnUnsentLink(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	res := w.requestReset(" Ada@Example.invalid")
	if res.Refusal != nil || res.TokenID == nil {
		t.Fatalf("RequestReset = %+v", res)
	}
	if w.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND purpose = 'reset' AND owner_id = $2 AND token_hash IS NULL AND ttl = interval '1 hour'`, *res.TokenID, id) != 1 {
		t.Fatal("no unsent one-hour reset row for the principal")
	}
}

func TestRequestResetForAnUnknownLoginWritesNothing(t *testing.T) {
	w := newWorld(t)
	if res := w.requestReset("nobody@example.invalid"); res.TokenID != nil || w.Count(`SELECT count(*) FROM auth_tokens`) != 0 {
		t.Fatalf("an unknown login = %+v", res)
	}
}

func TestRequestResetServesAPrincipalWithoutAPassword(t *testing.T) {
	w := newWorld(t)
	w.User("invited@example.invalid", "")
	if res := w.requestReset("invited@example.invalid"); res.TokenID == nil {
		t.Fatal("a principal without a credential is eligible (spec §11.1 step 4)")
	}
}

func TestRequestResetCapsAtThreeAnHour(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the old password")
	for i := range 3 {
		if res := w.requestReset("ada@example.invalid"); res.TokenID == nil {
			t.Fatalf("request %d was capped", i+1)
		}
		w.Clock.Advance(time.Minute)
	}
	if res := w.requestReset("ada@example.invalid"); res.TokenID != nil || w.Count(`SELECT count(*) FROM auth_tokens`) != 3 {
		t.Fatal("a fourth request within the hour created a link")
	}
	w.Clock.Advance(58 * time.Minute)
	if res := w.requestReset("ada@example.invalid"); res.TokenID == nil {
		t.Fatal("the cap outlived its hour")
	}
}

// WHY: a request that waits on a lock held by another request counts the link that request created, so concurrent requests keep the cap.
func TestRequestResetCountsUnderTheLock(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the old password")
	for range 2 {
		w.requestReset("ada@example.invalid")
	}
	holder, err := w.D.App.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if res, err := w.Svc.Password.RequestReset(w.Ctx, sqldb.Tx(holder), "staff", "ada@example.invalid"); err != nil || res.TokenID == nil {
		t.Fatalf("the third request = %+v (%v)", res, err)
	}
	type outcome struct {
		res authkit.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var res authkit.Result
		err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			var err error
			res, err = w.Svc.Password.RequestReset(w.Ctx, q, "staff", "ada@example.invalid")
			return err
		})
		done <- outcome{res, err}
	}()
	w.D.WaitForLockWaiters(t, 1)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	o := <-done
	if o.err != nil {
		t.Fatal(o.err)
	}
	if o.res.TokenID != nil || w.Count(`SELECT count(*) FROM auth_tokens`) != 3 {
		t.Fatal("a fourth request that waited on the third's lock created a link")
	}
}

func TestCompleteResetSetsThePasswordAndEndsEverySession(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	w.SignIn("ada@example.invalid", "the old password")
	w.SignIn("ada@example.invalid", "the old password")
	raw := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	w.Clock.Advance(time.Second)
	res := w.completeReset(raw, "the new password")
	if res.Refusal != nil || res.Session != nil || res.Tokens != nil {
		t.Fatalf("CompleteReset = %+v; it must not sign in", res)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoke_reason = 'password_reset'`, id) != 2 {
		t.Fatal("a session survived the reset")
	}
	if got := w.Results(id); got[len(got)-1] != "password_reset" {
		t.Fatalf("log = %v, want password_reset last", got)
	}
	if res := w.Login("staff", "ada@example.invalid", "the old password"); res.Refusal == nil {
		t.Fatal("the old password still works")
	}
	w.SignIn("ada@example.invalid", "the new password")
}

func TestCompleteResetLiftsTheLockout(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the old password")
	for range 10 {
		w.Login("staff", "ada@example.invalid", "a wrong password")
	}
	if res := w.completeReset(w.mintLink(*w.requestReset("ada@example.invalid").TokenID), "the new password"); res.Refusal != nil {
		t.Fatalf("CompleteReset = %v", res.Refusal)
	}
	w.SignIn("ada@example.invalid", "the new password")
}

func TestCompleteResetLogsPasswordSetForAFirstPassword(t *testing.T) {
	w := newWorld(t)
	id := w.User("invited@example.invalid", "")
	if res := w.completeReset(w.mintLink(*w.requestReset("invited@example.invalid").TokenID), "a first password"); res.Refusal != nil {
		t.Fatalf("CompleteReset = %v", res.Refusal)
	}
	if got := w.Results(id); !slices.Equal(got, []string{"password_set"}) {
		t.Fatalf("log = %v, want password_set", got)
	}
	w.SignIn("invited@example.invalid", "a first password")
}

func TestCompleteResetRefusals(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	spent := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	w.completeReset(spent, "the new password")
	superseded := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	expired := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	var invite string
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		tid, err := w.Svc.OneTime().Create(w.Ctx, q, "invite", id, time.Hour)
		if err != nil {
			return err
		}
		m, err := w.Svc.OneTime().Mint(w.Ctx, q, tid)
		invite = m.Raw
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w.Clock.Advance(61 * time.Minute)
	for name, tc := range map[string]struct {
		raw   string
		state onetime.State
	}{
		"unknown":    {"not-a-token", ""},
		"superseded": {superseded, ""},
		"invite":     {invite, ""},
		"spent":      {spent, onetime.StateUsed},
		"expired":    {expired, onetime.StateExpired},
	} {
		res := w.completeReset(tc.raw, "yet another password")
		var gone authkit.ErrTokenGone
		switch {
		case tc.state == "" && !errors.Is(res.Refusal, authkit.ErrTokenUnknown):
			t.Errorf("%s: %v, want ErrTokenUnknown (404)", name, res.Refusal)
		case tc.state != "" && (!errors.As(res.Refusal, &gone) || gone.State != tc.state):
			t.Errorf("%s: %v, want ErrTokenGone{%s} (410)", name, res.Refusal, tc.state)
		}
	}
}

func TestCompleteResetChecksThePolicyFirst(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the old password")
	raw := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	var pe authkit.PolicyError
	if res := w.completeReset(raw, "short"); !errors.As(res.Refusal, &pe) {
		t.Fatalf("a short password = %v, want PolicyError", res.Refusal)
	}
	if res := w.completeReset(raw, "a long enough password"); res.Refusal != nil {
		t.Fatalf("the link was spent by the refused attempt: %v", res.Refusal)
	}
}

func TestPadSinceWaitsForTheFloor(t *testing.T) {
	start := time.Now()
	authkit.PadSince(start, 40*time.Millisecond)
	if waited := time.Since(start); waited < 40*time.Millisecond {
		t.Fatalf("PadSince returned after %v, want at least 40ms (spec §8.6)", waited)
	}
	start = time.Now()
	authkit.PadSince(start.Add(-time.Second), 40*time.Millisecond)
	if waited := time.Since(start); waited > 200*time.Millisecond {
		t.Fatalf("PadSince past its floor slept %v", waited)
	}
}

func TestCompleteResetForAGonePrincipalKeepsTheSpend(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	link := *w.requestReset("ada@example.invalid").TokenID
	raw := w.mintLink(link)
	w.D.Exec(t, `DELETE FROM users WHERE id = $1`, id)
	if res := w.completeReset(raw, "the new password"); !errors.Is(res.Refusal, authkit.ErrTokenUnknown) {
		t.Fatalf("a gone principal's link = %v, want ErrTokenUnknown", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NOT NULL`, link) != 1 {
		t.Fatal("the refusal dropped the spend")
	}
	if w.Count(`SELECT count(*) FROM auth_credentials`)+w.Count(`SELECT count(*) FROM auth_events`) != 0 {
		t.Fatal("a gone principal's reset wrote a credential or an event")
	}
}

func TestPadSincePadsToTheFloorNotBeyondIt(t *testing.T) {
	start := time.Now().Add(-600 * time.Millisecond)
	authkit.PadSince(start, 700*time.Millisecond)
	if total := time.Since(start); total < 700*time.Millisecond || total > time.Second {
		t.Fatalf("PadSince 600ms into a 700ms floor returned %v after start, want about 700ms", total)
	}
}

// WHY: Login keys the throttle by the normalised login, which the stored login may not match, so the reset clears under that key.
func TestCompleteResetClearsTheNormalisedLoginsThrottle(t *testing.T) {
	w := newWorld(t)
	id := w.User("Ada@Example.invalid", "the old password")
	for _, aud := range []string{"staff", "client"} {
		w.D.Exec(t, `INSERT INTO auth_throttle (login, audience, failures, window_start, locked_until) VALUES ('ada@example.invalid', $1, 10, $2, $3)`,
			aud, w.Clock.Now(), w.Clock.Now().Add(15*time.Minute))
	}
	var link uuid.UUID
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		link, err = w.Svc.OneTime().Create(w.Ctx, q, authkit.PurposeReset, id, time.Hour)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res := w.completeReset(w.mintLink(link), "the new password"); res.Refusal != nil {
		t.Fatalf("CompleteReset = %v", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_throttle WHERE audience = 'staff'`) != 0 || w.Count(`SELECT count(*) FROM auth_throttle WHERE audience = 'client'`) != 1 {
		t.Fatal("the reset kept the staff counter or cleared another audience's")
	}
}
