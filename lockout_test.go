package authkit_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// hashedKey is the default auth_throttle key: hex(sha256(normalised login)).
func hashedKey(login string) string {
	sum := sha256.Sum256([]byte(login))
	return hex.EncodeToString(sum[:])
}

// TestTheSixthAttemptIsRefusedUnverified is spec §3.2 at the defaults: five
// attempts are judged, the sixth is refused for Lockout without a
// verification, and its locked event names the principal (spec §3.6).
func TestTheSixthAttemptIsRefusedUnverified(t *testing.T) {
	w := newWorld(t, defaults)
	id := w.user("ada@example.invalid", "the right password")
	var calls atomic.Int64
	authkit.SetVerifyHook(w.svc, func() { calls.Add(1) })
	for i := range 5 {
		if res := w.login("staff", "ada@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", i+1, res.Refusal)
		}
	}
	w.clock.Advance(time.Minute)
	var locked authkit.ErrLocked
	if res := w.login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 15*time.Minute {
		t.Fatalf("the sixth attempt = %v, want ErrLocked{15m}", res.Refusal)
	}
	if n := calls.Load(); n != 5 {
		t.Fatalf("%d verifications, want 5: the sixth attempt must not verify", n)
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE result = 'locked' AND principal_id = $1`, id) != 1 {
		t.Fatal("the locked event does not name the principal")
	}
	w.clock.Advance(10 * time.Minute)
	if res := w.login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 5*time.Minute {
		t.Fatalf("an attempt 10 minutes into the lockout = %v, want ErrLocked{5m}: the lockout is kept, not extended", res.Refusal)
	}
	w.clock.Advance(5 * time.Minute)
	w.signIn("ada@example.invalid", "the right password")
	if w.count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a sign-in left the counter behind")
	}
}

// TestALapsedLockoutStartsAFreshWindow: with Lockout shorter than Window, the
// attempt after the lockout is judged, not refused for the old window's count.
func TestALapsedLockoutStartsAFreshWindow(t *testing.T) {
	w := newWorld(t, defaults, func(c *authkit.Config) { c.Throttle.Lockout = 5 * time.Minute })
	w.user("ada@example.invalid", "the right password")
	for range 6 {
		w.login("staff", "ada@example.invalid", "a wrong password")
	}
	w.clock.Advance(5 * time.Minute)
	if res := w.login("staff", "ada@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("the attempt after a 5-minute lockout = %v, want it judged (ErrInvalidCredentials)", res.Refusal)
	}
	if n := w.count(`SELECT failures FROM auth_throttle WHERE login = $1`, hashedKey("ada@example.invalid")); n != 1 {
		t.Fatalf("failures = %d, want a fresh window of 1", n)
	}
}

// TestABusyLoginCountsNothing is spec §3.2: the hash slot comes before the
// count, so a Busy refusal writes nothing.
func TestABusyLoginCountsNothing(t *testing.T) {
	w := newWorld(t, defaults, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
	w.user("ada@example.invalid", "the right password")
	release, err := authkit.HoldHashSlot(w.ctx, w.svc)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if res := w.login("staff", "ada@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrBusy) {
		t.Fatalf("Login with the ceiling full = %v, want ErrBusy", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_throttle`)+w.count(`SELECT count(*) FROM auth_events`) != 0 {
		t.Fatal("a Busy refusal counted or logged")
	}
}

// TestTheCountComesBeforeTheVerify: a login that waits on another attempt's
// throttle row has not verified yet. Under CountAfterVerify it verifies
// first and waits to count its failure, as v0.1 did.
func TestTheCountComesBeforeTheVerify(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak    func(*authkit.Config)
		key      string
		verified int64
	}{
		"count-before":     {defaults, hashedKey("ada@example.invalid"), 0},
		"CountAfterVerify": {func(*authkit.Config) {}, "ada@example.invalid", 1},
	} {
		w := newWorld(t, tc.tweak)
		w.user("ada@example.invalid", "the right password")
		w.d.Exec(t, `INSERT INTO auth_throttle (login, audience, failures, window_start) VALUES ($1, 'staff', 1, $2)`, tc.key, w.clock.Now())
		holder, err := w.d.Owner.BeginTx(w.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := holder.ExecContext(w.ctx, `SELECT 1 FROM auth_throttle WHERE login = $1 FOR UPDATE`, tc.key); err != nil {
			t.Fatal(err)
		}
		var calls atomic.Int64
		authkit.SetVerifyHook(w.svc, func() { calls.Add(1) })
		done := make(chan error, 1)
		var res authkit.Result
		go func() {
			done <- w.d.InAuthTx(w.ctx, func(q db.Querier) error {
				var err error
				res, err = w.svc.Login(w.ctx, q, "staff", "ada@example.invalid", "a wrong password", authkit.Meta{})
				return err
			})
		}()
		w.d.WaitForLockWaiters(t, 1)
		if n := calls.Load(); n != tc.verified {
			t.Errorf("%s: %d verifications while the login waits on its throttle row, want %d", name, n, tc.verified)
		}
		if err := holder.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil || !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
			t.Fatalf("%s: Login = %v, %v", name, res.Refusal, err)
		}
	}
}

// TestAnAdmitRefusalStaysCounted: the attempt was counted before its outcome
// was known, and only a sign-in clears the counter.
func TestAnAdmitRefusalStaysCounted(t *testing.T) {
	w := newWorld(t, defaults)
	id := w.user("ada@example.invalid", "the right password")
	w.p.Refuse(id, errors.New("app: deactivated"))
	w.login("staff", "ada@example.invalid", "the right password")
	if n := w.count(`SELECT failures FROM auth_throttle WHERE login = $1`, hashedKey("ada@example.invalid")); n != 1 {
		t.Fatalf("failures after an Admit refusal = %d, want 1", n)
	}
}

// TestTheThrottleKeysTheLoginsHashByDefault: auth_throttle holds no logins
// unless PlainLoginKey, v0.1's key, is set.
func TestTheThrottleKeysTheLoginsHashByDefault(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak func(*authkit.Config)
		key   string
	}{
		"the default":   {defaults, hashedKey("ada@example.invalid")},
		"PlainLoginKey": {func(c *authkit.Config) { defaults(c); c.Throttle.PlainLoginKey = true }, "ada@example.invalid"},
	} {
		w := newWorld(t, tc.tweak)
		w.user("ada@example.invalid", "the right password")
		w.login("staff", " Ada@Example.invalid", "a wrong password")
		if w.count(`SELECT count(*) FROM auth_throttle WHERE login = $1`, tc.key) != 1 || w.count(`SELECT count(*) FROM auth_throttle`) != 1 {
			t.Errorf("%s: the counter is not keyed %q", name, tc.key)
		}
	}
}

// TestCompleteResetClearsTheHashedKey: the reset clears the counter under the
// key Login wrote it under, the hash of the normalised login, though the
// stored login is not in that form.
func TestCompleteResetClearsTheHashedKey(t *testing.T) {
	w := newWorld(t, defaults)
	id := w.user("Ada@Example.invalid", "the old password")
	for range 3 {
		w.login("staff", "ada@example.invalid", "a wrong password")
	}
	var link uuid.UUID
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		link, err = w.svc.OneTime().Create(w.ctx, q, authkit.PurposeReset, id, time.Hour)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res := w.completeReset(w.mintLink(link), "the new password"); res.Refusal != nil {
		t.Fatalf("CompleteReset = %v", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_throttle WHERE login = $1`, hashedKey("ada@example.invalid")) != 0 {
		t.Fatal("the reset left the hashed counter")
	}
}
