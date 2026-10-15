package password_test

import (
	"context"
	crand "crypto/rand"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/password"
)

type world struct{ *kittest.World }

func newWorld(t *testing.T, tweaks ...func(*kittest.Rules)) *world {
	t.Helper()
	return &world{kittest.New(t, tweaks...)}
}

func TestTheSixthAttemptIsRefusedUnverified(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	id := w.User("ada@example.invalid", "the right password")
	var calls atomic.Int64
	password.SetVerifyHook(w.Svc.Password, func() { calls.Add(1) })
	for i := range 5 {
		if res := w.Login("staff", "ada@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", i+1, res.Refusal)
		}
	}
	w.Clock.Advance(time.Minute)
	var locked authkit.ErrLocked
	if res := w.Login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 15*time.Minute {
		t.Fatalf("the sixth attempt = %v, want ErrLocked{15m}", res.Refusal)
	}
	if n := calls.Load(); n != 5 {
		t.Fatalf("%d verifications, want 5: the sixth attempt must not verify", n)
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE result = 'locked' AND principal_id = $1`, id) != 1 {
		t.Fatal("the locked event does not name the principal")
	}
	w.Clock.Advance(10 * time.Minute)
	if res := w.Login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 5*time.Minute {
		t.Fatalf("an attempt 10 minutes into the lockout = %v, want ErrLocked{5m}: the lockout is kept, not extended", res.Refusal)
	}
	w.Clock.Advance(5 * time.Minute)
	w.SignIn("ada@example.invalid", "the right password")
	if w.Count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a sign-in left the counter behind")
	}
}

func TestABusyLoginCountsNothing(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules, func(c *kittest.Rules) { c.Password.HashConcurrency, c.Password.HashWait = 1, 50*time.Millisecond })
	w.User("ada@example.invalid", "the right password")
	release, err := password.HoldHashSlot(w.Ctx, w.Svc.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if res := w.Login("staff", "ada@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrBusy) {
		t.Fatalf("Login with the ceiling full = %v, want ErrBusy", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_throttle`)+w.Count(`SELECT count(*) FROM auth_events`) != 0 {
		t.Fatal("a Busy refusal counted or logged")
	}
}

func TestTheCountComesBeforeTheVerify(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak    func(*kittest.Rules)
		key      string
		verified int64
	}{
		"count-before":     {kittest.DefaultRules, kittest.HashedKey("ada@example.invalid"), 0},
		"CountAfterVerify": {func(*kittest.Rules) {}, "ada@example.invalid", 1},
	} {
		w := newWorld(t, tc.tweak)
		w.User("ada@example.invalid", "the right password")
		w.D.Exec(t, `INSERT INTO auth_throttle (login, audience, failures, window_start) VALUES ($1, 'staff', 1, $2)`, tc.key, w.Clock.Now())
		holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := holder.ExecContext(w.Ctx, `SELECT 1 FROM auth_throttle WHERE login = $1 FOR UPDATE`, tc.key); err != nil {
			t.Fatal(err)
		}
		var calls atomic.Int64
		password.SetVerifyHook(w.Svc.Password, func() { calls.Add(1) })
		done := make(chan error, 1)
		var res authkit.Result
		go func() {
			done <- w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
				var err error
				res, err = w.Svc.Password.Login(w.Ctx, q, "staff", "ada@example.invalid", "a wrong password", authkit.Meta{})
				return err
			})
		}()
		w.D.WaitForLockWaiters(t, 1)
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

func TestLoginVerifiesExactlyOncePerAttempt(t *testing.T) {
	w := newWorld(t)
	w.User("known@example.invalid", "the right password")
	w.User("invited@example.invalid", "")
	var calls atomic.Int64
	password.SetVerifyHook(w.Svc.Password, func() { calls.Add(1) })
	for name, tc := range map[string][2]string{
		"unknown login":  {"nobody@example.invalid", "whatever it is"},
		"no credential":  {"invited@example.invalid", "whatever it is"},
		"wrong password": {"known@example.invalid", "a wrong password"},
		"right password": {"known@example.invalid", "the right password"},
	} {
		calls.Store(0)
		w.Login("client", tc[0], tc[1])
		if n := calls.Load(); n != 1 {
			t.Errorf("%s: %d argon2id verifications, want exactly 1", name, n)
		}
	}
}

func TestTheLockoutEngagesAfterTenFailures(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	for range 10 {
		w.Login("staff", "ada@example.invalid", "a wrong password")
	}
	var calls atomic.Int64
	password.SetVerifyHook(w.Svc.Password, func() { calls.Add(1) })
	w.Clock.Advance(5 * time.Minute)
	var locked authkit.ErrLocked
	if res := w.Login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 10*time.Minute {
		t.Fatalf("the 11th attempt = %v, want ErrLocked{10m}", res.Refusal)
	}
	if calls.Load() != 0 {
		t.Fatal("a locked login ran the hash; the check must come first")
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE result = 'locked' AND login = 'ada@example.invalid'`) != 1 {
		t.Fatal("no locked event")
	}
	w.Clock.Advance(10 * time.Minute)
	if res := w.Login("staff", "ada@example.invalid", "the right password"); res.Refusal != nil {
		t.Fatalf("after the lockout = %v", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_throttle WHERE login = 'ada@example.invalid'`) != 0 {
		t.Fatal("a sign-in left the counter behind")
	}
}

func TestARehashKeepsAPasswordChangedDuringTheLogin(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	changed, err := password.Encode(w.Cfg.Password.Hashing, crand.Reader, "the new password")
	if err != nil {
		t.Fatal(err)
	}
	stronger := w.Cfg
	stronger.Password.Hashing.Time = 2
	w.Svc = w.Build(stronger)
	var once sync.Once
	password.SetVerifyHook(w.Svc.Password, func() {
		once.Do(func() {
			w.D.Exec(t, `UPDATE auth_credentials SET password_hash = $2 WHERE principal_id = $1`, id, changed)
		})
	})
	w.Login("staff", "ada@example.invalid", "the old password")
	if got := w.StoredHash(id); got != changed {
		t.Fatalf("the rehash overwrote a password changed during the login: stored %q, want %q", got, changed)
	}
}

// WHY: the hook runs after the verify releases its hash slot and before the rehash asks for one.
type admitHook struct {
	*authkittest.Principals
	before func()
}

func (p admitHook) Admit(ctx context.Context, q db.Querier, prop authkit.Proposal) (authkit.Admission, error) {
	p.before()
	return p.Principals.Admit(ctx, q, prop)
}

func TestLoginSkipsTheRehashWhenTheCeilingIsFull(t *testing.T) {
	w := newWorld(t, func(c *kittest.Rules) { c.Password.HashConcurrency, c.Password.HashWait = 1, 50*time.Millisecond })
	id := w.User("ada@example.invalid", "the right password")
	stronger := w.Cfg
	stronger.Password.Hashing.Time = 2
	var kit *kittest.Kit
	var release func()
	hold := true
	kit, err := kittest.NewKit(stronger, admitHook{w.P, func() {
		if !hold {
			return
		}
		r, err := password.HoldHashSlot(w.Ctx, kit.Password)
		if err != nil {
			t.Fatal(err)
		}
		release = r
	}})
	if err != nil {
		t.Fatal(err)
	}
	w.Svc = kit
	w.SignIn("ada@example.invalid", "the right password")
	if h := w.StoredHash(id); !strings.Contains(h, ",t=1,") {
		t.Fatalf("hash after a sign-in with the ceiling full = %q; want the rehash skipped", h)
	}
	release()
	hold = false
	w.SignIn("ada@example.invalid", "the right password")
	if h := w.StoredHash(id); !strings.Contains(h, ",t=2,") {
		t.Fatalf("hash after the next sign-in = %q; want it rehashed at t=2", h)
	}
}

func TestLoginAnswersBusyWhenTheCeilingIsFull(t *testing.T) {
	w := newWorld(t, func(c *kittest.Rules) { c.Password.HashConcurrency, c.Password.HashWait = 1, 50*time.Millisecond })
	w.User("ada@example.invalid", "the right password")
	release, err := password.HoldHashSlot(w.Ctx, w.Svc.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if res := w.Login("staff", "ada@example.invalid", "the right password"); !errors.Is(res.Refusal, authkit.ErrBusy) {
		t.Fatalf("Login with the ceiling full = %v, want ErrBusy", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_events`)+w.Count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a busy refusal wrote")
	}
}

func TestChangePasswordHashesBeforeItLocks(t *testing.T) {
	w := newWorld(t, func(c *kittest.Rules) { c.Password.HashConcurrency = 1 })
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.Ctx, `SELECT 1 FROM auth_credentials WHERE principal_id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	conn, c := w.Pinned(id), w.Claims(keep)
	var res authkit.Result
	done := make(chan error, 1)
	go func() {
		done <- authkittest.InConnTx(w.Ctx, conn, func(q db.Querier) error {
			var err error
			res, err = w.Svc.Password.ChangePassword(w.Ctx, q, c, "the old password", "the changed password", authkit.Meta{})
			return err
		})
	}()
	w.D.WaitForLockWaiters(t, 1)
	release, err := password.HoldHashSlot(w.Ctx, w.Svc.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if res.Refusal != nil {
		t.Fatalf("a change that waited on the credential row = %v; it hashed under the lock", res.Refusal)
	}
}
