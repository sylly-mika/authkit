package tests

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
)

func TestALapsedLockoutStartsAFreshWindow(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules, func(c *authkit.Config) { c.Throttle.Lockout = 5 * time.Minute })
	w.User("ada@example.invalid", "the right password")
	for range 6 {
		w.Login("staff", "ada@example.invalid", "a wrong password")
	}
	w.Clock.Advance(5 * time.Minute)
	if res := w.Login("staff", "ada@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("the attempt after a 5-minute lockout = %v, want it judged (ErrInvalidCredentials)", res.Refusal)
	}
	if n := w.Count(`SELECT failures FROM auth_throttle WHERE login = $1`, kittest.HashedKey("ada@example.invalid")); n != 1 {
		t.Fatalf("failures = %d, want a fresh window of 1", n)
	}
}

func TestAnAdmitRefusalStaysCounted(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	id := w.User("ada@example.invalid", "the right password")
	w.P.Refuse(id, errors.New("app: deactivated"))
	w.Login("staff", "ada@example.invalid", "the right password")
	if n := w.Count(`SELECT failures FROM auth_throttle WHERE login = $1`, kittest.HashedKey("ada@example.invalid")); n != 1 {
		t.Fatalf("failures after an Admit refusal = %d, want 1", n)
	}
}

func TestTheThrottleKeysTheLoginsHashByDefault(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak func(*authkit.Config)
		key   string
	}{
		"the default":   {kittest.DefaultRules, kittest.HashedKey("ada@example.invalid")},
		"PlainLoginKey": {func(c *authkit.Config) { kittest.DefaultRules(c); c.Throttle.PlainLoginKey = true }, "ada@example.invalid"},
	} {
		w := newWorld(t, tc.tweak)
		w.User("ada@example.invalid", "the right password")
		w.Login("staff", " Ada@Example.invalid", "a wrong password")
		if w.Count(`SELECT count(*) FROM auth_throttle WHERE login = $1`, tc.key) != 1 || w.Count(`SELECT count(*) FROM auth_throttle`) != 1 {
			t.Errorf("%s: the counter is not keyed %q", name, tc.key)
		}
	}
}

func TestCompleteResetClearsTheHashedKey(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	id := w.User("Ada@Example.invalid", "the old password")
	for range 3 {
		w.Login("staff", "ada@example.invalid", "a wrong password")
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
	if w.Count(`SELECT count(*) FROM auth_throttle WHERE login = $1`, kittest.HashedKey("ada@example.invalid")) != 0 {
		t.Fatal("the reset left the hashed counter")
	}
}
