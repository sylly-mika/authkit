package tests

import (
	"errors"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
)

func withRecent(d time.Duration) func(*kittest.Rules) {
	return func(c *kittest.Rules) { c.Recent = d }
}

func (w *world) requireRecent(c *authkit.Claims, window time.Duration) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) { return w.Svc.RequireRecent(w.Ctx, q, c, window) })
}

func TestRecentDefault(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		w := newWorld(t, withPasskeys)
		w.User("ada@example.invalid", "the right password")
		c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
		w.Clock.Advance(5 * time.Minute)
		if res := w.requireRecent(c, 0); res.Refusal != nil {
			t.Fatalf("RequireRecent at 5m = %v; want nil", res.Refusal)
		}
		begin := func() authkit.Result {
			return w.InAuth(func(q db.Querier) (authkit.Result, error) {
				return w.Svc.Passkeys.BeginPasskeyRegistration(w.Ctx, q, c, authkit.Meta{})
			})
		}
		if res := begin(); res.Refusal != nil {
			t.Fatalf("BeginPasskeyRegistration at 5m = %v; want nil", res.Refusal)
		}
		w.Clock.Advance(time.Second)
		if res := w.requireRecent(c, 0); !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
			t.Fatalf("RequireRecent at 5m1s = %v; want ErrReauthRequired", res.Refusal)
		}
		if res := begin(); !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
			t.Fatalf("BeginPasskeyRegistration at 5m1s = %v; want ErrReauthRequired", res.Refusal)
		}
	})

	t.Run("passkey", func(t *testing.T) {
		w := newWorld(t, withRecent(2*time.Minute), withPasskeys)
		w.User("ada@example.invalid", "the right password")
		c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
		w.Clock.Advance(2*time.Minute + time.Second)
		res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
			return w.Svc.Passkeys.BeginPasskeyRegistration(w.Ctx, q, c, authkit.Meta{})
		})
		if !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
			t.Fatalf("BeginPasskeyRegistration at 2m1s with Recent 2m = %v; want ErrReauthRequired", res.Refusal)
		}
		if n := w.Count("SELECT count(*) FROM auth_passkey_ceremonies"); n != 0 {
			t.Fatalf("passkey ceremonies = %d, want 0", n)
		}
	})

	t.Run("secondfactor", func(t *testing.T) {
		w := newWorld(t, withRecent(2*time.Minute), withSecondFactors)
		ada := w.User("ada@example.invalid", "the right password")
		c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
		w.Clock.Advance(2*time.Minute + time.Second)
		res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
			return w.Svc.Factors.BeginTOTPSetup(w.Ctx, q, c, authkit.Meta{})
		})
		if !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
			t.Fatalf("BeginTOTPSetup at 2m1s with Recent 2m = %v; want ErrReauthRequired", res.Refusal)
		}
		if n := w.Count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1", ada); n != 0 {
			t.Fatalf("second factors = %d, want 0", n)
		}
	})

	t.Run("oidc", func(t *testing.T) {
		w := newWorld(t, withRecent(2*time.Minute))
		w.withOIDC(false)
		w.User("ada@example.invalid", "the right password")
		c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
		w.Clock.Advance(2*time.Minute + time.Second)
		err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			_, err := w.Svc.OIDC.Link(w.Ctx, q, c, "google", authkit.Meta{})
			return err
		})
		if !errors.Is(err, authkit.ErrReauthRequired) {
			t.Fatalf("OIDC.Link at 2m1s with Recent 2m = %v; want ErrReauthRequired", err)
		}
		if n := w.Count("SELECT count(*) FROM auth_ceremonies"); n != 0 {
			t.Fatalf("OIDC ceremonies = %d, want 0", n)
		}
	})
}

func TestRecentWideWindow(t *testing.T) {
	w := newWorld(t)
	r := w.Cfg
	r.Recent = 20 * time.Minute
	if kit, err := kittest.NewKit(r, w.P); kit != nil || err == nil {
		t.Fatalf("NewKit with Recent 20m = %v, %v; want an error and no Service", kit, err)
	}

	w = newWorld(t, withRecent(10*time.Minute), withPasskeys)
	w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	w.Clock.Advance(9 * time.Minute)
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Passkeys.BeginPasskeyRegistration(w.Ctx, q, c, authkit.Meta{})
	})
	if res.Refusal != nil {
		t.Fatalf("BeginPasskeyRegistration at 9m with Recent 10m = %v; want nil", res.Refusal)
	}
}

func TestRecentSetReauthWins(t *testing.T) {
	w := newWorld(t, withRecent(2*time.Minute), func(c *kittest.Rules) {
		withPasskeys(c)
		c.Passkeys.Reauth = 4 * time.Minute
	})
	w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	begin := func() authkit.Result {
		return w.InAuth(func(q db.Querier) (authkit.Result, error) {
			return w.Svc.Passkeys.BeginPasskeyRegistration(w.Ctx, q, c, authkit.Meta{})
		})
	}
	w.Clock.Advance(3 * time.Minute)
	if res := begin(); res.Refusal != nil {
		t.Fatalf("BeginPasskeyRegistration at 3m with Reauth 4m = %v; want nil", res.Refusal)
	}
	w.Clock.Advance(time.Minute + time.Second)
	if res := begin(); !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("BeginPasskeyRegistration at 4m1s with Reauth 4m = %v; want ErrReauthRequired", res.Refusal)
	}
}

func TestRecentNegativeRefused(t *testing.T) {
	w := newWorld(t)
	r := w.Cfg
	r.Recent = -time.Second
	kit, err := kittest.NewKit(r, w.P)
	if kit != nil || err == nil || err.Error() != "authkit: Config.Recent must be positive, not -1s" {
		t.Fatalf("NewKit with Recent -1s = %v, %v; want the positive-duration error and no Service", kit, err)
	}
}

func TestRequireRecentFresh(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	t0 := w.Clock.Now()
	events := w.Count("SELECT count(*) FROM auth_events")
	w.Clock.Advance(5 * time.Minute)
	res := w.requireRecent(c, 0)
	if res.Refusal != nil || res.Principal.ID != ada {
		t.Fatalf("RequireRecent at 5m = %v, principal %s; want nil and %s", res.Refusal, res.Principal.ID, ada)
	}
	if n := w.Count("SELECT count(*) FROM auth_events"); n != events {
		t.Fatalf("events = %d, want %d unchanged", n, events)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND authenticated_at = $2", c.SessionID, t0); n != 1 {
		t.Fatalf("session rows with authenticated_at %v = %d, want 1 unchanged", t0, n)
	}
}

func TestRequireRecentStale(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	events := w.Count("SELECT count(*) FROM auth_events")
	w.Clock.Advance(5*time.Minute + time.Second)
	if res := w.requireRecent(c, 0); !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("RequireRecent at 5m1s = %v; want ErrReauthRequired", res.Refusal)
	}
	if n := w.Count("SELECT count(*) FROM auth_events"); n != events {
		t.Fatalf("events = %d, want %d unchanged", n, events)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL", c.SessionID); n != 1 {
		t.Fatalf("open session rows = %d, want 1: a refusal must not end the session", n)
	}
}

func TestRequireRecentWindowArg(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	w.Clock.Advance(time.Minute + time.Second)
	if res := w.requireRecent(c, time.Minute); !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("RequireRecent(1m) at 1m1s = %v; want ErrReauthRequired", res.Refusal)
	}
	if res := w.requireRecent(c, 0); res.Refusal != nil {
		t.Fatalf("RequireRecent(0) at 1m1s = %v; want nil", res.Refusal)
	}
	w.Clock.Advance(5 * time.Minute)
	if res := w.requireRecent(c, 10*time.Minute); res.Refusal != nil {
		t.Fatalf("RequireRecent(10m) at 6m1s = %v; want nil", res.Refusal)
	}
	if res := w.requireRecent(c, 0); !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("RequireRecent(0) at 6m1s = %v; want ErrReauthRequired", res.Refusal)
	}
}

func TestRequireRecentFromAuthenticatedAt(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	c1 := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	w.Clock.Advance(6 * time.Minute)
	w.D.Exec(t, "UPDATE auth_sessions SET authenticated_at = $2 WHERE id = $1", c1.SessionID, w.Clock.Now().Add(-time.Minute))
	c2 := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	w.D.Exec(t, "UPDATE auth_sessions SET authenticated_at = $2 WHERE id = $1", c2.SessionID, w.Clock.Now().Add(-6*time.Minute))
	if res := w.requireRecent(c1, 0); res.Refusal != nil {
		t.Fatalf("RequireRecent on a session created 6m ago, authenticated 1m ago = %v; want nil", res.Refusal)
	}
	if res := w.requireRecent(c2, 0); !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("RequireRecent on a session created now, authenticated 6m ago = %v; want ErrReauthRequired", res.Refusal)
	}
}

func TestRequireRecentEnded(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the right password")
	c1 := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	c2 := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	w.InAuth(func(q db.Querier) (authkit.Result, error) { return w.Svc.Logout(w.Ctx, q, c1, authkit.Meta{}) })
	events := w.Count("SELECT count(*) FROM auth_events")
	if res := w.requireRecent(c1, 0); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("RequireRecent on a logged-out session = %v; want ErrSessionEnded", res.Refusal)
	}
	w.Clock.Advance(7*24*time.Hour + time.Second)
	if res := w.requireRecent(c2, 0); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("RequireRecent on an idle-expired session = %v; want ErrSessionEnded", res.Refusal)
	}
	if n := w.Count("SELECT count(*) FROM auth_events"); n != events {
		t.Fatalf("events = %d, want %d unchanged", n, events)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", ada); n != 2 {
		t.Fatalf("sessions for ada = %d, want 2: an ended session must not make a new one", n)
	}
}

func TestRequireRecentLocksTheSession(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	tx1, err := w.D.App.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback()
	if res, err := w.Svc.RequireRecent(w.Ctx, sqldb.Tx(tx1), c, 0); err != nil || res.Refusal != nil {
		t.Fatalf("RequireRecent in tx1 = %v, %v; want nil", res.Refusal, err)
	}

	type outcome struct {
		res authkit.Result
		err error
	}
	out := make(chan outcome, 1)
	go func() {
		var res authkit.Result
		err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			var err error
			res, err = w.Svc.Logout(w.Ctx, q, c, authkit.Meta{})
			return err
		})
		out <- outcome{res, err}
	}()
	w.D.WaitForLockWaiters(t, 1)
	if err := tx1.Commit(); err != nil {
		t.Fatal(err)
	}
	got := <-out
	if got.err != nil || got.res.Refusal != nil {
		t.Fatalf("Logout after the guarded change = %v, %v; want nil", got.res.Refusal, got.err)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NOT NULL", c.SessionID); n != 1 {
		t.Fatalf("revoked session rows = %d, want 1", n)
	}
}
