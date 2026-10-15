package tests

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
)

type sourceLog struct {
	*authkittest.Principals
	mu   sync.Mutex
	seen []string
}

func (s *sourceLog) Admit(ctx context.Context, q db.Querier, prop authkit.Proposal) (authkit.Admission, error) {
	s.mu.Lock()
	s.seen = append(s.seen, prop.Source)
	s.mu.Unlock()
	return s.Principals.Admit(ctx, q, prop)
}

func (s *sourceLog) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	got := s.seen
	s.seen = nil
	return got
}

func withSourceLog(w *world) *sourceLog {
	w.T.Helper()
	rec := &sourceLog{Principals: w.P}
	w.Svc = w.BuildWith(w.Cfg, rec)
	return rec
}

func lastSource(t *testing.T, rec *sourceLog) string {
	t.Helper()
	got := rec.take()
	if len(got) == 0 {
		t.Fatal("Admit was not called")
	}
	return got[len(got)-1]
}

func TestAdmitSeesTheSource(t *testing.T) {
	const login = "ada@example.invalid"
	t.Run("login", func(t *testing.T) {
		w := newWorld(t)
		rec := withSourceLog(w)
		w.User(login, pw)
		if res := w.SignIn(login, pw); res.Refusal != nil {
			t.Fatalf("sign in refused: %v", res.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourceLogin {
			t.Fatalf("source = %q, want %q", got, authkit.SourceLogin)
		}
	})
	t.Run("refresh", func(t *testing.T) {
		w := newWorld(t)
		rec := withSourceLog(w)
		w.User(login, pw)
		res := w.SignIn(login, pw)
		if r := w.refresh("staff", res.Tokens.RefreshToken); r.Refusal != nil {
			t.Fatalf("refresh refused: %v", r.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourceRefresh {
			t.Fatalf("source = %q, want %q", got, authkit.SourceRefresh)
		}
	})
	t.Run("authenticate", func(t *testing.T) {
		w := newWorld(t)
		rec := withSourceLog(w)
		w.User(login, pw)
		res := w.SignIn(login, pw)
		if r := w.InAuth(func(q db.Querier) (authkit.Result, error) {
			return w.Svc.Authenticate(w.Ctx, q, w.Claims(res))
		}); r.Refusal != nil {
			t.Fatalf("authenticate refused: %v", r.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourceAuthenticate {
			t.Fatalf("source = %q, want %q", got, authkit.SourceAuthenticate)
		}
	})
	t.Run("open_session", func(t *testing.T) {
		w := newWorld(t)
		rec := withSourceLog(w)
		id := w.User(login, pw)
		if r := w.openSession(authkit.Principal{ID: id, Login: login}); r.Refusal != nil {
			t.Fatalf("open session refused: %v", r.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourceOpenSession {
			t.Fatalf("source = %q, want %q", got, authkit.SourceOpenSession)
		}
	})
	t.Run("authenticate_session", func(t *testing.T) {
		w := sessionWorld(t)
		rec := withSourceLog(w)
		w.User(login, pw)
		res := w.SignIn(login, pw)
		if r := w.authenticateSession("staff", res.SessionToken); r.Refusal != nil {
			t.Fatalf("authenticate session refused: %v", r.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourceAuthenticateSession {
			t.Fatalf("source = %q, want %q", got, authkit.SourceAuthenticateSession)
		}
	})
	t.Run("complete_reset", func(t *testing.T) {
		w := sessionWorld(t)
		rec := withSourceLog(w)
		w.User(login, pw)
		if r := w.completeReset(w.mintLink(*w.requestReset(login).TokenID), "the changed password 2040"); r.Refusal != nil {
			t.Fatalf("complete reset refused: %v", r.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourceCompleteReset {
			t.Fatalf("source = %q, want %q", got, authkit.SourceCompleteReset)
		}
	})
	t.Run("change_password", func(t *testing.T) {
		w := newWorld(t, func(c *kittest.Rules) { c.RevokeOnPasswordChange = authkit.RevokeAll })
		rec := withSourceLog(w)
		id := w.User(login, pw)
		res := w.SignIn(login, pw)
		if r := w.changePassword(w.Pinned(id), w.Claims(res), pw, "the changed password 2040"); r.Refusal != nil {
			t.Fatalf("change password refused: %v", r.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourceChangePassword {
			t.Fatalf("source = %q, want %q", got, authkit.SourceChangePassword)
		}
	})
	t.Run("passkey_login", func(t *testing.T) {
		w := newWorld(t, kittest.Passkeys)
		rec := withSourceLog(w)
		id := w.User(login, "")
		a := authkittest.NewAuthenticator("localhost", kittest.StaffOrigin)
		w.SeedPasskey(id, a)
		if r := w.passkeySignIn("staff", a); r.Refusal != nil {
			t.Fatalf("passkey sign in refused: %v", r.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourcePasskeyLogin {
			t.Fatalf("source = %q, want %q", got, authkit.SourcePasskeyLogin)
		}
	})
	t.Run("second_step", func(t *testing.T) {
		w := newWorld(t, factors)
		rec := withSourceLog(w)
		_, secret, _ := w.enrolTOTP(login)
		tok := w.challenge(login)
		if r := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)); r.Refusal != nil {
			t.Fatalf("second step refused: %v", r.Refusal)
		}
		if got := lastSource(t, rec); got != authkit.SourceSecondStep {
			t.Fatalf("source = %q, want %q", got, authkit.SourceSecondStep)
		}
	})
}

func TestAttachTwice(t *testing.T) {
	w := newWorld(t)
	svc, err := authkit.New(w.Cfg.Config, w.P)
	if err != nil {
		t.Fatal(err)
	}
	core, err := svc.Attach("password")
	if core == nil || err != nil {
		t.Fatalf("first Attach = %v, %v; want a Core and no error", core, err)
	}
	again, err := svc.Attach("password")
	if again != nil || !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second Attach = %v, %v; want nil and ErrAttached", again, err)
	}
	if other, err := svc.Attach("passkey"); other == nil || err != nil {
		t.Fatalf("Attach passkey = %v, %v; want a Core and no error", other, err)
	}
}

func TestAttachNames(t *testing.T) {
	w := newWorld(t)
	first, err := authkit.New(w.Cfg.Config, w.P)
	if err != nil {
		t.Fatal(err)
	}
	second, err := authkit.New(w.Cfg.Config, w.P)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"password", "passkey", "secondfactor"} {
		if c, err := first.Attach(name); c == nil || err != nil {
			t.Fatalf("Attach %q = %v, %v; want a Core and no error", name, c, err)
		}
	}
	if c, err := first.Attach(""); c != nil || err == nil || errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("Attach \"\" = %v, %v; want nil and an error other than ErrAttached", c, err)
	}
	if c, err := second.Attach("password"); c == nil || err != nil {
		t.Fatalf("second Service Attach password = %v, %v; want a Core: the registry is per Service", c, err)
	}
}

func TestCoreAttemptCountsAndLocks(t *testing.T) {
	const login = "ada@example.invalid"
	cases := []struct {
		name     string
		tweaks   []func(*kittest.Rules)
		n        int
		lockedBy bool
	}{
		{name: "pinned", n: 10},
		{name: "defaults", tweaks: []func(*kittest.Rules){kittest.DefaultRules}, n: 5, lockedBy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t, tc.tweaks...)
			id := w.User(login, pw)
			svc, err := authkit.New(w.Cfg.Config, w.P)
			if err != nil {
				t.Fatal(err)
			}
			core, err := svc.Attach("password")
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tc.n; i++ {
				var a *authkit.Attempt
				res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
					att, begun, err := core.Begin(w.Ctx, q, authkit.SourceLogin, "staff", "  Ada@Example.invalid", authkit.Meta{})
					if err != nil || att == nil {
						return begun, err
					}
					a = att
					a.SetPrincipal(&authkit.Principal{ID: id, Login: login})
					return a.Refuse(w.Ctx, q, authkit.ResultBadPassword, authkit.ErrInvalidCredentials)
				})
				if a == nil {
					t.Fatalf("round %d: Begin refused %v before the limit", i+1, res.Refusal)
				}
				if a.Login() != login || !a.Counted() {
					t.Fatalf("round %d: Login = %q, Counted = %v", i+1, a.Login(), a.Counted())
				}
				if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
					t.Fatalf("round %d: refusal = %v, want ErrInvalidCredentials", i+1, res.Refusal)
				}
			}
			var last *authkit.Attempt
			res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
				att, begun, err := core.Begin(w.Ctx, q, authkit.SourceLogin, "staff", login, authkit.Meta{})
				last = att
				return begun, err
			})
			if last != nil {
				t.Fatal("Begin after the limit returned an Attempt; want a locked refusal")
			}
			var locked authkit.ErrLocked
			if !errors.As(res.Refusal, &locked) {
				t.Fatalf("Begin after the limit refusal = %v, want ErrLocked", res.Refusal)
			}
			if got := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'login' AND result = 'bad_password' AND principal_id = $1`, id); got != tc.n {
				t.Fatalf("bad_password rows = %d, want %d", got, tc.n)
			}
			if got := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'login' AND result = 'locked'`); got != 1 {
				t.Fatalf("locked rows = %d, want 1", got)
			}
			lockedRow := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'login' AND result = 'locked' AND principal_id IS NULL`)
			if tc.lockedBy {
				lockedRow = w.Count(`SELECT count(*) FROM auth_events WHERE source = 'login' AND result = 'locked' AND principal_id = $1`, id)
			}
			if lockedRow != 1 {
				t.Fatalf("the locked row does not name the principal as this mode expects (count %d)", lockedRow)
			}
		})
	}
}
