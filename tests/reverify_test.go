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

const rvLogin = "ada@example.invalid"

var rvMeta = authkit.Meta{IP: "192.0.2.9", UserAgent: "authkit-test"}

func (w *world) rvPassword(c *authkit.Claims, pass string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.Reverify(w.Ctx, q, c, pass, rvMeta)
	})
}

func (w *world) rvStamped(c *authkit.Claims) bool {
	return w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND authenticated_at = $2`, c.SessionID, w.Clock.Now()) == 1
}

func (w *world) rvEvents(id uuid.UUID, result string) int {
	return w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = $2 AND source = 'reverify'`, id, result)
}

func (w *world) rvTOTP(c *authkit.Claims, code string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Factors.Reverify(w.Ctx, q, c, code, rvMeta)
	})
}

func TestPasswordReverify(t *testing.T) {
	w := newWorld(t)
	id := w.User(rvLogin, pw)
	c := w.Claims(w.SignIn(rvLogin, pw))
	w.Clock.Advance(10 * time.Minute)

	wrong := w.rvPassword(c, "a wrong password")
	if !errors.Is(wrong.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("a wrong password = %v, want ErrInvalidCredentials", wrong.Refusal)
	}
	if w.rvStamped(c) {
		t.Fatal("a wrong password stamped the session")
	}
	if n := w.rvEvents(id, authkit.ResultBadPassword); n != 1 {
		t.Fatalf("bad_password events = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE login = $1 AND failures = 1`, rvLogin); n != 1 {
		t.Fatalf("throttle rows with one failure = %d, want 1", n)
	}

	right := w.rvPassword(c, pw)
	if right.Refusal != nil {
		t.Fatalf("the right password refused: %v", right.Refusal)
	}
	if right.Principal.ID != id || right.Session != nil || right.Tokens != nil {
		t.Fatal("the right password gave more than the principal")
	}
	if !w.rvStamped(c) {
		t.Fatal("the right password did not stamp the session")
	}
	if n := w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id); n != 1 {
		t.Fatalf("sessions of the principal = %d, want 1", n)
	}
	if got := w.authenticate(w.Pinned(id), c); got.Refusal != nil {
		t.Fatalf("the same token after a re-verify = %v, want it to pass", got.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE result = 'reverified' AND source = 'reverify' AND session_id = $1 AND audience = 'staff'`, c.SessionID); n != 1 {
		t.Fatalf("reverified events = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE login = $1`, rvLogin); n != 0 {
		t.Fatalf("throttle rows after the right password = %d, want 0", n)
	}
	for _, secret := range []string{pw, "a wrong password"} {
		if n := w.Count(`SELECT count(*) FROM auth_events e WHERE strpos(e::text, $1) > 0`, secret); n != 0 {
			t.Fatalf("%d events hold a password", n)
		}
	}
}

func TestPasswordReverifyThrottle(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tweak func(*kittest.Rules)
	}{{"count-after", throttleAt(3)}, {"count-before", kittest.DefaultRules}} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t, tc.tweak)
			id := w.User(rvLogin, pw)
			c := w.Claims(w.SignIn(rvLogin, pw))
			w.Clock.Advance(10 * time.Minute)

			var lk authkit.ErrLocked
			for range 12 {
				if res := w.rvPassword(c, "a wrong password"); errors.As(res.Refusal, &lk) {
					break
				}
			}
			if lk.RetryAfter <= 0 {
				t.Fatalf("no ErrLocked with RetryAfter > 0 within 12 wrong passwords; got %v", lk)
			}
			if n := w.rvEvents(id, authkit.ResultBadPassword); n < 1 {
				t.Fatalf("bad_password events = %d, want at least 1", n)
			}
			if res := w.Login("staff", rvLogin, pw); !errors.As(res.Refusal, &lk) {
				t.Fatalf("the login after the lock = %v, want ErrLocked", res.Refusal)
			}
			res := w.rvPassword(c, pw)
			if !errors.As(res.Refusal, &lk) {
				t.Fatalf("the right password while locked = %v, want ErrLocked", res.Refusal)
			}
			if w.rvStamped(c) {
				t.Fatal("a locked re-verify stamped the session")
			}
			if n := w.Count(`SELECT count(*) FROM auth_events WHERE result = 'locked' AND source = 'reverify'`); n < 1 {
				t.Fatalf("locked reverify events = %d, want at least 1", n)
			}
		})
	}
}

func TestPasswordReverifyWithTOTPOn(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	id := w.User(rvLogin, pw)
	c := w.Claims(w.SignIn(rvLogin, pw))
	w.setUpTOTP(c)
	w.Clock.Advance(10 * time.Minute)

	res := w.rvPassword(c, pw)
	if res.Refusal != nil || res.SecondStep != nil || res.Tokens != nil {
		t.Fatalf("the password with TOTP on = refusal %v, second step %t, tokens %t; want the stamp alone", res.Refusal, res.SecondStep != nil, res.Tokens != nil)
	}
	if !w.rvStamped(c) {
		t.Fatal("the password with TOTP on did not stamp the session")
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'reverified' AND source = 'reverify' AND second_factor = ''`, id); n != 1 {
		t.Fatalf("reverified events without a second factor = %d, want 1", n)
	}
}

func TestReverifyEnded(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		w := newWorld(t)
		id := w.User(rvLogin, pw)
		c := w.Claims(w.SignIn(rvLogin, pw))
		w.Clock.Advance(10 * time.Minute)
		w.logout(w.Pinned(id), c)

		if res := w.rvPassword(c, pw); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Fatalf("a re-verify on an ended session = %v, want ErrSessionEnded", res.Refusal)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'reverify'`); n != 0 {
			t.Fatalf("reverify events on an ended session = %d, want 0", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_throttle`); n != 0 {
			t.Fatalf("throttle rows on an ended session = %d, want 0", n)
		}
		if w.rvStamped(c) {
			t.Fatal("a re-verify on an ended session stamped it")
		}
	})
	t.Run("totp", func(t *testing.T) {
		w := newWorld(t, withSecondFactors)
		id := w.User(rvLogin, pw)
		c := w.Claims(w.SignIn(rvLogin, pw))
		secret, _ := w.setUpTOTP(c)
		w.Clock.Advance(10 * time.Minute)
		w.logout(w.Pinned(id), c)
		_, before, _ := w.totpRow(id)

		if res := w.rvTOTP(c, totpCode(t, secret, w.Clock.Now())); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Fatalf("a TOTP re-verify on an ended session = %v, want ErrSessionEnded", res.Refusal)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'reverify'`); n != 0 {
			t.Fatalf("reverify events on an ended session = %d, want 0", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_throttle`); n != 0 {
			t.Fatalf("throttle rows on an ended session = %d, want 0", n)
		}
		if w.rvStamped(c) {
			t.Fatal("a TOTP re-verify on an ended session stamped it")
		}
		if _, after, _ := w.totpRow(id); after != before {
			t.Fatal("a TOTP re-verify on an ended session spent a step")
		}
	})
}

func TestReverifyOtherAudience(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		w := newWorld(t)
		id := w.User(rvLogin, pw)
		cl := *w.Claims(w.Login("client", rvLogin, pw))
		cl.Audience = "staff"

		if res := w.rvPassword(&cl, "a wrong password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
			t.Fatalf("a wrong password = %v, want ErrInvalidCredentials", res.Refusal)
		}
		if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE audience = 'client'`); n != 1 {
			t.Fatalf("client throttle rows = %d, want 1", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE audience = 'staff'`); n != 0 {
			t.Fatalf("staff throttle rows = %d, want 0", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE result = 'bad_password' AND source = 'reverify' AND audience = 'client'`); n != 1 {
			t.Fatalf("client bad_password events = %d, want 1", n)
		}
		if res := w.rvPassword(&cl, pw); res.Refusal != nil {
			t.Fatalf("the right password refused: %v", res.Refusal)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE result = 'reverified' AND source = 'reverify' AND audience = 'client' AND principal_id = $1`, id); n != 1 {
			t.Fatalf("client reverified events = %d, want 1", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE audience = 'staff' AND source = 'reverify'`); n != 0 {
			t.Fatalf("staff reverify events = %d, want 0", n)
		}
	})
	t.Run("totp", func(t *testing.T) {
		w := newWorld(t, withSecondFactors)
		w.User(rvLogin, pw)
		c0 := w.Claims(w.Login("client", rvLogin, pw))
		secret, _ := w.setUpTOTP(c0)
		w.Clock.Advance(10 * time.Minute)
		cl := *c0
		cl.Audience = "staff"

		if res := w.rvTOTP(&cl, w.wrongTOTP(secret)); !errors.Is(res.Refusal, authkit.ErrBadCode) {
			t.Fatalf("a wrong code = %v, want ErrBadCode", res.Refusal)
		}
		if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE audience = 'client'`); n != 1 {
			t.Fatalf("client throttle rows = %d, want 1", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE audience = 'staff'`); n != 0 {
			t.Fatalf("staff throttle rows = %d, want 0", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE result = 'bad_code' AND source = 'reverify' AND audience = 'client'`); n != 1 {
			t.Fatalf("client bad_code events = %d, want 1", n)
		}
		if res := w.rvTOTP(&cl, totpCode(t, secret, w.Clock.Now())); res.Refusal != nil {
			t.Fatalf("the right code refused: %v", res.Refusal)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE result = 'reverified' AND source = 'reverify' AND audience = 'client'`); n != 1 {
			t.Fatalf("client reverified events = %d, want 1", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE audience = 'staff' AND source = 'reverify'`); n != 0 {
			t.Fatalf("staff reverify events = %d, want 0", n)
		}
	})
}

func TestTOTPReverify(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	id := w.User(rvLogin, pw)
	c := w.Claims(w.SignIn(rvLogin, pw))
	secret, _ := w.setUpTOTP(c)
	w.Clock.Advance(10 * time.Minute)

	wrong := w.rvTOTP(c, w.wrongTOTP(secret))
	if !errors.Is(wrong.Refusal, authkit.ErrBadCode) {
		t.Fatalf("a wrong code = %v, want ErrBadCode", wrong.Refusal)
	}
	if w.rvStamped(c) {
		t.Fatal("a wrong code stamped the session")
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'bad_code' AND source = 'reverify' AND second_factor = 'totp'`, id); n != 1 {
		t.Fatalf("bad_code events = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE login = $1 AND failures = 1`, rvLogin); n != 1 {
		t.Fatalf("throttle rows with one failure = %d, want 1", n)
	}

	code := totpCode(t, secret, w.Clock.Now())
	right := w.rvTOTP(c, code)
	if right.Refusal != nil {
		t.Fatalf("the right code refused: %v", right.Refusal)
	}
	if right.Principal.ID != id || right.Tokens != nil {
		t.Fatal("the right code gave more than the principal")
	}
	if !w.rvStamped(c) {
		t.Fatal("the right code did not stamp the session")
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'reverified' AND source = 'reverify' AND second_factor = 'totp' AND session_id = $2`, id, c.SessionID); n != 1 {
		t.Fatalf("reverified events = %d, want 1", n)
	}
	if replay := w.rvTOTP(c, code); !errors.Is(replay.Refusal, authkit.ErrBadCode) {
		t.Fatalf("a replayed code = %v, want ErrBadCode", replay.Refusal)
	}
}

func TestTOTPReverifyRefusesEmailCode(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	id := w.User(rvLogin, pw)
	c := w.Claims(w.SignIn(rvLogin, pw))
	w.enrolEmail(c)
	tok := w.challenge(rvLogin)
	sent := w.stepSend("staff", tok)
	mail, err := w.mint(sent.EmailCode.ID)
	if err != nil {
		t.Fatal(err)
	}
	w.Clock.Advance(time.Minute)

	if res := w.rvTOTP(c, mail.Code); !errors.Is(res.Refusal, authkit.ErrBadCode) {
		t.Fatalf("an email sign-in code = %v, want ErrBadCode", res.Refusal)
	}
	if w.rvStamped(c) {
		t.Fatal("an email sign-in code stamped the session")
	}
	if n := w.codeRow(id).Tries; n != 0 {
		t.Fatalf("sign-in code tries = %d, want 0: the code was spent", n)
	}
	if n := w.rvEvents(id, authkit.ResultReverified); n != 0 {
		t.Fatalf("reverified events = %d, want 0", n)
	}
}

func TestTOTPReverifyRefusesRecovery(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	id := w.User(rvLogin, pw)
	c := w.Claims(w.SignIn(rvLogin, pw))
	_, codes := w.setUpTOTP(c)
	w.Clock.Advance(time.Minute)

	if res := w.rvTOTP(c, codes[0]); !errors.Is(res.Refusal, authkit.ErrBadCode) {
		t.Fatalf("a recovery code = %v, want ErrBadCode", res.Refusal)
	}
	if w.rvStamped(c) {
		t.Fatal("a recovery code stamped the session")
	}
	if n := w.Count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NULL`, id); n != len(codes) {
		t.Fatalf("unspent recovery codes = %d, want %d", n, len(codes))
	}
	if n := w.rvEvents(id, authkit.ResultReverified); n != 0 {
		t.Fatalf("reverified events = %d, want 0", n)
	}
}

func TestTOTPReverifyLocked(t *testing.T) {
	w := newWorld(t, withSecondFactors, throttleAt(3))
	id := w.User(rvLogin, pw)
	c := w.Claims(w.SignIn(rvLogin, pw))
	secret, _ := w.setUpTOTP(c)
	w.Clock.Advance(10 * time.Minute)
	for range 3 {
		w.rvTOTP(c, w.wrongTOTP(secret))
	}
	_, before, _ := w.totpRow(id)

	res := w.rvTOTP(c, totpCode(t, secret, w.Clock.Now()))
	var locked authkit.ErrLocked
	if !errors.As(res.Refusal, &locked) || locked.RetryAfter <= 0 {
		t.Fatalf("a code on a locked login = %v, want ErrLocked", res.Refusal)
	}
	if w.rvStamped(c) {
		t.Fatal("a code on a locked login stamped the session")
	}
	if n := w.rvEvents(id, authkit.ResultLocked); n != 1 {
		t.Fatalf("locked events = %d, want 1", n)
	}
	if _, after, _ := w.totpRow(id); after != before {
		t.Fatal("a code on a locked login spent a step")
	}
	if res := w.Login("staff", rvLogin, pw); !errors.As(res.Refusal, &locked) {
		t.Fatalf("a password sign-in on a locked login = %v, want ErrLocked", res.Refusal)
	}
}

func TestTOTPReverifyOff(t *testing.T) {
	w := newWorld(t)
	w.User(rvLogin, pw)
	c := w.Claims(w.SignIn(rvLogin, pw))

	if res := w.rvTOTP(c, "000000"); !errors.Is(res.Refusal, authkit.ErrSecondFactorsOff) {
		t.Fatalf("a TOTP re-verify with second factors off = %v, want ErrSecondFactorsOff", res.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'reverify'`); n != 0 {
		t.Fatalf("reverify events = %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_throttle`); n != 0 {
		t.Fatalf("throttle rows = %d, want 0", n)
	}
}
