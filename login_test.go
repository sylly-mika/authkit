package authkit_test

import (
	"context"
	crand "crypto/rand"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/password"
	"github.com/sylly-mika/authkit/transport/bearer"
)

func TestLoginSignsIn(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "correct horse battery")
	res := w.login("staff", "  Ada@Example.invalid ", "correct horse battery")
	if res.Refusal != nil || res.Principal.ID != id || res.Session == nil || res.Tokens == nil || res.Admission == nil {
		t.Fatalf("result = %+v", res)
	}
	now := w.clock.Now()
	if s := res.Session; *s.ScopeID != w.p.Scope || s.Audience != "staff" || !s.AuthenticatedAt.Equal(now) || !s.ExpiresAt.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("session = %+v", s)
	}
	c := w.claims(res)
	if c.Subject != id || c.SessionID != res.Session.ID || c.App["ws"] != w.p.Scope.String() || c.App["role"] != "member" || !res.Tokens.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("access token claims = %+v, expiry %v", c, res.Tokens.ExpiresAt)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND token_hash = $2`, res.Session.ID, authkit.HashToken(res.Tokens.RefreshToken)) != 1 {
		t.Fatal("the session does not store the refresh token's sha256")
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'signed_in' AND session_id = $2 AND scope_id = $3
	            AND login = '  Ada@Example.invalid ' AND ip = '192.0.2.1' AND user_agent = 'authkit-test'`, id, res.Session.ID, w.p.Scope) != 1 {
		t.Fatal("no signed_in event with the session, scope and the login as typed")
	}
}

func TestLoginHonoursRefreshTTLFor(t *testing.T) {
	w := newWorld(t, func(c *authkit.Config) {
		c.RefreshTTLFor = map[authkit.Audience]time.Duration{"client": time.Hour}
	})
	w.user("ada@example.invalid", "the right password")
	now := w.clock.Now()
	for aud, ttl := range map[authkit.Audience]time.Duration{"client": time.Hour, "staff": 7 * 24 * time.Hour} {
		res := w.login(aud, "ada@example.invalid", "the right password")
		if res.Refusal != nil || !res.Session.ExpiresAt.Equal(now.Add(ttl)) ||
			w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND expires_at = $2`, res.Session.ID, now.Add(ttl)) != 1 {
			t.Errorf("%s: %+v; want the session to expire at now+%v", aud, res, ttl)
		}
	}
}

func TestLoginRefusalsAreLoggedAndCounted(t *testing.T) {
	w := newWorld(t)
	known := w.user("known@example.invalid", "the right password")
	invited := w.user("invited@example.invalid", "")
	for _, tc := range []struct {
		login, pw, result string
		principal         *uuid.UUID
	}{
		{"nobody@example.invalid", "whatever it is", authkit.ResultUnknownLogin, nil},
		{"invited@example.invalid", "whatever it is", authkit.ResultNoPassword, &invited},
		{"known@example.invalid", "a wrong password", authkit.ResultBadPassword, &known},
	} {
		res := w.login("staff", tc.login, tc.pw)
		if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) || res.Session != nil {
			t.Fatalf("%s: %+v, want ErrInvalidCredentials", tc.result, res)
		}
		var result string
		var principal *uuid.UUID
		if err := w.d.Row(t, `SELECT result, principal_id FROM auth_events WHERE login = $1`, tc.login).Scan(&result, &principal); err != nil {
			t.Fatal(err)
		}
		if result != tc.result || (principal == nil) != (tc.principal == nil) || (principal != nil && *principal != *tc.principal) {
			t.Errorf("%s: logged %s for %v", tc.result, result, principal)
		}
		if w.count(`SELECT COALESCE((SELECT failures FROM auth_throttle WHERE login = $1 AND audience = 'staff'), 0)`, tc.login) != 1 {
			t.Errorf("%s: the failure was not counted", tc.result)
		}
	}
}

// TestLoginVerifiesExactlyOncePerAttempt is spec §8.6: the dummy verify makes
// an unknown login and a login without a password cost what a wrong one does.
func TestLoginVerifiesExactlyOncePerAttempt(t *testing.T) {
	w := newWorld(t)
	w.user("known@example.invalid", "the right password")
	w.user("invited@example.invalid", "")
	var calls atomic.Int64
	authkit.SetVerifyHook(w.svc, func() { calls.Add(1) })
	for name, tc := range map[string][2]string{
		"unknown login":  {"nobody@example.invalid", "whatever it is"},
		"no credential":  {"invited@example.invalid", "whatever it is"},
		"wrong password": {"known@example.invalid", "a wrong password"},
		"right password": {"known@example.invalid", "the right password"},
	} {
		calls.Store(0)
		w.login("client", tc[0], tc[1])
		if n := calls.Load(); n != 1 {
			t.Errorf("%s: %d argon2id verifications, want exactly 1", name, n)
		}
	}
}

// TestARefusedLoginCommitsItsThrottleAndEvent is spec §12's transaction test:
// the refusal is a value, so the caller's transaction commits its writes.
func TestARefusedLoginCommitsItsThrottleAndEvent(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	var res authkit.Result
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		res, err = w.svc.Login(w.ctx, q, "staff", "ada@example.invalid", "a wrong password", authkit.Meta{})
		return err
	}); err != nil || !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("Login = %+v, %v", res, err)
	}
	if w.count(`SELECT failures FROM auth_throttle WHERE login = 'ada@example.invalid'`) != 1 || !slices.Equal(w.results(id), []string{"bad_password"}) {
		t.Fatal("the committed transaction lost the throttle increment or the bad_password event")
	}
}

// TestTheLockoutEngagesAfterTenFailures is spec §8.9.
func TestTheLockoutEngagesAfterTenFailures(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	for range 10 {
		w.login("staff", "ada@example.invalid", "a wrong password")
	}
	var calls atomic.Int64
	authkit.SetVerifyHook(w.svc, func() { calls.Add(1) })
	w.clock.Advance(5 * time.Minute)
	var locked authkit.ErrLocked
	if res := w.login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 10*time.Minute {
		t.Fatalf("the 11th attempt = %v, want ErrLocked{10m}", res.Refusal)
	}
	if calls.Load() != 0 {
		t.Fatal("a locked login ran the hash; the check must come first")
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE result = 'locked' AND login = 'ada@example.invalid'`) != 1 {
		t.Fatal("no locked event")
	}
	w.clock.Advance(10 * time.Minute)
	if res := w.login("staff", "ada@example.invalid", "the right password"); res.Refusal != nil {
		t.Fatalf("after the lockout = %v", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_throttle WHERE login = 'ada@example.invalid'`) != 0 {
		t.Fatal("a sign-in left the counter behind")
	}
}

func TestTheThrottleKeysTheNormalisedLogin(t *testing.T) {
	w := newWorld(t)
	w.user("zoë@example.invalid", "the right password")
	variants := []string{"zoë@example.invalid", " ZOË@example.invalid", "zoe\u0308@example.invalid", "Zoe\u0308@EXAMPLE.invalid "}
	for i := range 10 {
		w.login("staff", variants[i%len(variants)], "a wrong password")
	}
	var locked authkit.ErrLocked
	if res := w.login("staff", "zoë@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) {
		t.Fatalf("ten failures across case, space and NFD variants = %v, want ErrLocked", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_throttle`) != 1 {
		t.Fatal("the variants got counters of their own")
	}
}

func TestUnknownLoginsAreCountedAndTheThrottleIsPerAudience(t *testing.T) {
	w := newWorld(t)
	for range 10 {
		w.login("staff", "nobody@example.invalid", "a wrong password")
	}
	var locked authkit.ErrLocked
	if res := w.login("staff", "nobody@example.invalid", "a wrong password"); !errors.As(res.Refusal, &locked) {
		t.Fatalf("an unknown login was not locked: %v", res.Refusal)
	}
	w.user("ada@example.invalid", "the right password")
	for range 10 {
		w.login("staff", "ada@example.invalid", "a wrong password")
	}
	if res := w.login("client", "ada@example.invalid", "the right password"); res.Refusal != nil {
		t.Fatalf("a staff lockout locked the client audience: %v", res.Refusal)
	}
}

func TestAdmitRefusalIsReturnedAsTheAppMadeIt(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	errNoMembership := errors.New("app: no membership")
	w.p.Refuse(id, errNoMembership)
	res := w.login("staff", "ada@example.invalid", "the right password")
	if res.Refusal != errNoMembership || res.Session != nil {
		t.Fatalf("refusal = %v, want the app's own error value", res.Refusal)
	}
	if !slices.Equal(w.results(id), []string{"no_membership"}) || w.count(`SELECT count(*) FROM auth_sessions`) != 0 ||
		w.count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("want one no_membership event, no session and no counted failure")
	}
}

func TestAnAdmitRefusalLeavesTheThrottleAsItWas(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	for range 9 {
		w.login("staff", "ada@example.invalid", "a wrong password")
	}
	w.p.Refuse(id, errors.New("app: no membership"))
	w.login("staff", "ada@example.invalid", "the right password")
	if n := w.count(`SELECT COALESCE((SELECT failures FROM auth_throttle WHERE login = 'ada@example.invalid' AND audience = 'staff'), 0)`); n != 9 {
		t.Fatalf("failures after an Admit refusal = %d, want 9: only a sign-in clears the throttle (spec §7)", n)
	}
}

func TestANilErrorRefusalIsAnError(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	w.p.Refuse(id, nil)
	var res authkit.Result
	err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		res, err = w.svc.Login(w.ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{})
		return err
	})
	if err == nil {
		t.Fatalf("Admit's Refuse(result, nil) = %+v with no error; want an error", res)
	}
}

func TestLoginRefusesReservedAppClaims(t *testing.T) {
	for _, name := range bearer.Reserved {
		w := newWorld(t)
		w.user("ada@example.invalid", "the right password")
		w.p.SetClaim(name, "x")
		err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
			_, err := w.svc.Login(w.ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{})
			return err
		})
		if !errors.Is(err, bearer.ErrReservedClaim) || w.count(`SELECT count(*) FROM auth_sessions`) != 0 {
			t.Errorf("app claim %q = %v; want ErrReservedClaim and no session (spec §8.4)", name, err)
		}
	}
}

func TestReservedClaimsFailBeforeTheSessionRow(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	w.p.SetClaim("sub", "x")
	tx, err := w.d.App.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	q := sqldb.Tx(tx)
	if _, err := w.svc.Login(w.ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{}); !errors.Is(err, bearer.ErrReservedClaim) {
		t.Fatalf("Login = %v, want ErrReservedClaim", err)
	}
	var n int
	if err := q.QueryRow(w.ctx, `SELECT count(*) FROM auth_sessions`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the failed Login's transaction holds %d session rows (%v); want 0, the check comes first (spec §8.4)", n, err)
	}
}

func TestLoginRehashesWhenTheParametersRise(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	stronger := w.cfg
	stronger.Hashing.Time = 2
	w.svc = w.service(stronger)
	w.signIn("ada@example.invalid", "the right password")
	var hash string
	if err := w.d.Row(t, `SELECT password_hash FROM auth_credentials WHERE principal_id = $1`, id).Scan(&hash); err != nil || !strings.Contains(hash, ",t=2,") {
		t.Fatalf("hash after the login = %q (%v); want it rehashed at t=2 (spec §8.7)", hash, err)
	}
	w.signIn("ada@example.invalid", "the right password")
}

// TestARehashKeepsAPasswordChangedDuringTheLogin: a change or reset that
// commits between Login's credential read and its rehash must survive it.
func TestARehashKeepsAPasswordChangedDuringTheLogin(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	changed, err := password.Encode(w.cfg.Hashing, crand.Reader, "the new password")
	if err != nil {
		t.Fatal(err)
	}
	stronger := w.cfg
	stronger.Hashing.Time = 2
	w.svc = w.service(stronger)
	var once sync.Once
	authkit.SetVerifyHook(w.svc, func() {
		once.Do(func() {
			w.d.Exec(t, `UPDATE auth_credentials SET password_hash = $2 WHERE principal_id = $1`, id, changed)
		})
	})
	w.login("staff", "ada@example.invalid", "the old password")
	if got := w.storedHash(id); got != changed {
		t.Fatalf("the rehash overwrote a password changed during the login: stored %q, want %q", got, changed)
	}
}

// admitHook runs before the harness's Admit: after Login's verify has released
// its hash slot and before the rehash asks for one.
type admitHook struct {
	*authkittest.Principals
	before func()
}

func (p admitHook) Admit(ctx context.Context, q db.Querier, prop authkit.Proposal) (authkit.Admission, error) {
	p.before()
	return p.Principals.Admit(ctx, q, prop)
}

func TestLoginSkipsTheRehashWhenTheCeilingIsFull(t *testing.T) {
	w := newWorld(t, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
	id := w.user("ada@example.invalid", "the right password")
	stronger := w.cfg
	stronger.Hashing.Time = 2
	var svc *authkit.Service
	var release func()
	hold := true
	svc, err := authkit.New(stronger, admitHook{w.p, func() {
		if !hold {
			return
		}
		r, err := authkit.HoldHashSlot(w.ctx, svc)
		if err != nil {
			t.Fatal(err)
		}
		release = r
	}})
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	w.signIn("ada@example.invalid", "the right password")
	if h := w.storedHash(id); !strings.Contains(h, ",t=1,") {
		t.Fatalf("hash after a sign-in with the ceiling full = %q; want the rehash skipped", h)
	}
	release()
	hold = false
	w.signIn("ada@example.invalid", "the right password")
	if h := w.storedHash(id); !strings.Contains(h, ",t=2,") {
		t.Fatalf("hash after the next sign-in = %q; want it rehashed at t=2", h)
	}
}

func TestLoginAnswersBusyWhenTheCeilingIsFull(t *testing.T) {
	w := newWorld(t, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
	w.user("ada@example.invalid", "the right password")
	release, err := authkit.HoldHashSlot(w.ctx, w.svc)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if res := w.login("staff", "ada@example.invalid", "the right password"); !errors.Is(res.Refusal, authkit.ErrBusy) {
		t.Fatalf("Login with the ceiling full = %v, want ErrBusy", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_events`)+w.count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a busy refusal wrote")
	}
}

func TestLoginLogsTheLoginAsTypedWithinBounds(t *testing.T) {
	w := newWorld(t)
	typed := strings.Repeat("ā", 300) + "@example.invalid"
	w.login("staff", typed, "a wrong password")
	if w.count(`SELECT count(*) FROM auth_events WHERE login = $1`, strings.Repeat("ā", 254)) != 1 {
		t.Fatal("the event's login is not the typed login cut to 254 characters")
	}
	if w.count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a login longer than 254 characters got a throttle row")
	}
}

// TestALoginTooLongToThrottleIsUnknown is spec correction 14: a login the
// throttle cannot count is never looked up, so no account escapes it.
func TestALoginTooLongToThrottleIsUnknown(t *testing.T) {
	w := newWorld(t)
	long := strings.Repeat("a", 260) + "@example.invalid"
	id := w.user(long, "the right password")
	if res := w.login("staff", long, "the right password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("an account whose login the throttle cannot key = %+v; want ErrInvalidCredentials", res.Refusal)
	}
	if len(w.results(id)) != 0 || w.count(`SELECT count(*) FROM auth_events WHERE result = 'unknown_login' AND principal_id IS NULL`) != 1 {
		t.Fatalf("results = %v; want one unknown_login event without a principal", w.results(id))
	}
}

// TestLoginRefusesNotErrsOnNUL: Postgres text holds no NUL or invalid UTF-8,
// so what the client sends must not turn a refusal or a sign-in into an error.
func TestLoginRefusesNotErrsOnNUL(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	if res := w.login("staff", "ada\x00@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("a login with a NUL = %v, want ErrInvalidCredentials", res.Refusal)
	}
	if !slices.Equal(w.results(id), []string{"bad_password"}) {
		t.Fatalf("results = %v, want the NUL login's bad_password", w.results(id))
	}
	res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.Login(w.ctx, q, "staff", "ada@example.invalid", "the right password",
			authkit.Meta{IP: "192.0.2.1\x00", UserAgent: "authkit-\xfftest\x00"})
	})
	if res.Refusal != nil || res.Session == nil || res.Session.IP != "192.0.2.1" || res.Session.UserAgent != "authkit-test" {
		t.Fatalf("result = %+v", res)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND ip = '192.0.2.1' AND user_agent = 'authkit-test'`, res.Session.ID) != 1 ||
		w.count(`SELECT count(*) FROM auth_events WHERE session_id = $1 AND ip = '192.0.2.1' AND user_agent = 'authkit-test'`, res.Session.ID) != 1 {
		t.Fatal("the session or its signed_in event does not hold the cleaned IP and user agent")
	}
}

func TestLoginNeedsATransaction(t *testing.T) {
	w := newWorld(t)
	conn := w.pinned(w.user("ada@example.invalid", "the right password"))
	if _, err := w.svc.Login(w.ctx, sqldb.Conn(conn), "staff", "ada@example.invalid", "the right password", authkit.Meta{}); !errors.Is(err, db.ErrTxRequired) {
		t.Fatalf("Login on a bare connection = %v, want db.ErrTxRequired", err)
	}
}

// ticking advances a second on every read, so a method that reads the clock
// twice stamps two instants.
type ticking struct{ c *authkittest.Clock }

func (t ticking) Now() time.Time {
	t.c.Advance(time.Second)
	return t.c.Now()
}

// TestTheAccessTokenUsesTheMethodsInstant is Decision P3: the access token is
// issued at the method's one now, not at a second read of the clock.
func TestTheAccessTokenUsesTheMethodsInstant(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	cfg := w.cfg
	cfg.Clock = ticking{w.clock}
	w.svc = w.service(cfg)
	res := w.signIn("ada@example.invalid", "the right password")
	if want := res.Session.CreatedAt.Add(15 * time.Minute); !res.Tokens.ExpiresAt.Equal(want) {
		t.Fatalf("Login's access token expires at %v, want its session's now + 15m = %v", res.Tokens.ExpiresAt, want)
	}
	if iat := w.claims(res).IssuedAt; !iat.Equal(res.Session.CreatedAt) {
		t.Fatalf("Login's access token was issued at %v, want its session's now %v", iat, res.Session.CreatedAt)
	}
	next := w.refresh("staff", res.Tokens.RefreshToken)
	if next.Refusal != nil {
		t.Fatalf("refresh = %v", next.Refusal)
	}
	if now := *next.Session.RotatedAt; !next.Tokens.ExpiresAt.Equal(now.Add(15*time.Minute)) || !w.claims(next).IssuedAt.Equal(now) {
		t.Fatalf("Refresh's access token runs %v to %v, want from its rotation's now %v", w.claims(next).IssuedAt, next.Tokens.ExpiresAt, now)
	}
}
