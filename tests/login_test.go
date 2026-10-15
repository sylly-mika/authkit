package tests

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/transport/bearer"
)

func TestLoginSignsIn(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "correct horse battery")
	res := w.Login("staff", "  Ada@Example.invalid ", "correct horse battery")
	if res.Refusal != nil || res.Principal.ID != id || res.Session == nil || res.Tokens == nil || res.Admission == nil {
		t.Fatalf("result = %+v", res)
	}
	now := w.Clock.Now()
	if s := res.Session; *s.ScopeID != w.P.Scope || s.Audience != "staff" || !s.AuthenticatedAt.Equal(now) || !s.ExpiresAt.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("session = %+v", s)
	}
	c := w.Claims(res)
	if c.Subject != id || c.SessionID != res.Session.ID || c.App["ws"] != w.P.Scope.String() || c.App["role"] != "member" || !res.Tokens.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("access token claims = %+v, expiry %v", c, res.Tokens.ExpiresAt)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND token_hash = $2`, res.Session.ID, authkit.HashToken(res.Tokens.RefreshToken)) != 1 {
		t.Fatal("the session does not store the refresh token's sha256")
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'signed_in' AND session_id = $2 AND scope_id = $3
	            AND login = '  Ada@Example.invalid ' AND ip = '192.0.2.1' AND user_agent = 'authkit-test'`, id, res.Session.ID, w.P.Scope) != 1 {
		t.Fatal("no signed_in event with the session, scope and the login as typed")
	}
}

func TestLoginHonoursRefreshTTLFor(t *testing.T) {
	w := newWorld(t, func(c *kittest.Rules) {
		c.RefreshTTLFor = map[authkit.Audience]time.Duration{"client": time.Hour}
	})
	w.User("ada@example.invalid", "the right password")
	now := w.Clock.Now()
	for aud, ttl := range map[authkit.Audience]time.Duration{"client": time.Hour, "staff": 7 * 24 * time.Hour} {
		res := w.Login(aud, "ada@example.invalid", "the right password")
		if res.Refusal != nil || !res.Session.ExpiresAt.Equal(now.Add(ttl)) ||
			w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND expires_at = $2`, res.Session.ID, now.Add(ttl)) != 1 {
			t.Errorf("%s: %+v; want the session to expire at now+%v", aud, res, ttl)
		}
	}
}

func TestLoginRefusalsAreLoggedAndCounted(t *testing.T) {
	w := newWorld(t)
	known := w.User("known@example.invalid", "the right password")
	invited := w.User("invited@example.invalid", "")
	for _, tc := range []struct {
		login, pw, result string
		principal         *uuid.UUID
	}{
		{"nobody@example.invalid", "whatever it is", authkit.ResultUnknownLogin, nil},
		{"invited@example.invalid", "whatever it is", authkit.ResultNoPassword, &invited},
		{"known@example.invalid", "a wrong password", authkit.ResultBadPassword, &known},
	} {
		res := w.Login("staff", tc.login, tc.pw)
		if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) || res.Session != nil {
			t.Fatalf("%s: %+v, want ErrInvalidCredentials", tc.result, res)
		}
		var result string
		var principal *uuid.UUID
		if err := w.D.Row(t, `SELECT result, principal_id FROM auth_events WHERE login = $1`, tc.login).Scan(&result, &principal); err != nil {
			t.Fatal(err)
		}
		if result != tc.result || (principal == nil) != (tc.principal == nil) || (principal != nil && *principal != *tc.principal) {
			t.Errorf("%s: logged %s for %v", tc.result, result, principal)
		}
		if w.Count(`SELECT COALESCE((SELECT failures FROM auth_throttle WHERE login = $1 AND audience = 'staff'), 0)`, tc.login) != 1 {
			t.Errorf("%s: the failure was not counted", tc.result)
		}
	}
}

func TestARefusedLoginCommitsItsThrottleAndEvent(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	var res authkit.Result
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		res, err = w.Svc.Password.Login(w.Ctx, q, "staff", "ada@example.invalid", "a wrong password", authkit.Meta{})
		return err
	}); err != nil || !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("Login = %+v, %v", res, err)
	}
	if w.Count(`SELECT failures FROM auth_throttle WHERE login = 'ada@example.invalid'`) != 1 || !slices.Equal(w.Results(id), []string{"bad_password"}) {
		t.Fatal("the committed transaction lost the throttle increment or the bad_password event")
	}
}

func TestTheThrottleKeysTheNormalisedLogin(t *testing.T) {
	w := newWorld(t)
	w.User("zoë@example.invalid", "the right password")
	variants := []string{"zoë@example.invalid", " ZOË@example.invalid", "zoe\u0308@example.invalid", "Zoe\u0308@EXAMPLE.invalid "}
	for i := range 10 {
		w.Login("staff", variants[i%len(variants)], "a wrong password")
	}
	var locked authkit.ErrLocked
	if res := w.Login("staff", "zoë@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) {
		t.Fatalf("ten failures across case, space and NFD variants = %v, want ErrLocked", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_throttle`) != 1 {
		t.Fatal("the variants got counters of their own")
	}
}

func TestUnknownLoginsAreCountedAndTheThrottleIsPerAudience(t *testing.T) {
	w := newWorld(t)
	for range 10 {
		w.Login("staff", "nobody@example.invalid", "a wrong password")
	}
	var locked authkit.ErrLocked
	if res := w.Login("staff", "nobody@example.invalid", "a wrong password"); !errors.As(res.Refusal, &locked) {
		t.Fatalf("an unknown login was not locked: %v", res.Refusal)
	}
	w.User("ada@example.invalid", "the right password")
	for range 10 {
		w.Login("staff", "ada@example.invalid", "a wrong password")
	}
	if res := w.Login("client", "ada@example.invalid", "the right password"); res.Refusal != nil {
		t.Fatalf("a staff lockout locked the client audience: %v", res.Refusal)
	}
}

func TestAdmitRefusalIsReturnedAsTheAppMadeIt(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	errNoMembership := errors.New("app: no membership")
	w.P.Refuse(id, errNoMembership)
	res := w.Login("staff", "ada@example.invalid", "the right password")
	if res.Refusal != errNoMembership || res.Session != nil {
		t.Fatalf("refusal = %v, want the app's own error value", res.Refusal)
	}
	if !slices.Equal(w.Results(id), []string{"no_membership"}) || w.Count(`SELECT count(*) FROM auth_sessions`) != 0 ||
		w.Count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("want one no_membership event, no session and no counted failure")
	}
}

func TestAnAdmitRefusalLeavesTheThrottleAsItWas(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	for range 9 {
		w.Login("staff", "ada@example.invalid", "a wrong password")
	}
	w.P.Refuse(id, errors.New("app: no membership"))
	w.Login("staff", "ada@example.invalid", "the right password")
	if n := w.Count(`SELECT COALESCE((SELECT failures FROM auth_throttle WHERE login = 'ada@example.invalid' AND audience = 'staff'), 0)`); n != 9 {
		t.Fatalf("failures after an Admit refusal = %d, want 9: only a sign-in clears the throttle (spec §7)", n)
	}
}

func TestANilErrorRefusalIsAnError(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	w.P.Refuse(id, nil)
	var res authkit.Result
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		res, err = w.Svc.Password.Login(w.Ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{})
		return err
	})
	if err == nil {
		t.Fatalf("Admit's Refuse(result, nil) = %+v with no error; want an error", res)
	}
}

func TestLoginRefusesReservedAppClaims(t *testing.T) {
	for _, name := range bearer.Reserved {
		w := newWorld(t)
		w.User("ada@example.invalid", "the right password")
		w.P.SetClaim(name, "x")
		err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			_, err := w.Svc.Password.Login(w.Ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{})
			return err
		})
		if !errors.Is(err, bearer.ErrReservedClaim) || w.Count(`SELECT count(*) FROM auth_sessions`) != 0 {
			t.Errorf("app claim %q = %v; want ErrReservedClaim and no session (spec §8.4)", name, err)
		}
	}
}

func TestReservedClaimsFailBeforeTheSessionRow(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	w.P.SetClaim("sub", "x")
	tx, err := w.D.App.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	q := sqldb.Tx(tx)
	if _, err := w.Svc.Password.Login(w.Ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{}); !errors.Is(err, bearer.ErrReservedClaim) {
		t.Fatalf("Login = %v, want ErrReservedClaim", err)
	}
	var n int
	if err := q.QueryRow(w.Ctx, w.D.SQL(`SELECT count(*) FROM auth_sessions`)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the failed Login's transaction holds %d session rows (%v); want 0, the check comes first (spec §8.4)", n, err)
	}
}

func TestLoginRehashesWhenTheParametersRise(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	stronger := w.Cfg
	stronger.Password.Hashing.Time = 2
	w.Svc = w.Build(stronger)
	w.SignIn("ada@example.invalid", "the right password")
	var hash string
	if err := w.D.Row(t, `SELECT password_hash FROM auth_credentials WHERE principal_id = $1`, id).Scan(&hash); err != nil || !strings.Contains(hash, ",t=2,") {
		t.Fatalf("hash after the login = %q (%v); want it rehashed at t=2 (spec §8.7)", hash, err)
	}
	w.SignIn("ada@example.invalid", "the right password")
}

func TestLoginLogsTheLoginAsTypedWithinBounds(t *testing.T) {
	w := newWorld(t)
	typed := strings.Repeat("ā", 300) + "@example.invalid"
	w.Login("staff", typed, "a wrong password")
	if w.Count(`SELECT count(*) FROM auth_events WHERE login = $1`, strings.Repeat("ā", 254)) != 1 {
		t.Fatal("the event's login is not the typed login cut to 254 characters")
	}
	if w.Count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a login longer than 254 characters got a throttle row")
	}
}

func TestALoginTooLongToThrottleIsUnknown(t *testing.T) {
	w := newWorld(t)
	long := strings.Repeat("a", 260) + "@example.invalid"
	id := w.User(long, "the right password")
	if res := w.Login("staff", long, "the right password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("an account whose login the throttle cannot key = %+v; want ErrInvalidCredentials", res.Refusal)
	}
	if len(w.Results(id)) != 0 || w.Count(`SELECT count(*) FROM auth_events WHERE result = 'unknown_login' AND principal_id IS NULL`) != 1 {
		t.Fatalf("results = %v; want one unknown_login event without a principal", w.Results(id))
	}
}

func TestLoginRefusesNotErrsOnNUL(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	if res := w.Login("staff", "ada\x00@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("a login with a NUL = %v, want ErrInvalidCredentials", res.Refusal)
	}
	if !slices.Equal(w.Results(id), []string{"bad_password"}) {
		t.Fatalf("results = %v, want the NUL login's bad_password", w.Results(id))
	}
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.Login(w.Ctx, q, "staff", "ada@example.invalid", "the right password",
			authkit.Meta{IP: "192.0.2.1\x00", UserAgent: "authkit-\xfftest\x00"})
	})
	if res.Refusal != nil || res.Session == nil || res.Session.IP != "192.0.2.1" || res.Session.UserAgent != "authkit-test" {
		t.Fatalf("result = %+v", res)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND ip = '192.0.2.1' AND user_agent = 'authkit-test'`, res.Session.ID) != 1 ||
		w.Count(`SELECT count(*) FROM auth_events WHERE session_id = $1 AND ip = '192.0.2.1' AND user_agent = 'authkit-test'`, res.Session.ID) != 1 {
		t.Fatal("the session or its signed_in event does not hold the cleaned IP and user agent")
	}
}

func TestLoginNeedsATransaction(t *testing.T) {
	w := newWorld(t)
	conn := w.Pinned(w.User("ada@example.invalid", "the right password"))
	if _, err := w.Svc.Password.Login(w.Ctx, sqldb.Conn(conn), "staff", "ada@example.invalid", "the right password", authkit.Meta{}); !errors.Is(err, db.ErrTxRequired) {
		t.Fatalf("Login on a bare connection = %v, want db.ErrTxRequired", err)
	}
}

type ticking struct{ c *authkittest.Clock }

func (t ticking) Now() time.Time {
	t.c.Advance(time.Second)
	return t.c.Now()
}

func TestTheAccessTokenUsesTheMethodsInstant(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	cfg := w.Cfg
	cfg.Clock = ticking{w.Clock}
	w.Svc = w.Build(cfg)
	res := w.SignIn("ada@example.invalid", "the right password")
	if want := res.Session.CreatedAt.Add(15 * time.Minute); !res.Tokens.ExpiresAt.Equal(want) {
		t.Fatalf("Login's access token expires at %v, want its session's now + 15m = %v", res.Tokens.ExpiresAt, want)
	}
	if iat := w.Claims(res).IssuedAt; !iat.Equal(res.Session.CreatedAt) {
		t.Fatalf("Login's access token was issued at %v, want its session's now %v", iat, res.Session.CreatedAt)
	}
	next := w.refresh("staff", res.Tokens.RefreshToken)
	if next.Refusal != nil {
		t.Fatalf("refresh = %v", next.Refusal)
	}
	if now := *next.Session.RotatedAt; !next.Tokens.ExpiresAt.Equal(now.Add(15*time.Minute)) || !w.Claims(next).IssuedAt.Equal(now) {
		t.Fatalf("Refresh's access token runs %v to %v, want from its rotation's now %v", w.Claims(next).IssuedAt, next.Tokens.ExpiresAt, now)
	}
}
