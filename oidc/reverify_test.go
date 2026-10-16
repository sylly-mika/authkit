package oidc_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/oidc"
)

func rvSetup(t *testing.T) (*acctEnv, uuid.UUID, *authkit.Claims) {
	t.Helper()
	e := acctSetup(t)
	id, cl := e.oidcOnly("ada@example.invalid", "g-ada")
	return e, id, cl
}

func (e *acctEnv) beginRV(cl *authkit.Claims, provider string) (oidc.Redirect, error) {
	e.w.T.Helper()
	var r oidc.Redirect
	err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		r, err = e.m.BeginReverify(e.w.Ctx, q, cl, provider)
		return err
	})
	return r, err
}

func (e *acctEnv) rvCeremonies(spent bool) int {
	return e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'reverify' AND (spent_at IS NOT NULL) = $1", spent)
}

func endSession(e *acctEnv, cl *authkit.Claims) {
	e.w.T.Helper()
	e.w.D.Exec(e.w.T, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'user' WHERE id = $1`, cl.SessionID, e.w.Clock.Now())
}

func TestBeginReverifyPrompt(t *testing.T) {
	e, id, cl := rvSetup(t)
	r, err := e.beginRV(cl, "google")
	if err != nil {
		t.Fatalf("begin reverify = %v", err)
	}
	if got := queryOf(r); got.Get("prompt") != "login" || got.Get("max_age") != "0" {
		t.Fatalf("reverify URL query %v, want prompt=login and max_age=0", got)
	}
	e.google.Authorize(e.w.T, r, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	if got := e.google.LastAuthorize().Get("prompt"); got != "login" {
		t.Fatalf("the provider saw prompt %q, want login", got)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'reverify' AND principal_id = $1 AND provider = 'google' AND audience = 'staff' AND spent_at IS NULL", id); n != 1 {
		t.Fatalf("unspent reverify ceremonies for Ada = %d, want 1", n)
	}
	var plain oidc.Redirect
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		plain, err = e.m.Begin(e.w.Ctx, q, "google", acctAud, acctMeta)
		return err
	}); err != nil {
		t.Fatalf("begin = %v", err)
	}
	if got := queryOf(plain); got.Has("prompt") || got.Has("max_age") {
		t.Fatalf("sign-in URL query %v, want no prompt or max_age", got)
	}
}

func TestBeginReverifyUnlinked(t *testing.T) {
	e, _, cl := rvSetup(t)
	cases := []struct {
		name, provider string
		want           error
	}{
		{name: "unlinked", provider: "apple", want: oidc.ErrNotLinked},
		{name: "unknown", provider: "github", want: oidc.ErrUnknownProvider},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.beginRV(cl, tc.provider); !errors.Is(err, tc.want) {
				t.Fatalf("begin reverify with %s = %v, want %v", tc.provider, err, tc.want)
			}
		})
	}
	if n := e.rvCeremonies(false); n != 0 {
		t.Fatalf("reverify ceremonies after refusals = %d, want 0", n)
	}
}

func TestBeginReverifyEnded(t *testing.T) {
	e, _, cl := rvSetup(t)
	endSession(e, cl)
	if _, err := e.beginRV(cl, "google"); !errors.Is(err, authkit.ErrSessionEnded) {
		t.Fatalf("begin reverify on an ended session = %v, want ErrSessionEnded", err)
	}
	if n := e.rvCeremonies(false); n != 0 {
		t.Fatalf("reverify ceremonies on an ended session = %d, want 0", n)
	}
}

func rvRound(e *acctEnv, cl *authkit.Claims, u oidcfake.User) (oidc.Redirect, oidc.Callback) {
	e.w.T.Helper()
	r, err := e.beginRV(cl, "google")
	if err != nil {
		e.w.T.Fatalf("begin reverify = %v", err)
	}
	return r, e.google.Authorize(e.w.T, r, u)
}

func (e *acctEnv) finishRV(cl *authkit.Claims, cb oidc.Callback, binding string) authkit.Result {
	e.w.T.Helper()
	var res authkit.Result
	err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		res, err = e.m.FinishReverify(e.w.Ctx, q, cl, cb, binding, acctMeta)
		return err
	})
	if err != nil {
		e.w.T.Fatalf("finish reverify = %v", err)
	}
	return res
}

func refusedRV(t *testing.T, e *acctEnv, res authkit.Result) {
	t.Helper()
	if n := e.rvEvents("bad_identity"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) || n != 1 {
		t.Fatalf("finish reverify = %+v with %d bad_identity events; want ErrInvalidCredentials and 1 event", res, n)
	}
}

func (e *acctEnv) freshSince(id uuid.UUID, t0 time.Time) int {
	return e.w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL AND authenticated_at > $2", id, t0)
}

func (e *acctEnv) rvEvents(result string) int {
	return e.w.Count("SELECT count(*) FROM auth_events WHERE result = $1 AND source = 'reverify'", result)
}

func noSecret(e *acctEnv, secrets ...string) {
	e.w.T.Helper()
	for i, s := range secrets {
		if n := e.w.Count("SELECT count(*) FROM auth_events e WHERE strpos(row_to_json(e)::text, $1) > 0", s); n != 0 {
			e.w.T.Errorf("an event row carries secret %d", i)
		}
	}
}

func TestFinishReverify(t *testing.T) {
	e, id, cl := rvSetup(t)
	t0 := e.w.Clock.Now()
	e.w.Clock.Advance(3 * time.Minute)
	now := e.w.Clock.Now()
	x0 := e.google.Exchanges()
	r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true, AuthTime: &now})
	res := e.finishRV(cl, cb, r.Binding)
	if res.Refusal != nil || res.Principal.ID != id || res.Session != nil {
		t.Fatalf("finish reverify = %+v; want Ada with no refusal and no session", res)
	}
	if n := e.freshSince(id, t0); n != 1 {
		t.Fatalf("sessions authenticated since the start = %d, want 1", n)
	}
	if n := e.sessions(id); n != 1 {
		t.Fatalf("sessions = %d, want 1 (a reverify adds none)", n)
	}
	if n := e.identityRows(id); n != 1 {
		t.Fatalf("identity rows = %d, want 1", n)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_events WHERE result = 'reverified' AND source = 'reverify' AND second_factor = 'oidc' AND session_id = $1", cl.SessionID); n != 1 {
		t.Fatalf("reverified events for the session = %d, want 1", n)
	}
	if n := e.rvCeremonies(true); n != 1 {
		t.Fatalf("spent reverify ceremonies = %d, want 1", n)
	}
	if n := e.google.Exchanges(); n != x0+1 {
		t.Fatalf("exchanges = %d, want %d", n, x0+1)
	}
	noSecret(e, cb.Code, cb.State, r.Binding)
}

func TestFinishReverifyOtherSubject(t *testing.T) {
	e, id, cl := rvSetup(t)
	idB, _ := e.oidcOnly("bob@example.invalid", "g-bob")
	t0 := e.w.Clock.Now()
	e.w.Clock.Advance(3 * time.Minute)
	r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-bob", Email: "bob@example.invalid", EmailVerified: true})
	refusedRV(e.w.T, e, e.finishRV(cl, cb, r.Binding))
	if n := e.freshSince(id, t0); n != 0 {
		t.Fatalf("Ada's sessions authenticated = %d, want 0", n)
	}
	if n := e.freshSince(idB, t0); n != 0 {
		t.Fatalf("Bob's sessions authenticated = %d, want 0", n)
	}
	if n := e.rvEvents("reverified"); n != 0 {
		t.Fatalf("reverified events = %d, want 0", n)
	}
	if n := e.rvCeremonies(true); n != 1 {
		t.Fatalf("spent reverify ceremonies = %d, want 1", n)
	}
}

func TestFinishReverifyOtherPrincipal(t *testing.T) {
	e, id, cl := rvSetup(t)
	idB, clB := e.oidcOnly("bob@example.invalid", "g-bob")
	t0 := e.w.Clock.Now()
	e.w.Clock.Advance(3 * time.Minute)
	x0 := e.google.Exchanges()
	r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	refusedRV(e.w.T, e, e.finishRV(clB, cb, r.Binding))
	if n := e.google.Exchanges(); n != x0 {
		t.Fatalf("exchanges = %d, want %d (a callback for another principal makes no provider call)", n, x0)
	}
	if n := e.freshSince(id, t0) + e.freshSince(idB, t0); n != 0 {
		t.Fatalf("sessions authenticated = %d, want 0", n)
	}
	if n := e.rvEvents("reverified"); n != 0 {
		t.Fatalf("reverified events = %d, want 0", n)
	}
}

func TestFinishReverifyStaleAuthTime(t *testing.T) {
	cases := []struct {
		name   string
		offset time.Duration
		passes bool
	}{
		{name: "stale", offset: -5*time.Minute - 2*time.Second},
		{name: "inside", offset: -5*time.Minute + 2*time.Second, passes: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, id, cl := rvSetup(t)
			t0 := e.w.Clock.Now()
			e.w.Clock.Advance(3 * time.Minute)
			authAt := e.w.Clock.Now().Add(tc.offset)
			r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true, AuthTime: &authAt})
			res := e.finishRV(cl, cb, r.Binding)
			if tc.passes {
				if res.Refusal != nil || e.freshSince(id, t0) != 1 {
					t.Fatalf("finish reverify = %+v, fresh sessions %d; want no refusal and 1 fresh session", res, e.freshSince(id, t0))
				}
				return
			}
			refusedRV(t, e, res)
			if n := e.freshSince(id, t0); n != 0 {
				t.Fatalf("fresh sessions = %d, want 0", n)
			}
		})
	}
}

func TestFinishReverifyFutureAuthTime(t *testing.T) {
	e, id, cl := rvSetup(t)
	t0 := e.w.Clock.Now()
	e.w.Clock.Advance(3 * time.Minute)
	authAt := e.w.Clock.Now().Add(5*time.Minute + 2*time.Second)
	r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true, AuthTime: &authAt})
	refusedRV(e.w.T, e, e.finishRV(cl, cb, r.Binding))
	if n := e.freshSince(id, t0); n != 0 {
		t.Fatalf("fresh sessions = %d, want 0", n)
	}
}

func TestFinishReverifyNoAuthTime(t *testing.T) {
	e, id, cl := rvSetup(t)
	t0 := e.w.Clock.Now()
	e.w.Clock.Advance(3 * time.Minute)
	r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	res := e.finishRV(cl, cb, r.Binding)
	if res.Refusal != nil {
		t.Fatalf("finish reverify without auth_time = %+v, want no refusal", res)
	}
	if n := e.freshSince(id, t0); n != 1 {
		t.Fatalf("fresh sessions = %d, want 1", n)
	}
	if n := e.rvEvents("reverified"); n != 1 {
		t.Fatalf("reverified events = %d, want 1", n)
	}
}

func TestFinishRefusesReverifyCeremony(t *testing.T) {
	e, id, cl := rvSetup(t)
	t0 := e.w.Clock.Now()
	e.w.Clock.Advance(3 * time.Minute)
	x0 := e.google.Exchanges()
	r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	var res authkit.Result
	var su *oidc.SignUp
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		res, su, err = e.m.Finish(e.w.Ctx, q, cb, r.Binding, acctMeta)
		return err
	}); err != nil {
		t.Fatalf("finish = %v", err)
	}
	if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) || su != nil {
		t.Fatalf("Finish on a reverify ceremony = %+v, sign-up %+v; want ErrInvalidCredentials and no sign-up", res, su)
	}
	if n := e.google.Exchanges(); n != x0 {
		t.Fatalf("exchanges = %d, want %d", n, x0)
	}
	if n := e.sessions(id); n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}
	if n := e.rvCeremonies(false); n != 1 {
		t.Fatalf("unspent reverify ceremonies = %d, want 1", n)
	}
	res = e.finishRV(cl, cb, r.Binding)
	if res.Refusal != nil || e.freshSince(id, t0) != 1 {
		t.Fatalf("FinishReverify after Finish = %+v, fresh sessions %d; want no refusal and 1", res, e.freshSince(id, t0))
	}
}

func TestFinishReverifyRefusesSignInCeremony(t *testing.T) {
	e, _, cl := rvSetup(t)
	e.w.Clock.Advance(3 * time.Minute)
	x0 := e.google.Exchanges()
	var r oidc.Redirect
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		r, err = e.m.Begin(e.w.Ctx, q, "google", acctAud, acctMeta)
		return err
	}); err != nil {
		t.Fatalf("begin = %v", err)
	}
	cb := e.google.Authorize(e.w.T, r, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	refusedRV(e.w.T, e, e.finishRV(cl, cb, r.Binding))
	if n := e.google.Exchanges(); n != x0 {
		t.Fatalf("exchanges = %d, want %d", n, x0)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'signin' AND spent_at IS NULL"); n != 1 {
		t.Fatalf("unspent sign-in ceremonies = %d, want 1", n)
	}
}

func TestFinishReverifyReplay(t *testing.T) {
	e, id, cl := rvSetup(t)
	t0 := e.w.Clock.Now()
	e.w.Clock.Advance(3 * time.Minute)
	x0 := e.google.Exchanges()
	r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	if res := e.finishRV(cl, cb, r.Binding); res.Refusal != nil {
		t.Fatalf("first finish = %+v, want no refusal", res)
	}
	res := e.finishRV(cl, cb, r.Binding)
	if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("second finish = %+v, want ErrInvalidCredentials", res)
	}
	if n := e.google.Exchanges(); n != x0+1 {
		t.Fatalf("exchanges = %d, want %d", n, x0+1)
	}
	if n := e.rvEvents("reverified"); n != 1 {
		t.Fatalf("reverified events = %d, want 1", n)
	}
	if n := e.freshSince(id, t0); n != 1 {
		t.Fatalf("fresh sessions = %d, want 1", n)
	}
}

func TestFinishReverifyEnded(t *testing.T) {
	e, id, cl := rvSetup(t)
	e.w.Clock.Advance(3 * time.Minute)
	r, cb := rvRound(e, cl, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	endSession(e, cl)
	res := e.finishRV(cl, cb, r.Binding)
	if !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("finish on an ended session = %+v, want ErrSessionEnded", res)
	}
	if n := e.rvEvents("reverified"); n != 0 {
		t.Fatalf("reverified events = %d, want 0", n)
	}
	if n := e.rvCeremonies(true); n != 1 {
		t.Fatalf("spent reverify ceremonies = %d, want 1", n)
	}
	_ = id
}
