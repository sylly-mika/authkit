package oidc_test

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/oidc"
)

const redirect = "https://app.example.invalid/oidc/callback"

var aud = authkit.Audience("staff")

// newWorld builds a World with one oidc module over a fake provider per kind. tweak, when not nil, edits each provider before it is configured.
func newWorld(t *testing.T, tweak func(*oidc.Provider), kinds ...oidcfake.Kind) (*kittest.World, *oidc.Module, map[oidcfake.Kind]*oidcfake.Server) {
	t.Helper()
	w := kittest.New(t)
	fakes := make(map[oidcfake.Kind]*oidcfake.Server, len(kinds))
	var ps []oidc.Provider
	for _, kind := range kinds {
		f := oidcfake.New(t, kind)
		f.Now = w.Clock.Now
		p := f.Provider(redirect)
		if tweak != nil {
			tweak(&p)
		}
		fakes[kind] = f
		ps = append(ps, p)
	}
	m, err := oidc.New(w.Svc.Service, oidc.Rules{Providers: ps, HTTPClient: fakes[kinds[0]].Client})
	if err != nil {
		t.Fatal(err)
	}
	return w, m, fakes
}

// begin runs Begin for a sign-in through the named provider in its own transaction.
func begin(w *kittest.World, m *oidc.Module, name string) oidc.Redirect {
	w.T.Helper()
	var r oidc.Redirect
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		r, err = m.Begin(w.Ctx, q, name, aud, authkit.Meta{})
		return err
	})
	if err != nil {
		w.T.Fatal(err)
	}
	return r
}

func queryOf(r oidc.Redirect) url.Values {
	u, _ := url.Parse(r.URL)
	return u.Query()
}

func sha(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// nothing asserts that sub has no identity, no session and no sign-up ticket.
func nothing(w *kittest.World, sub string) {
	w.T.Helper()
	if n := w.Count("SELECT count(*) FROM auth_identities WHERE subject = $1", sub); n != 0 {
		w.T.Errorf("identities for %s = %d, want 0", sub, n)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions"); n != 0 {
		w.T.Errorf("sessions = %d, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'signup'"); n != 0 {
		w.T.Errorf("sign-up tickets = %d, want 0", n)
	}
}

// bad counts the oidc events recorded as bad_identity.
func bad(w *kittest.World) int {
	return w.Count("SELECT count(*) FROM auth_events WHERE result = 'bad_identity' AND source = 'oidc'")
}

// finish runs Finish in its own transaction and commits it.
func finish(w *kittest.World, m *oidc.Module, cb oidc.Callback, binding string) (authkit.Result, *oidc.SignUp) {
	w.T.Helper()
	var res authkit.Result
	var sup *oidc.SignUp
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		res, sup, err = m.Finish(w.Ctx, q, cb, binding, authkit.Meta{})
		return err
	})
	if err != nil {
		w.T.Fatal(err)
	}
	return res, sup
}

// postedCallback sends cb as the form POST that Apple makes and reads it back with ParseCallback.
func postedCallback(w *kittest.World, cb oidc.Callback) oidc.Callback {
	w.T.Helper()
	form := url.Values{"state": {cb.State}, "code": {cb.Code}}
	if cb.User != "" {
		form.Set("user", cb.User)
	}
	r := httptest.NewRequest(http.MethodPost, redirect, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got, err := oidc.ParseCallback(r)
	if err != nil {
		w.T.Fatal(err)
	}
	return got
}

func nameOf(k oidcfake.Kind) string {
	if k == oidcfake.Apple {
		return "apple"
	}
	return "google"
}

// seedIdentity links subject at provider to principal, as an earlier sign-in would have.
func seedIdentity(w *kittest.World, principal uuid.UUID, provider, subject, email string) {
	w.D.Exec(w.T, "INSERT INTO auth_identities (id, principal_id, provider, subject, email, created_at) VALUES ($1,$2,$3,$4,$5,$6)", uuid.New(), principal, provider, subject, email, w.Clock.Now())
}

// seedTOTP enrolls a confirmed TOTP factor for principal, so a password sign-in needs a second step.
func seedTOTP(w *kittest.World, principal uuid.UUID) {
	w.D.Exec(w.T, "INSERT INTO auth_second_factors (principal_id, kind, secret, created_at, confirmed_at) VALUES ($1, 'totp', '\x01'::bytea, $2, $2)", principal, w.Clock.Now())
}

// stepVerifier stands in for the second-step verifier, which a sign-in that needs a second step must have.
type stepVerifier struct{}

func (stepVerifier) Verify(context.Context, db.Querier, uuid.UUID, authkit.FactorKind, string) (bool, error) {
	return false, nil
}

func (stepVerifier) RecoveryCodesLeft(context.Context, db.Querier, uuid.UUID) (int, error) {
	return 0, nil
}

func (stepVerifier) SendCode(context.Context, db.Querier, uuid.UUID) (authkit.EmailCodeRequest, time.Duration, error) {
	return authkit.EmailCodeRequest{}, 0, nil
}

func (stepVerifier) ChallengeRules() (time.Duration, int) {
	return 5 * time.Minute, 2
}

// attachVerifier gives the world's Service a second-step verifier.
// WHY: kittest attaches second factors with no Key, so the core has no verifier and a second step fails closed.
func attachVerifier(w *kittest.World) {
	w.T.Helper()
	c, err := w.Svc.Attach("fakefactor")
	if err != nil {
		w.T.Fatal(err)
	}
	if err := c.SetVerifier(stepVerifier{}); err != nil {
		w.T.Fatal(err)
	}
}
