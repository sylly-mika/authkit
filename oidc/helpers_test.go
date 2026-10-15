package oidc_test

import (
	"crypto/sha256"
	"net/url"
	"testing"

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
