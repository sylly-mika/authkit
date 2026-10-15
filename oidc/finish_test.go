package oidc_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/oidc"
)

func newService(t *testing.T) *authkit.Service {
	t.Helper()
	svc, err := authkit.New(authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// rulesWith returns the rules for one Google provider, edited by tweak when not nil.
func rulesWith(tweak func(*oidc.Provider)) oidc.Rules {
	p := oidc.Google("cid", "sec", redirect)
	if tweak != nil {
		tweak(&p)
	}
	return oidc.Rules{Providers: []oidc.Provider{p}}
}

func TestNewRefuses(t *testing.T) {
	google := oidc.Google("cid", "sec", redirect)
	rows := []struct {
		name string
		r    oidc.Rules
		want string
	}{
		{"no provider", oidc.Rules{}, "oidc: no provider"},
		{"bad name", rulesWith(func(p *oidc.Provider) { p.Name = "Google" }), `oidc: provider name "Google" is not valid`},
		{"duplicate name", oidc.Rules{Providers: []oidc.Provider{google, google}}, `oidc: provider "google" is configured twice`},
		{"no client id", rulesWith(func(p *oidc.Provider) { p.ClientID = "" }), `oidc: provider "google" has no client id`},
		{"no issuer", rulesWith(func(p *oidc.Provider) { p.Issuers = nil }), `oidc: provider "google" has no issuer`},
		{"AuthURL not https", rulesWith(func(p *oidc.Provider) { p.AuthURL = "http://accounts.example.invalid/auth" }), `oidc: provider "google": AuthURL is not https`},
		{"TokenURL not https", rulesWith(func(p *oidc.Provider) { p.TokenURL = "http://oauth.example.invalid/token" }), `oidc: provider "google": TokenURL is not https`},
		{"JWKSURL not https", rulesWith(func(p *oidc.Provider) { p.JWKSURL = "http://keys.example.invalid/certs" }), `oidc: provider "google": JWKSURL is not https`},
		{"RedirectURL not https", rulesWith(func(p *oidc.Provider) { p.RedirectURL = "http://evil.example/cb" }), `oidc: provider "google": RedirectURL is not https`},
		{"no client secret", rulesWith(func(p *oidc.Provider) { p.ClientSecret = "" }), `oidc: provider "google" has no client secret`},
		{"no AuthStyle", rulesWith(func(p *oidc.Provider) { p.AuthStyle = 0 }), `oidc: provider "google" has no AuthStyle`},
		{"no SameSite", rulesWith(func(p *oidc.Provider) { p.SameSite = 0 }), `oidc: provider "google" has no SameSite`},
		{"negative duration", oidc.Rules{Providers: []oidc.Provider{google}, CeremonyTTL: -1}, "oidc: negative duration"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, err := oidc.New(newService(t), row.r)
			if err == nil {
				t.Fatalf("New accepted the rules, want %q", row.want)
			}
			if err.Error() != row.want {
				t.Fatalf("New error = %q, want %q", err.Error(), row.want)
			}
		})
	}
}

func TestNewAccepts(t *testing.T) {
	for _, redirectURL := range []string{"http://localhost:8080/cb", "http://127.0.0.1/cb"} {
		_, err := oidc.New(newService(t), rulesWith(func(p *oidc.Provider) { p.RedirectURL = redirectURL }))
		if err != nil {
			t.Errorf("RedirectURL %s: New = %v, want nil", redirectURL, err)
		}
	}
	svc := newService(t)
	if _, err := oidc.New(svc, oidc.Rules{}); err == nil {
		t.Fatal("New with no provider succeeded")
	}
	if _, err := oidc.New(svc, rulesWith(nil)); err != nil {
		t.Fatalf("New after a refused New = %v, want nil", err)
	}
	if _, err := oidc.New(svc, rulesWith(nil)); err == nil {
		t.Fatal("second New on one Service succeeded")
	}
}

func TestBeginRedirect(t *testing.T) {
	w, m, fakes := newWorld(t, nil, oidcfake.Google, oidcfake.Apple)
	if got := m.Providers(); !slices.Equal(got, []string{"google", "apple"}) {
		t.Fatalf("Providers() = %v, want [google apple]", got)
	}
	rows := []struct {
		name     string
		kind     oidcfake.Kind
		formPost bool
		sameSite http.SameSite
	}{
		{"google", oidcfake.Google, false, http.SameSiteLaxMode},
		{"apple", oidcfake.Apple, true, http.SameSiteNoneMode},
	}
	for _, row := range rows {
		p := fakes[row.kind].Provider(redirect)
		r := begin(w, m, row.name)
		q := queryOf(r)
		state, nonce, challenge := q.Get("state"), q.Get("nonce"), q.Get("code_challenge")
		if !strings.HasPrefix(r.URL, p.AuthURL) {
			t.Errorf("%s: URL %q does not start with %q", row.name, r.URL, p.AuthURL)
		}
		if len(state) != 43 || len(nonce) != 43 || len(challenge) != 43 {
			t.Errorf("%s: state, nonce and code_challenge lengths = %d %d %d, want 43 each", row.name, len(state), len(nonce), len(challenge))
		}
		if q.Get("code_challenge_method") != "S256" {
			t.Errorf("%s: code_challenge_method = %q, want S256", row.name, q.Get("code_challenge_method"))
		}
		if q.Has("response_mode") != row.formPost || (row.formPost && q.Get("response_mode") != "form_post") {
			t.Errorf("%s: response_mode = %q, want form_post only on Apple", row.name, q.Get("response_mode"))
		}
		if len(r.Binding) != 43 || r.Binding == state {
			t.Errorf("%s: binding length %d or equal to state, want 43 and different", row.name, len(r.Binding))
		}
		if r.SameSite != row.sameSite {
			t.Errorf("%s: SameSite = %v, want %v", row.name, r.SameSite, row.sameSite)
		}

		var kind, audience, verifier string
		var bindingHash, nonceHash []byte
		var expires time.Time
		var spent sql.NullTime
		err := w.D.Row(t, "SELECT kind, audience, binding_hash, nonce_hash, verifier, expires_at, spent_at FROM auth_ceremonies WHERE state_hash = $1", sha(state)).
			Scan(&kind, &audience, &bindingHash, &nonceHash, &verifier, &expires, &spent)
		if err != nil {
			t.Fatalf("%s: no ceremony row for the state: %v", row.name, err)
		}
		if kind != "signin" || audience != "staff" {
			t.Errorf("%s: kind, audience = %q, %q; want signin, staff", row.name, kind, audience)
		}
		if !bytes.Equal(bindingHash, sha(r.Binding)) || !bytes.Equal(nonceHash, sha(nonce)) {
			t.Errorf("%s: stored binding or nonce hash does not match the redirect", row.name)
		}
		if base64.RawURLEncoding.EncodeToString(sha(verifier)) != challenge {
			t.Errorf("%s: code_challenge is not the S256 of the stored verifier", row.name)
		}
		if !expires.Equal(w.Clock.Now().Add(10*time.Minute)) || spent.Valid {
			t.Errorf("%s: expires_at = %v (spent %v), want now+10m and unspent", row.name, expires, spent)
		}
	}

	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		_, err := m.Begin(w.Ctx, q, "github", aud, authkit.Meta{})
		return err
	})
	if !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("Begin with an unknown provider = %v, want ErrUnknownProvider", err)
	}
	if n := w.Count("SELECT count(*) FROM auth_ceremonies"); n != 2 {
		t.Errorf("ceremony rows = %d, want 2 (one per Begin)", n)
	}
}
