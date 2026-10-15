package oidc_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
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

// spent reports whether the ceremony for state has been spent.
func spent(w *kittest.World, state string) bool {
	return w.Count("SELECT count(*) FROM auth_ceremonies WHERE state_hash = $1 AND spent_at IS NOT NULL", sha(state)) == 1
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestFinishBadToken(t *testing.T) {
	forged, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name string
		hook func(f *oidcfake.Server, now time.Time)
		want error
	}{
		{"valid token, new identity", nil, oidc.ErrIdentityUnknown},
		{"iss", func(f *oidcfake.Server, _ time.Time) {
			f.Tamper(func(_, c map[string]any) { c["iss"] = "https://evil.example" })
		}, authkit.ErrInvalidCredentials},
		{"aud", func(f *oidcfake.Server, _ time.Time) {
			f.Tamper(func(_, c map[string]any) { c["aud"] = "other" })
		}, authkit.ErrInvalidCredentials},
		{"azp", func(f *oidcfake.Server, _ time.Time) {
			f.Tamper(func(_, c map[string]any) { c["azp"] = "other" })
		}, authkit.ErrInvalidCredentials},
		{"multi-audience without azp", func(f *oidcfake.Server, _ time.Time) {
			f.Tamper(func(_, c map[string]any) {
				c["aud"] = []string{f.ClientID, "other"}
				delete(c, "azp")
			})
		}, authkit.ErrInvalidCredentials},
		{"nonce", func(f *oidcfake.Server, _ time.Time) {
			f.Tamper(func(_, c map[string]any) { c["nonce"] = "x" })
		}, authkit.ErrInvalidCredentials},
		{"nonce missing", func(f *oidcfake.Server, _ time.Time) {
			f.Tamper(func(_, c map[string]any) { delete(c, "nonce") })
		}, authkit.ErrInvalidCredentials},
		{"iat in the future", func(f *oidcfake.Server, now time.Time) {
			f.Tamper(func(_, c map[string]any) { c["iat"] = now.Add(6 * time.Minute).Unix() })
		}, authkit.ErrInvalidCredentials},
		{"expired", func(f *oidcfake.Server, now time.Time) {
			f.Tamper(func(_, c map[string]any) {
				c["exp"] = now.Add(-10 * time.Minute).Unix()
				c["iat"] = now.Add(-70 * time.Minute).Unix()
			})
		}, authkit.ErrInvalidCredentials},
		{"HS256", func(f *oidcfake.Server, _ time.Time) { f.SignNextWith(nil, "HS256") }, authkit.ErrInvalidCredentials},
		{"alg none", func(f *oidcfake.Server, _ time.Time) { f.SignNextWith(nil, "none") }, authkit.ErrInvalidCredentials},
		{"unknown kid", func(f *oidcfake.Server, _ time.Time) {
			f.Tamper(func(h, _ map[string]any) { h["kid"] = "nope" })
		}, authkit.ErrInvalidCredentials},
		{"signed by another key", func(f *oidcfake.Server, _ time.Time) { f.SignNextWith(forged, "RS256") }, authkit.ErrInvalidCredentials},
		{"empty subject", func(f *oidcfake.Server, _ time.Time) {
			f.Tamper(func(_, c map[string]any) { c["sub"] = "" })
		}, authkit.ErrInvalidCredentials},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w, m, fakes := newWorld(t, nil, oidcfake.Google)
			f := fakes[oidcfake.Google]
			if r.hook != nil {
				r.hook(f, w.Clock.Now())
			}
			rd := begin(w, m, "google")
			cb := f.Authorize(t, rd, oidcfake.User{Subject: "s-1", Email: "new@example.test", EmailVerified: true})
			res, sup := finish(w, m, cb, rd.Binding)
			if res.Refusal != r.want {
				t.Fatalf("Refusal = %v, want %v", res.Refusal, r.want)
			}
			if r.want != authkit.ErrInvalidCredentials {
				return
			}
			if sup != nil {
				t.Error("a refused token returned a sign-up ticket")
			}
			if n := bad(w); n != 1 {
				t.Errorf("bad_identity events = %d, want 1", n)
			}
			nothing(w, "s-1")
		})
	}
}

func TestFinishPostWrongBinding(t *testing.T) {
	rows := []struct {
		name    string
		kind    oidcfake.Kind
		post    bool
		binding string
	}{
		{"Google GET", oidcfake.Google, false, "x"},
		{"Apple POST", oidcfake.Apple, true, "x"},
		{"Apple POST, empty binding", oidcfake.Apple, true, ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w, m, fakes := newWorld(t, nil, r.kind)
			f := fakes[r.kind]
			rd := begin(w, m, nameOf(r.kind))
			cb := f.Authorize(t, rd, oidcfake.User{Subject: "s-1", Email: "new@example.test", EmailVerified: true})
			if r.post {
				cb = postedCallback(w, cb)
			}
			res, _ := finish(w, m, cb, r.binding)
			if res.Refusal != authkit.ErrInvalidCredentials {
				t.Fatalf("Refusal = %v, want ErrInvalidCredentials", res.Refusal)
			}
			if n := f.Exchanges(); n != 0 {
				t.Errorf("token exchanges = %d, want 0", n)
			}
			if !spent(w, cb.State) {
				t.Error("the ceremony is not spent after a wrong binding")
			}
			if n := bad(w); n != 1 {
				t.Errorf("bad_identity events = %d, want 1", n)
			}
			nothing(w, "s-1")
			res, _ = finish(w, m, cb, rd.Binding)
			if res.Refusal != authkit.ErrInvalidCredentials {
				t.Errorf("retry with the right binding: Refusal = %v, want ErrInvalidCredentials", res.Refusal)
			}
			if n := f.Exchanges(); n != 0 {
				t.Errorf("token exchanges after retry = %d, want 0", n)
			}
		})
	}
}

func TestFinishReplay(t *testing.T) {
	w, m, fakes := newWorld(t, nil, oidcfake.Google)
	f := fakes[oidcfake.Google]
	ann := w.User("ann@example.test", "pw")
	seedIdentity(w, ann, "google", "s-1", "ann@example.test")
	rd := begin(w, m, "google")
	cb := f.Authorize(t, rd, oidcfake.User{Subject: "s-1", Email: "ann@example.test", EmailVerified: true})
	res, _ := finish(w, m, cb, rd.Binding)
	if res.Session == nil {
		t.Fatal("first Finish opened no session")
	}
	res, _ = finish(w, m, cb, rd.Binding)
	if res.Refusal != authkit.ErrInvalidCredentials {
		t.Errorf("replayed callback: Refusal = %v, want ErrInvalidCredentials", res.Refusal)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", ann); n != 1 {
		t.Errorf("sessions for ann = %d, want 1", n)
	}
	if n := f.Exchanges(); n != 1 {
		t.Errorf("token exchanges = %d, want 1", n)
	}
	if n := bad(w); n != 1 {
		t.Errorf("bad_identity events = %d, want 1", n)
	}
}

func TestFinishCeremonyExpired(t *testing.T) {
	w, m, fakes := newWorld(t, nil, oidcfake.Google)
	f := fakes[oidcfake.Google]
	ann := w.User("ann@example.test", "pw")
	seedIdentity(w, ann, "google", "s-1", "ann@example.test")
	rd := begin(w, m, "google")
	w.Clock.Advance(11 * time.Minute)
	cb := f.Authorize(t, rd, oidcfake.User{Subject: "s-1", Email: "ann@example.test", EmailVerified: true})
	res, _ := finish(w, m, cb, rd.Binding)
	if res.Refusal != authkit.ErrInvalidCredentials {
		t.Errorf("Refusal = %v, want ErrInvalidCredentials", res.Refusal)
	}
	if n := f.Exchanges(); n != 0 {
		t.Errorf("token exchanges = %d, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions"); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
}

func TestFinishCancelled(t *testing.T) {
	rows := []struct {
		name    string
		kind    oidcfake.Kind
		errCode string
		wrong   bool
		want    error
	}{
		{"Apple user_cancelled_authorize", oidcfake.Apple, "user_cancelled_authorize", false, oidc.ErrCancelled},
		{"Google access_denied", oidcfake.Google, "access_denied", false, oidc.ErrCancelled},
		{"Google server_error", oidcfake.Google, "server_error", false, authkit.ErrInvalidCredentials},
		{"Google access_denied with a wrong binding", oidcfake.Google, "access_denied", true, authkit.ErrInvalidCredentials},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w, m, fakes := newWorld(t, nil, r.kind)
			f := fakes[r.kind]
			rd := begin(w, m, nameOf(r.kind))
			binding := rd.Binding
			if r.wrong {
				binding = "x"
			}
			cb := oidc.Callback{State: queryOf(rd).Get("state"), Error: r.errCode}
			res, _ := finish(w, m, cb, binding)
			if res.Refusal != r.want {
				t.Fatalf("Refusal = %v, want %v", res.Refusal, r.want)
			}
			if n := f.Exchanges(); n != 0 {
				t.Errorf("token exchanges = %d, want 0", n)
			}
			if r.want == oidc.ErrCancelled {
				if !spent(w, cb.State) {
					t.Error("the ceremony of a cancelled sign-in is not spent")
				}
				if n := bad(w); n != 0 {
					t.Errorf("bad_identity events = %d, want 0", n)
				}
				if n := w.Count("SELECT count(*) FROM auth_events WHERE source = 'oidc'"); n != 0 {
					t.Errorf("oidc events = %d, want 0", n)
				}
				return
			}
			if n := bad(w); n != 1 {
				t.Errorf("bad_identity events = %d, want 1", n)
			}
		})
	}
}

func TestFinishAppleUnverified(t *testing.T) {
	rows := []struct {
		name     string
		kind     oidcfake.Kind
		verified any
	}{
		{"Apple false", oidcfake.Apple, "false"},
		{"Google false", oidcfake.Google, "false"},
		{"Google missing", oidcfake.Google, nil},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w, m, fakes := newWorld(t, nil, r.kind)
			f := fakes[r.kind]
			rd := begin(w, m, nameOf(r.kind))
			cb := f.Authorize(t, rd, oidcfake.User{Subject: "s-9", Email: "relay@privaterelay.example.test", EmailVerified: r.verified})
			res, sup := finish(w, m, cb, rd.Binding)
			if res.Refusal != oidc.ErrEmailUnverified {
				t.Fatalf("Refusal = %v, want ErrEmailUnverified", res.Refusal)
			}
			if sup != nil {
				t.Error("an unverified email returned a sign-up ticket")
			}
			nothing(w, "s-9")
			if n := bad(w); n != 0 {
				t.Errorf("bad_identity events = %d, want 0", n)
			}
		})
	}
}

func TestFinishUserFieldNameOnly(t *testing.T) {
	rows := []struct {
		name                    string
		form                    string
		given, family, fullName string
	}{
		{"name in the user field", `{"name":{"firstName":"Ann","lastName":"Lee"},"email":"evil@example.test"}`, "Ann", "Lee", "Ann Lee"},
		{"user field is not JSON", "not json", "", "", ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w, m, fakes := newWorld(t, nil, oidcfake.Apple)
			f := fakes[oidcfake.Apple]
			rd := begin(w, m, "apple")
			cb := f.Authorize(t, rd, oidcfake.User{Subject: "s-a", Email: "ann@relay.example.test", EmailVerified: "true", PrivateEmail: true, FormUser: r.form})
			res, sup := finish(w, m, cb, rd.Binding)
			if res.Refusal != oidc.ErrIdentityUnknown {
				t.Fatalf("Refusal = %v, want ErrIdentityUnknown", res.Refusal)
			}
			if sup == nil {
				t.Fatal("no sign-up ticket")
			}
			if sup.Email != "ann@relay.example.test" || sup.Provider != "apple" || !sup.PrivateEmail {
				t.Errorf("sign-up = %+v, want the relay email, provider apple, private", *sup)
			}
			if sup.GivenName != r.given || sup.FamilyName != r.family || sup.Name != r.fullName {
				t.Errorf("names = %q %q %q, want %q %q %q", sup.Name, sup.GivenName, sup.FamilyName, r.fullName, r.given, r.family)
			}
			if n := w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'signup' AND state_hash = $1 AND email = $2 AND subject = $3 AND profile->>'given_name' = $4 AND expires_at = $5",
				sha(sup.Ticket), "ann@relay.example.test", "s-a", sup.GivenName, w.Clock.Now().Add(10*time.Minute)); n != 1 {
				t.Errorf("sign-up rows = %d, want 1", n)
			}
			if n := w.Count("SELECT count(*) FROM auth_identities WHERE subject = 's-a'"); n != 0 {
				t.Errorf("identities = %d, want 0", n)
			}
			if n := w.Count("SELECT count(*) FROM auth_sessions"); n != 0 {
				t.Errorf("sessions = %d, want 0", n)
			}
		})
	}
}

func TestFinishSignInSkipsGate(t *testing.T) {
	rows := []struct {
		name  string
		tweak func(*oidc.Provider)
		skip  bool
	}{
		{"skip", nil, true},
		{"gate", func(p *oidc.Provider) { p.SkipSecondFactor = false }, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w, m, fakes := newWorld(t, r.tweak, oidcfake.Google)
			if !r.skip {
				attachVerifier(w)
			}
			f := fakes[oidcfake.Google]
			ann := w.User("ann@example.test", "pw")
			seedTOTP(w, ann)
			seedIdentity(w, ann, "google", "s-1", "ann@example.test")
			rd := begin(w, m, "google")
			cb := f.Authorize(t, rd, oidcfake.User{Subject: "s-1", Email: "ann@example.test", EmailVerified: true})
			res, _ := finish(w, m, cb, rd.Binding)
			if r.skip {
				if res.Session == nil || res.SecondStep != nil {
					t.Fatalf("Session = %v, SecondStep = %v; want a session and no second step", res.Session != nil, res.SecondStep != nil)
				}
				if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND second_factor = 'oidc'", ann); n != 1 {
					t.Errorf("oidc sessions for ann = %d, want 1", n)
				}
				if n := w.Count("SELECT count(*) FROM auth_identities WHERE subject = 's-1' AND last_used_at = $1", w.Clock.Now()); n != 1 {
					t.Errorf("identity last_used_at not set to now")
				}
				return
			}
			if res.SecondStep == nil || res.Session != nil {
				t.Fatalf("Refusal = %v, Session = %v, SecondStep = %v; want a second step and no session", res.Refusal, res.Session != nil, res.SecondStep != nil)
			}
			if n := w.Count("SELECT count(*) FROM auth_sessions"); n != 0 {
				t.Errorf("sessions = %d, want 0", n)
			}
		})
	}
}

func TestFinishEmailMatchRefused(t *testing.T) {
	rows := []struct {
		name  string
		email string
	}{
		{"same email", "ann@example.test"},
		{"email in another case", "Ann@Example.TEST"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w, m, fakes := newWorld(t, nil, oidcfake.Google)
			f := fakes[oidcfake.Google]
			w.User("ann@example.test", "pw")
			rd := begin(w, m, "google")
			cb := f.Authorize(t, rd, oidcfake.User{Subject: "s-2", Email: r.email, EmailVerified: true})
			res, sup := finish(w, m, cb, rd.Binding)
			if res.Refusal != oidc.ErrSignInToLink {
				t.Fatalf("Refusal = %v, want ErrSignInToLink", res.Refusal)
			}
			if sup != nil {
				t.Error("a matching email returned a sign-up ticket")
			}
			nothing(w, "s-2")
		})
	}
}

func TestFinishNoSecretInErrors(t *testing.T) {
	secret, code := randomHex(t), randomHex(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/token" {
			_, _ = rw.Write([]byte(`{"keys":[]}`))
			return
		}
		_ = r.ParseForm()
		body, _ := json.Marshal(map[string]string{
			"error":             "invalid_grant",
			"error_description": r.PostForm.Get("client_secret") + " " + r.PostForm.Get("code"),
		})
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write(body)
	}))
	t.Cleanup(srv.Close)

	w := kittest.New(t)
	p := oidc.Google("cid", secret, redirect)
	p.Issuers = []string{srv.URL}
	p.AuthURL = srv.URL + "/auth"
	p.TokenURL = srv.URL + "/token"
	p.JWKSURL = srv.URL + "/jwks"
	m, err := oidc.New(w.Svc.Service, oidc.Rules{Providers: []oidc.Provider{p}, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	prev := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	rd := begin(w, m, "google")
	state, nonce := queryOf(rd).Get("state"), queryOf(rd).Get("nonce")
	cb := oidc.Callback{State: state, Code: code}
	var res authkit.Result
	var ferr error
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		res, _, ferr = m.Finish(w.Ctx, q, cb, rd.Binding, authkit.Meta{})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ferr != nil {
		t.Fatal("Finish returned an error for a refused exchange")
	}
	if res.Refusal != authkit.ErrInvalidCredentials {
		t.Fatalf("Refusal = %v, want ErrInvalidCredentials", res.Refusal)
	}

	var events string
	if err := w.D.Row(w.T, "SELECT coalesce(string_agg(e::text, ' '), '') FROM auth_events e").Scan(&events); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("%v %+v", ferr, res)
	for _, s := range []struct{ name, value string }{
		{"client secret", secret}, {"code", code}, {"state", state}, {"nonce", nonce}, {"binding", rd.Binding},
	} {
		for where, got := range map[string]string{"the error or result": text, "the log": logs.String(), "the events": events} {
			if strings.Contains(got, s.value) {
				t.Errorf("the %s reached %s", s.name, where)
			}
		}
	}
}
