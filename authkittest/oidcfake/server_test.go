package oidcfake

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/sylly-mika/authkit/oidc"
	"golang.org/x/oauth2"
)

const redirect = "https://app.example/oidc/callback"

var at = time.Date(2040, 1, 1, 12, 0, 0, 0, time.UTC)

func newServer(t *testing.T, kind Kind) *Server {
	t.Helper()
	s := New(t, kind)
	s.Now = func() time.Time { return at }
	return s
}

func config(p oidc.Provider) oauth2.Config {
	return oauth2.Config{
		ClientID:    p.ClientID,
		RedirectURL: p.RedirectURL,
		Scopes:      p.Scopes,
		Endpoint:    oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL, AuthStyle: p.AuthStyle},
	}
}

func begin(t *testing.T, s *Server, p oidc.Provider) (oidc.Redirect, string, string) {
	t.Helper()
	state, nonce, verifier := randomToken(), randomToken(), oauth2.GenerateVerifier()
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), gooidc.Nonce(nonce)}
	if p.FormPost {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	cfg := config(p)
	return oidc.Redirect{URL: cfg.AuthCodeURL(state, opts...)}, verifier, nonce
}

func exchange(t *testing.T, s *Server, p oidc.Provider, style oauth2.AuthStyle, code, verifier string) (*oauth2.Token, error) {
	t.Helper()
	cfg := config(p)
	cfg.ClientSecret = p.ClientSecret
	if p.Secret != nil {
		secret, err := p.Secret(at)
		if err != nil {
			t.Fatalf("client secret: %v", err)
		}
		cfg.ClientSecret = secret
	}
	cfg.Endpoint.AuthStyle = style
	var opts []oauth2.AuthCodeOption
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}
	return cfg.Exchange(context.WithValue(context.Background(), oauth2.HTTPClient, s.Client), code, opts...)
}

func verifyToken(s *Server, p oidc.Provider, raw string) error {
	ctx := gooidc.ClientContext(context.Background(), s.Client)
	v := gooidc.NewVerifier(s.URL, gooidc.NewRemoteKeySet(ctx, p.JWKSURL), &gooidc.Config{
		ClientID:             s.ClientID,
		SupportedSigningAlgs: []string{"RS256"},
		Now:                  s.Now,
	})
	_, err := v.Verify(ctx, raw)
	return err
}

func parts(t *testing.T, raw string) (header, claims map[string]any, sig []byte) {
	t.Helper()
	seg := strings.Split(raw, ".")
	if len(seg) != 3 {
		t.Fatalf("the ID token has %d parts, want 3", len(seg))
	}
	dec := func(part string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatalf("the ID token part is not base64url: %v", err)
		}
		return b
	}
	if err := json.Unmarshal(dec(seg[0]), &header); err != nil {
		t.Fatalf("the ID token header: %v", err)
	}
	if err := json.Unmarshal(dec(seg[1]), &claims); err != nil {
		t.Fatalf("the ID token claims: %v", err)
	}
	return header, claims, dec(seg[2])
}

func refused(t *testing.T, err error) (code string, status int, body string) {
	t.Helper()
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		t.Fatalf("the exchange error is %v, want an oauth2 RetrieveError", err)
	}
	return re.ErrorCode, re.Response.StatusCode, string(re.Body)
}

func noEcho(t *testing.T, body string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(body, secret) {
			t.Errorf("the refusal body repeats a secret the client sent")
		}
	}
}

func pathOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the URL %q: %v", raw, err)
	}
	return u.Path
}

func editQuery(t *testing.T, raw string, edit func(url.Values)) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the redirect URL: %v", err)
	}
	q := u.Query()
	edit(q)
	u.RawQuery = q.Encode()
	return u.String()
}

func get(t *testing.T, c *http.Client, target string) (*http.Response, []byte) {
	t.Helper()
	noFollow := *c
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Get(target)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	return resp, body
}

func TestFakeServesDiscoveryAndJWKS(t *testing.T) {
	cases := []struct {
		name string
		kind Kind
		doc  string
	}{
		{"google", Google, "google-discovery.json"},
		{"apple", Apple, "apple-discovery.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t, tc.kind)
			p := s.Provider(redirect)
			ctx := gooidc.ClientContext(context.Background(), s.Client)
			provider, err := gooidc.NewProvider(ctx, s.URL)
			if err != nil {
				t.Fatalf("discovery: %v", err)
			}
			if e := provider.Endpoint(); e.AuthURL != p.AuthURL || e.TokenURL != p.TokenURL {
				t.Errorf("discovered endpoints %s and %s, want the provider's %s and %s", e.AuthURL, e.TokenURL, p.AuthURL, p.TokenURL)
			}
			if !slices.Equal(p.Issuers, []string{s.URL}) {
				t.Errorf("issuers %v, want [%s]", p.Issuers, s.URL)
			}
			raw, err := os.ReadFile(filepath.Join("..", "..", "oidc", "testdata", tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			var recorded struct {
				Auth  string `json:"authorization_endpoint"`
				Token string `json:"token_endpoint"`
				JWKS  string `json:"jwks_uri"`
			}
			if err := json.Unmarshal(raw, &recorded); err != nil {
				t.Fatal(err)
			}
			for _, pair := range [][2]string{{recorded.Auth, p.AuthURL}, {recorded.Token, p.TokenURL}, {recorded.JWKS, p.JWKSURL}} {
				if got, want := pathOf(t, pair[1]), pathOf(t, pair[0]); got != want {
					t.Errorf("endpoint path %s, the recorded document has %s", got, want)
				}
			}

			r, verifier, _ := begin(t, s, p)
			cb := s.Authorize(t, r, User{Subject: "sub-1", Email: "ada@example.invalid", EmailVerified: true})
			tok, err := exchange(t, s, p, p.AuthStyle, cb.Code, verifier)
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			idToken, _ := tok.Extra("id_token").(string)
			if idToken == "" {
				t.Fatal("the token response has no id_token")
			}
			if err := verifyToken(s, p, idToken); err != nil {
				t.Errorf("verifying the ID token: %v", err)
			}
			if n := s.Exchanges(); n != 1 {
				t.Errorf("Exchanges() = %d, want 1", n)
			}
		})
	}
}

func TestFakeIDTokenClaims(t *testing.T) {
	cases := []struct {
		name   string
		kind   Kind
		user   User
		want   map[string]any
		absent []string
	}{
		{
			name: "google",
			kind: Google,
			user: User{Subject: "g-1", Email: "ada@example.invalid", EmailVerified: true, GivenName: "Ada", FamilyName: "Lovelace"},
			want: map[string]any{
				"sub": "g-1", "email": "ada@example.invalid", "email_verified": true,
				"given_name": "Ada", "family_name": "Lovelace", "name": "Ada Lovelace",
			},
			absent: []string{"is_private_email"},
		},
		{
			name: "apple",
			kind: Apple,
			user: User{Subject: "a-1", Email: "x1@privaterelay.appleid.com", EmailVerified: "true", PrivateEmail: "true", FormUser: `{"name":{"firstName":"Ada","lastName":"Lovelace"}}`},
			want: map[string]any{
				"sub": "a-1", "email": "x1@privaterelay.appleid.com", "email_verified": "true",
				"is_private_email": "true", "nonce_supported": true,
			},
			absent: []string{"azp", "name", "given_name", "family_name"},
		},
		{
			name:   "bare",
			kind:   Apple,
			user:   User{Subject: "a-2"},
			want:   map[string]any{"sub": "a-2", "nonce_supported": true},
			absent: []string{"email", "email_verified", "is_private_email"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t, tc.kind)
			p := s.Provider(redirect)
			r, verifier, nonce := begin(t, s, p)
			cb := s.Authorize(t, r, tc.user)
			tok, err := exchange(t, s, p, p.AuthStyle, cb.Code, verifier)
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			idToken, _ := tok.Extra("id_token").(string)
			if err := verifyToken(s, p, idToken); err != nil {
				t.Fatalf("verifying the ID token: %v", err)
			}
			_, claims, _ := parts(t, idToken)

			want := map[string]any{
				"iss":   s.URL,
				"aud":   s.ClientID,
				"nonce": nonce,
				"iat":   float64(at.Unix()),
				"exp":   float64(at.Add(time.Hour).Unix()),
			}
			if tc.kind == Google {
				want["azp"] = s.ClientID
			}
			for k, v := range tc.want {
				want[k] = v
			}
			for k, v := range want {
				if claims[k] != v {
					t.Errorf("claim %s = %v, want %v", k, claims[k], v)
				}
			}
			for _, k := range tc.absent {
				if _, ok := claims[k]; ok {
					t.Errorf("claim %s is present, want none", k)
				}
			}
			if cb.User != tc.user.FormUser {
				t.Errorf("callback user %q, want %q", cb.User, tc.user.FormUser)
			}
		})
	}
}

func TestFakeExchangeChecksPKCE(t *testing.T) {
	s := newServer(t, Google)
	p := s.Provider(redirect)

	r, verifier, _ := begin(t, s, p)
	cb := s.Authorize(t, r, User{Subject: "p-1", Email: "ada@example.invalid", EmailVerified: true})
	wrong := oauth2.GenerateVerifier()
	_, err := exchange(t, s, p, p.AuthStyle, cb.Code, wrong)
	code, status, body := refused(t, err)
	if code != "invalid_grant" || status != http.StatusBadRequest {
		t.Errorf("a wrong verifier: %s %d, want invalid_grant 400", code, status)
	}
	noEcho(t, body, p.ClientSecret, cb.Code, wrong)
	_, err = exchange(t, s, p, p.AuthStyle, cb.Code, verifier)
	if code, _, _ := refused(t, err); code != "invalid_grant" {
		t.Errorf("the right verifier after a refusal: %s, want invalid_grant (the code is spent)", code)
	}

	r, _, _ = begin(t, s, p)
	cb = s.Authorize(t, r, User{Subject: "p-2", Email: "ada@example.invalid", EmailVerified: true})
	_, err = exchange(t, s, p, p.AuthStyle, cb.Code, "")
	if code, _, _ := refused(t, err); code != "invalid_grant" {
		t.Errorf("no verifier: %s, want invalid_grant", code)
	}
	if n := s.Exchanges(); n != 3 {
		t.Errorf("Exchanges() = %d, want 3", n)
	}
}

func TestFakeCodeOnce(t *testing.T) {
	s := newServer(t, Apple)
	p := s.Provider(redirect)
	r, verifier, _ := begin(t, s, p)
	cb := s.Authorize(t, r, User{Subject: "c-1"})

	tok, err := exchange(t, s, p, p.AuthStyle, cb.Code, verifier)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if idToken, _ := tok.Extra("id_token").(string); idToken == "" {
		t.Fatal("the first exchange has no id_token")
	}
	_, err = exchange(t, s, p, p.AuthStyle, cb.Code, verifier)
	if code, status, _ := refused(t, err); code != "invalid_grant" || status != http.StatusBadRequest {
		t.Errorf("a reused code: %s %d, want invalid_grant 400", code, status)
	}

	s.Provider("https://app.example/other")
	r, verifier, _ = begin(t, s, p)
	cb = s.Authorize(t, r, User{Subject: "c-2"})
	changed := p
	changed.RedirectURL = "https://app.example/other"
	_, err = exchange(t, s, changed, changed.AuthStyle, cb.Code, verifier)
	if code, status, _ := refused(t, err); code != "invalid_grant" || status != http.StatusBadRequest {
		t.Errorf("a changed redirect_uri: %s %d, want invalid_grant 400", code, status)
	}
	if n := s.Exchanges(); n != 3 {
		t.Errorf("Exchanges() = %d, want 3", n)
	}
}

func TestFakeAuthorizeChecksRequest(t *testing.T) {
	g := newServer(t, Google)
	gp := g.Provider(redirect)
	a := newServer(t, Apple)
	ap := a.Provider(redirect)
	set := func(k, v string) func(url.Values) { return func(q url.Values) { q.Set(k, v) } }
	del := func(k string) func(url.Values) { return func(q url.Values) { q.Del(k) } }
	cases := []struct {
		name string
		s    *Server
		p    oidc.Provider
		edit func(url.Values)
		want string
	}{
		{"client_id", g, gp, set("client_id", "other"), "client_id"},
		{"redirect_uri", g, gp, set("redirect_uri", "https://evil.example/cb"), "redirect_uri"},
		{"response_type", g, gp, set("response_type", "token"), "response_type"},
		{"scope", g, gp, set("scope", "email"), "scope"},
		{"state", g, gp, del("state"), "state"},
		{"nonce", g, gp, del("nonce"), "nonce"},
		{"code_challenge", g, gp, del("code_challenge"), "code_challenge"},
		{"code_challenge_method", g, gp, set("code_challenge_method", "plain"), "code_challenge_method"},
		{"apple response_mode", a, ap, del("response_mode"), "response_mode"},
		{"google response_mode", g, gp, set("response_mode", "form_post"), "response_mode"},
		{"user", g, gp, nil, "user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			good, _, _ := begin(t, tc.s, tc.p)
			target := good.URL
			if tc.edit != nil {
				target = editQuery(t, good.URL, tc.edit)
			}
			resp, body := get(t, tc.s.Client, target)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", resp.StatusCode)
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Errorf("a refused request has a Location header")
			}
			var answer oauthError
			if err := json.Unmarshal(body, &answer); err != nil {
				t.Fatalf("the refusal is not JSON: %v", err)
			}
			if answer.Error != "invalid_request" || answer.Description != tc.want {
				t.Errorf("refusal %s %s, want invalid_request %s", answer.Error, answer.Description, tc.want)
			}
			if cb := tc.s.Authorize(t, good, User{Subject: "s"}); cb.Code == "" {
				t.Errorf("the good request after the refusal returned no code")
			}
		})
	}
}
