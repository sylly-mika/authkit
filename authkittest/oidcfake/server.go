// Package oidcfake is a local Google or Apple for tests: discovery, JWKS, authorize and token endpoints over httptest TLS.
package oidcfake

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sylly-mika/authkit/oidc"
)

// Kind selects the provider a Server plays.
type Kind int

const (
	// Google is Google's endpoints, claims and client authentication.
	Google Kind = iota + 1
	// Apple is Apple's endpoints, claims and client authentication.
	Apple
)

// Server is a local provider: discovery, JWKS, authorize and token endpoints over httptest TLS.
type Server struct {
	// URL is the base URL; also the iss of every ID token.
	URL string
	// Client trusts the server's certificate; set it as oidc.Rules.HTTPClient.
	Client *http.Client
	// ClientID is the client id the server accepts.
	ClientID string
	// Now is the clock for iat, exp and the Apple secret check; nil uses time.Now; set it to the Service's clock.
	Now func() time.Time

	t        testing.TB
	kind     Kind
	srv      *httptest.Server
	rsaKey   *rsa.PrivateKey
	kid      string
	secret   string
	appleKey *ecdsa.PrivateKey
	p8       []byte
	teamID   string
	keyID    string

	mu        sync.Mutex
	redirects map[string]bool
	users     map[string]User
	codes     map[string]*grant
	exchanges int
	tamper    func(header, claims map[string]any)
	signKey   crypto.Signer
	signAlg   string
}

type grant struct {
	nonce, challenge, redirectURI string
	user                          User
	spent                         bool
}

// User is who signs in at the fake provider.
type User struct {
	Subject, Email string
	// EmailVerified and PrivateEmail are true, false, "true" or "false"; nil omits the claim.
	EmailVerified any
	PrivateEmail  any
	GivenName     string
	FamilyName    string
	// FormUser is Apple's unsigned user field, returned in Callback.User when not empty.
	FormUser string
}

type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

type paths struct{ auth, token, jwks string }

func pathsFor(k Kind) paths {
	if k == Apple {
		return paths{auth: "/auth/authorize", token: "/auth/token", jwks: "/auth/keys"}
	}
	return paths{auth: "/o/oauth2/v2/auth", token: "/token", jwks: "/oauth2/v3/certs"}
}

// New starts a server of the given kind and closes it at test cleanup; its keys are generated here.
func New(t testing.TB, kind Kind) *Server {
	t.Helper()
	if kind != Google && kind != Apple {
		t.Fatalf("oidcfake: unknown kind %d", kind)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidcfake: RSA key: %v", err)
	}
	s := &Server{
		t:         t,
		kind:      kind,
		rsaKey:    rsaKey,
		kid:       "oidcfake-rsa-1",
		redirects: map[string]bool{},
		users:     map[string]User{},
		codes:     map[string]*grant{},
	}
	if kind == Google {
		s.ClientID = "oidcfake-client.apps.googleusercontent.com"
		s.secret = randomToken()
	} else {
		s.ClientID = "lv.example.oidcfake"
		s.teamID = "FAKETEAM01"
		s.keyID = "FAKEKEY001"
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("oidcfake: Apple key: %v", err)
		}
		s.appleKey = key
		s.p8, err = pkcs8PEM(key)
		if err != nil {
			t.Fatalf("oidcfake: Apple key: %v", err)
		}
	}
	s.srv = httptest.NewTLSServer(s.routes())
	t.Cleanup(s.srv.Close)
	s.URL = s.srv.URL
	s.Client = s.srv.Client()
	return s
}

// Provider returns Google() or Apple() values with every URL and Issuers on the server, and registers redirectURL.
func (s *Server) Provider(redirectURL string) oidc.Provider {
	s.t.Helper()
	s.mu.Lock()
	s.redirects[redirectURL] = true
	s.mu.Unlock()
	var p oidc.Provider
	if s.kind == Google {
		p = oidc.Google(s.ClientID, s.secret, redirectURL)
	} else {
		var err error
		p, err = oidc.Apple(s.teamID, s.keyID, s.ClientID, s.p8, redirectURL)
		if err != nil {
			s.t.Fatalf("oidcfake: Apple provider: %v", err)
		}
	}
	ep := pathsFor(s.kind)
	p.Issuers = []string{s.URL}
	p.AuthURL = s.URL + ep.auth
	p.TokenURL = s.URL + ep.token
	p.JWKSURL = s.URL + ep.jwks
	return p
}

// Authorize plays the browser at the authorize endpoint and returns the callback the provider sends.
func (s *Server) Authorize(t testing.TB, r oidc.Redirect, u User) oidc.Callback {
	t.Helper()
	if !strings.HasPrefix(r.URL, s.URL+pathsFor(s.kind).auth) {
		t.Fatalf("oidcfake: the redirect is not this server's authorize endpoint")
	}
	parsed, err := url.Parse(r.URL)
	if err != nil {
		t.Fatalf("oidcfake: the redirect URL: %v", err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("oidcfake: the redirect has no state")
	}
	s.mu.Lock()
	s.users[state] = u
	s.mu.Unlock()
	client := *s.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(r.URL)
	if err != nil {
		t.Fatalf("oidcfake: authorize request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		var answer oauthError
		_ = json.NewDecoder(resp.Body).Decode(&answer)
		t.Fatalf("oidcfake: authorize refused: %s", answer.Description)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("oidcfake: the callback URL: %v", err)
	}
	return oidc.Callback{State: location.Query().Get("state"), Code: location.Query().Get("code"), User: u.FormUser}
}

// Exchanges counts token requests, refused ones included.
func (s *Server) Exchanges() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exchanges
}

// Tamper changes the header and claims of the next ID token before it is signed.
func (s *Server) Tamper(fn func(header, claims map[string]any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tamper = fn
}

// SignNextWith signs the next ID token with key and alg: RS256 or ES256 with key; RS384 or PS256 with an RSA key, or nil for the server's published key; none or HS256 with a nil key.
func (s *Server) SignNextWith(key crypto.Signer, alg string) {
	s.t.Helper()
	switch alg {
	case "RS256", "ES256":
		if key == nil {
			s.t.Fatalf("oidcfake: SignNextWith %s: bad key", alg)
		}
	case "RS384", "PS256":
		if key == nil {
			key = s.rsaKey
		}
		if _, ok := key.(*rsa.PrivateKey); !ok {
			s.t.Fatalf("oidcfake: SignNextWith %s: bad key", alg)
		}
	case "none", "HS256":
		if key != nil {
			s.t.Fatalf("oidcfake: SignNextWith %s: bad key", alg)
		}
	default:
		s.t.Fatalf("oidcfake: SignNextWith %s: bad key", alg)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signKey, s.signAlg = key, alg
}

func (s *Server) routes() http.Handler {
	ep := pathsFor(s.kind)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET "+ep.jwks, s.serveJWKS)
	mux.HandleFunc("GET "+ep.auth, s.authorize)
	mux.HandleFunc("POST "+ep.token, s.token)
	return mux
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	ep := pathsFor(s.kind)
	doc := map[string]any{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + ep.auth,
		"token_endpoint":                        s.URL + ep.token,
		"jwks_uri":                              s.URL + ep.jwks,
		"response_types_supported":              []string{"code"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
	}
	if s.kind == Apple {
		doc["scopes_supported"] = []string{"openid", "email", "name"}
		doc["response_modes_supported"] = []string{"query", "fragment", "form_post"}
	}
	s.writeJSON(w, http.StatusOK, doc)
}

func (s *Server) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, s.jwks())
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	name, location := s.issue(r.URL.Query())
	if name != "" {
		s.refuse(w, http.StatusBadRequest, "invalid_request", name)
		return
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Server) issue(q url.Values) (refusal, location string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	redirectURI, state := q.Get("redirect_uri"), q.Get("state")
	switch {
	case q.Get("client_id") != s.ClientID:
		return "client_id", ""
	case !s.redirects[redirectURI]:
		return "redirect_uri", ""
	case q.Get("response_type") != "code":
		return "response_type", ""
	case !slices.Contains(strings.Fields(q.Get("scope")), "openid"):
		return "scope", ""
	case state == "":
		return "state", ""
	case q.Get("nonce") == "":
		return "nonce", ""
	case q.Get("code_challenge") == "":
		return "code_challenge", ""
	case q.Get("code_challenge_method") != "S256":
		return "code_challenge_method", ""
	case (s.kind == Apple && q.Get("response_mode") != "form_post") || (s.kind == Google && q.Has("response_mode")):
		return "response_mode", ""
	}
	u, ok := s.users[state]
	if !ok {
		return "user", ""
	}
	delete(s.users, state)
	code := randomToken()
	s.codes[code] = &grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirectURI: redirectURI, user: u}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return "", redirectURI + sep + url.Values{"code": {code}, "state": {state}}.Encode()
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	form := r.PostForm
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exchanges++
	if r.Header.Get("Authorization") != "" {
		s.refuse(w, http.StatusUnauthorized, "invalid_client", "authorization")
		return
	}
	if form.Get("client_id") != s.ClientID {
		s.refuse(w, http.StatusUnauthorized, "invalid_client", "client_id")
		return
	}
	if !s.clientSecretOK(form.Get("client_secret")) {
		s.refuse(w, http.StatusUnauthorized, "invalid_client", "client_secret")
		return
	}
	if form.Get("grant_type") != "authorization_code" {
		s.refuse(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type")
		return
	}
	g, ok := s.codes[form.Get("code")]
	if !ok || g.spent {
		s.refuse(w, http.StatusBadRequest, "invalid_grant", "code")
		return
	}
	g.spent = true
	if form.Get("redirect_uri") != g.redirectURI {
		s.refuse(w, http.StatusBadRequest, "invalid_grant", "redirect_uri")
		return
	}
	verifier := form.Get("code_verifier")
	if verifier == "" || subtle.ConstantTimeCompare([]byte(pkceChallenge(verifier)), []byte(g.challenge)) != 1 {
		s.refuse(w, http.StatusBadRequest, "invalid_grant", "code_verifier")
		return
	}
	idToken, err := s.idToken(g)
	if err != nil {
		s.t.Errorf("oidcfake: signing the ID token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token": randomToken(),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (s *Server) clientSecretOK(secret string) bool {
	if s.kind == Apple {
		return s.verifyAppleSecret(secret)
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(s.secret)) == 1
}

func (s *Server) idToken(g *grant) (string, error) {
	u := g.user
	now := s.now()
	alg, key := "RS256", crypto.Signer(s.rsaKey)
	if s.signAlg != "" {
		alg, key = s.signAlg, s.signKey
	}
	header := map[string]any{"alg": alg, "kid": s.kid, "typ": "JWT"}
	claims := map[string]any{
		"iss":   s.URL,
		"sub":   u.Subject,
		"aud":   s.ClientID,
		"iat":   now.Unix(),
		"exp":   now.Unix() + 3600,
		"nonce": g.nonce,
	}
	if u.Email != "" {
		claims["email"] = u.Email
	}
	if u.EmailVerified != nil {
		claims["email_verified"] = u.EmailVerified
	}
	if u.PrivateEmail != nil {
		claims["is_private_email"] = u.PrivateEmail
	}
	if s.kind == Google {
		claims["azp"] = s.ClientID
		if u.GivenName != "" {
			claims["given_name"] = u.GivenName
		}
		if u.FamilyName != "" {
			claims["family_name"] = u.FamilyName
		}
		if u.GivenName != "" || u.FamilyName != "" {
			claims["name"] = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
		}
	} else {
		claims["nonce_supported"] = true
	}
	if s.tamper != nil {
		s.tamper(header, claims)
	}
	s.tamper, s.signAlg, s.signKey = nil, "", nil
	return s.sign(header, claims, alg, key)
}

func (s *Server) refuse(w http.ResponseWriter, status int, code, name string) {
	s.writeJSON(w, status, oauthError{Error: code, Description: name})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		s.t.Errorf("oidcfake: encoding an answer: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
