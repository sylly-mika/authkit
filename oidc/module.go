package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// Rules configures the oidc module. Zero durations and a nil HTTPClient take their defaults.
type Rules struct {
	// Providers are the sign-in providers, reported by Providers in this order.
	Providers []Provider
	// CeremonyTTL is how long a Begin can be finished; Skew is the clock skew tolerated on iat; Reauth is the re-authentication window, zero meaning Config.Recent.
	CeremonyTTL, Skew, Reauth time.Duration
	// HTTPClient carries token exchanges and key fetches.
	HTTPClient *http.Client
}

// SignUp is a first sign-in whose identity no account holds. Ticket is the one-time token that redeems it; the store keeps only its hash.
type SignUp struct {
	Ticket, Provider, Email     string
	Name, GivenName, FamilyName string
	PrivateEmail                bool
}

var (
	ErrCancelled       = errors.New("oidc: the user cancelled at the provider")
	ErrEmailUnverified = errors.New("oidc: the provider has not verified the email")
	ErrSignInToLink    = errors.New("oidc: sign in to the existing account, then link")
	ErrIdentityUnknown = errors.New("oidc: no account holds this identity")
	ErrIdentityTaken   = errors.New("oidc: the identity is linked already")
	ErrLastCredential  = errors.New("oidc: the account would have no way to sign in")
	ErrNotLinked       = errors.New("oidc: the provider is not linked")
	ErrTicketUnknown   = errors.New("oidc: the sign-up ticket is unknown or ended")
	ErrUnknownProvider = errors.New("oidc: no such provider")
)

// Module is OpenID Connect sign-in on one Service.
type Module struct {
	core      *authkit.Core
	rules     Rules
	client    *http.Client
	names     []string
	providers map[string]*provider
}

type provider struct {
	Provider
	keys *gooidc.RemoteKeySet
}

var providerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// New attaches the oidc module to svc. It refuses a provider whose endpoints are not https or whose client is incomplete, and answers authkit.ErrAttached when svc already has the module; a refused New attaches nothing.
func New(svc *authkit.Service, r Rules) (*Module, error) {
	inherit := r.Reauth == 0
	r = withDefaults(r)
	if err := checkRules(r); err != nil {
		return nil, err
	}
	m := &Module{rules: r, client: r.HTTPClient, providers: make(map[string]*provider, len(r.Providers))}
	ctx := gooidc.ClientContext(context.Background(), r.HTTPClient)
	for _, p := range r.Providers {
		m.names = append(m.names, p.Name)
		m.providers[p.Name] = &provider{Provider: p, keys: gooidc.NewRemoteKeySet(ctx, p.JWKSURL)}
	}
	core, err := svc.Attach("oidc")
	if err != nil {
		return nil, err
	}
	m.core = core
	if inherit {
		m.rules.Reauth = core.Config().Recent
	}
	return m, nil
}

func withDefaults(r Rules) Rules {
	if r.CeremonyTTL == 0 {
		r.CeremonyTTL = 10 * time.Minute
	}
	if r.Skew == 0 {
		r.Skew = 5 * time.Minute
	}
	if r.Reauth == 0 {
		r.Reauth = 5 * time.Minute
	}
	if r.HTTPClient == nil {
		r.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return r
}

func checkRules(r Rules) error {
	if len(r.Providers) == 0 {
		return errors.New("oidc: no provider")
	}
	seen := make(map[string]bool, len(r.Providers))
	for _, p := range r.Providers {
		if !providerName.MatchString(p.Name) {
			return fmt.Errorf("oidc: provider name %q is not valid", p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("oidc: provider %q is configured twice", p.Name)
		}
		seen[p.Name] = true
		if p.ClientID == "" {
			return fmt.Errorf("oidc: provider %q has no client id", p.Name)
		}
		if len(p.Issuers) == 0 {
			return fmt.Errorf("oidc: provider %q has no issuer", p.Name)
		}
		if !httpsURL(p.AuthURL) {
			return fmt.Errorf("oidc: provider %q: AuthURL is not https", p.Name)
		}
		if !httpsURL(p.TokenURL) {
			return fmt.Errorf("oidc: provider %q: TokenURL is not https", p.Name)
		}
		if !httpsURL(p.JWKSURL) {
			return fmt.Errorf("oidc: provider %q: JWKSURL is not https", p.Name)
		}
		if !redirectURLOK(p.RedirectURL) {
			return fmt.Errorf("oidc: provider %q: RedirectURL is not https", p.Name)
		}
		if p.ClientSecret == "" && p.Secret == nil {
			return fmt.Errorf("oidc: provider %q has no client secret", p.Name)
		}
		if p.AuthStyle == 0 {
			return fmt.Errorf("oidc: provider %q has no AuthStyle", p.Name)
		}
		if p.SameSite == 0 {
			return fmt.Errorf("oidc: provider %q has no SameSite", p.Name)
		}
	}
	if r.CeremonyTTL < 0 || r.Skew < 0 || r.Reauth < 0 {
		return errors.New("oidc: negative duration")
	}
	return nil
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func redirectURLOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	}
	return false
}

// Providers returns the names of the configured providers, in Rules order.
func (m *Module) Providers() []string { return slices.Clone(m.names) }

// Begin starts a sign-in through the named provider. It stores a ceremony that Finish accepts once, and returns the redirect that sends the browser to the provider.
func (m *Module) Begin(ctx context.Context, q db.Querier, provider string, aud authkit.Audience, meta authkit.Meta) (Redirect, error) {
	return m.begin(ctx, q, "signin", provider, aud, nil)
}

func (m *Module) begin(ctx context.Context, q db.Querier, kind, provider string, aud authkit.Audience, principal *uuid.UUID, extra ...oauth2.AuthCodeOption) (Redirect, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Redirect{}, err
	}
	p, ok := m.providers[provider]
	if !ok {
		return Redirect{}, ErrUnknownProvider
	}
	rand := m.core.Rand()
	state, err := randomToken(rand)
	if err != nil {
		return Redirect{}, err
	}
	binding, err := randomToken(rand)
	if err != nil {
		return Redirect{}, err
	}
	nonce, err := randomToken(rand)
	if err != nil {
		return Redirect{}, err
	}
	verifier, err := randomToken(rand)
	if err != nil {
		return Redirect{}, err
	}
	id, err := uuid.NewRandomFromReader(rand)
	if err != nil {
		return Redirect{}, err
	}
	c := ceremony{id: id, kind: kind, provider: provider, audience: aud, bindingHash: digest(binding), nonceHash: digest(nonce), verifier: verifier}
	if principal != nil {
		c.principal = uuid.NullUUID{UUID: *principal, Valid: true}
	}
	now := m.core.Now()
	if err := insertCeremony(ctx, q, c, digest(state), now, now.Add(m.rules.CeremonyTTL)); err != nil {
		return Redirect{}, err
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)}
	if p.FormPost {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	opts = append(opts, extra...)
	return Redirect{URL: p.config().AuthCodeURL(state, opts...), Binding: binding, SameSite: p.SameSite}, nil
}

func (p *provider) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:    p.ClientID,
		RedirectURL: p.RedirectURL,
		Scopes:      p.Scopes,
		Endpoint:    oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL, AuthStyle: p.AuthStyle},
	}
}

func randomToken(r io.Reader) (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
