// Package oidc signs users in with OpenID Connect providers, such as Google and Apple, by redirect.
package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const (
	appleAudience  = "https://appleid.apple.com"
	appleSecretTTL = 5 * time.Minute
)

// Provider is one OpenID Connect provider: static endpoints and the client registered there.
type Provider struct {
	// Name identifies the provider in routes and stored identities.
	Name string
	// Issuers are the accepted iss values of its ID tokens.
	Issuers []string
	// AuthURL, TokenURL and JWKSURL are the provider's endpoints; nothing is discovered at startup.
	AuthURL, TokenURL, JWKSURL string
	// ClientID and ClientSecret identify the client at the provider.
	ClientID, ClientSecret string
	// RedirectURL is the app's callback URL as registered at the provider.
	RedirectURL string
	// Scopes are requested at the authorize endpoint.
	Scopes []string
	// SkipSecondFactor lets a sign-in through this provider skip the second-factor gate, as a passkey does.
	SkipSecondFactor bool
	// Secret returns the client secret for one token request; nil uses ClientSecret.
	Secret func(now time.Time) (string, error)
	// AuthStyle is how the client authenticates at TokenURL.
	AuthStyle oauth2.AuthStyle
	// FormPost asks for response_mode=form_post, so the callback is a POST.
	FormPost bool
	// SameSite is the binding cookie's SameSite attribute.
	SameSite http.SameSite
}

// Google returns the Google provider for a web client registered in Google Cloud.
func Google(clientID, secret, redirectURL string) Provider {
	return Provider{
		Name:             "google",
		Issuers:          []string{"https://accounts.google.com", "accounts.google.com"},
		AuthURL:          "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:         "https://oauth2.googleapis.com/token",
		JWKSURL:          "https://www.googleapis.com/oauth2/v3/certs",
		ClientID:         clientID,
		ClientSecret:     secret,
		RedirectURL:      redirectURL,
		Scopes:           []string{"openid", "email", "profile"},
		SkipSecondFactor: true,
		AuthStyle:        oauth2.AuthStyleInParams,
		SameSite:         http.SameSiteLaxMode,
	}
}

// Apple returns the Sign in with Apple provider; p8 is the PEM key file from the developer account.
func Apple(teamID, keyID, servicesID string, p8 []byte, redirectURL string) (Provider, error) {
	if teamID == "" || keyID == "" || servicesID == "" {
		return Provider{}, errors.New("oidc: Apple needs the team ID, the key ID and the services ID")
	}
	block, _ := pem.Decode(p8)
	if block == nil {
		return Provider{}, errors.New("oidc: the Apple key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Provider{}, errors.New("oidc: the Apple key is not a PKCS #8 private key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return Provider{}, errors.New("oidc: the Apple key is not an ECDSA P-256 key")
	}
	return Provider{
		Name:             "apple",
		Issuers:          []string{"https://appleid.apple.com"},
		AuthURL:          "https://appleid.apple.com/auth/authorize",
		TokenURL:         "https://appleid.apple.com/auth/token",
		JWKSURL:          "https://appleid.apple.com/auth/keys",
		ClientID:         servicesID,
		RedirectURL:      redirectURL,
		Scopes:           []string{"openid", "email", "name"},
		SkipSecondFactor: true,
		Secret: func(now time.Time) (string, error) {
			s, err := appleSecret(key, teamID, keyID, servicesID, now)
			if err != nil {
				return "", fmt.Errorf("oidc: signing the Apple client secret: %w", err)
			}
			return s, nil
		},
		AuthStyle: oauth2.AuthStyleInParams,
		FormPost:  true,
		SameSite:  http.SameSiteNoneMode,
	}, nil
}

type appleClaims struct {
	Iss string `json:"iss"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Aud string `json:"aud"`
	Sub string `json:"sub"`
}

func appleSecret(key *ecdsa.PrivateKey, teamID, keyID, servicesID string, now time.Time) (string, error) {
	payload, err := json.Marshal(appleClaims{
		Iss: teamID,
		Iat: now.Unix(),
		Exp: now.Add(appleSecretTTL).Unix(),
		Aud: appleAudience,
		Sub: servicesID,
	})
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), keyID),
	)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
