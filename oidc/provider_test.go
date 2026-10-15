package oidc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const (
	teamID     = "TEAM012345"
	keyID      = "KEY0123456"
	servicesID = "lv.example.web"
)

var t0 = time.Unix(1_800_000_000, 0)

func appleP8(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the Apple key: %v", err)
	}
	return key, pemOf(t, key)
}

func pemOf(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// verifySecret checks that s is a compact ES256 JWS signed by pub and returns its header and claims.
func verifySecret(t *testing.T, s string, pub *ecdsa.PublicKey) (jose.Header, map[string]any) {
	t.Helper()
	jws, err := jose.ParseSigned(s, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("the client secret does not parse as a compact ES256 JWS: %v", err)
	}
	if len(jws.Signatures) != 1 {
		t.Fatalf("the client secret has %d signatures, want 1", len(jws.Signatures))
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		t.Fatalf("the client secret does not verify with the Apple key: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("the client secret payload is not a JSON object: %v", err)
	}
	return jws.Signatures[0].Protected, claims
}

func intClaim(t *testing.T, claims map[string]any, key string) int64 {
	t.Helper()
	f, ok := claims[key].(float64)
	if !ok {
		t.Fatalf("the client secret claim %s is missing or not a number", key)
	}
	return int64(f)
}

func TestAppleSecret(t *testing.T) {
	t.Run("claims", func(t *testing.T) {
		priv, p8 := appleP8(t)
		p, err := Apple(teamID, keyID, servicesID, p8, "https://shop.example/apple/cb")
		if err != nil {
			t.Fatalf("Apple: %v", err)
		}
		s, err := p.Secret(t0)
		if err != nil {
			t.Fatalf("Secret: %v", err)
		}
		if n := strings.Count(s, "."); n != 2 {
			t.Fatalf("the client secret has %d dots, want 2", n)
		}
		header, claims := verifySecret(t, s, &priv.PublicKey)
		if header.Algorithm != "ES256" {
			t.Errorf("the client secret algorithm = %q, want ES256", header.Algorithm)
		}
		if header.KeyID != keyID {
			t.Errorf("the client secret kid = %q, want the key ID", header.KeyID)
		}
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating another key: %v", err)
		}
		jws, err := jose.ParseSigned(s, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatalf("parsing the client secret: %v", err)
		}
		if _, err := jws.Verify(&other.PublicKey); err == nil {
			t.Error("the client secret verifies with a key other than the Apple key")
		}
		if len(claims) != 5 {
			t.Errorf("the client secret has %d claims, want 5", len(claims))
		}
		if claims["iss"] != teamID {
			t.Errorf("the client secret iss is not the team ID")
		}
		if claims["sub"] != servicesID {
			t.Errorf("the client secret sub is not the services ID")
		}
		if aud, ok := claims["aud"].(string); !ok || aud != "https://appleid.apple.com" {
			t.Errorf("the client secret aud = %v, want the Apple audience as a string", claims["aud"])
		}
		iat := intClaim(t, claims, "iat")
		if iat != t0.Unix() {
			t.Errorf("the client secret iat = %d, want %d", iat, t0.Unix())
		}
		if exp := intClaim(t, claims, "exp"); exp-iat != 300 {
			t.Errorf("the client secret lifetime = %d seconds, want 300", exp-iat)
		}
	})

	t.Run("fresh", func(t *testing.T) {
		priv, p8 := appleP8(t)
		p, err := Apple(teamID, keyID, servicesID, p8, "https://shop.example/apple/cb")
		if err != nil {
			t.Fatalf("Apple: %v", err)
		}
		s1, err := p.Secret(t0)
		if err != nil {
			t.Fatalf("Secret at t0: %v", err)
		}
		s2, err := p.Secret(t0.Add(time.Second))
		if err != nil {
			t.Fatalf("Secret at t0+1s: %v", err)
		}
		verifySecret(t, s1, &priv.PublicKey)
		_, claims2 := verifySecret(t, s2, &priv.PublicKey)
		if s1 == s2 {
			t.Error("two calls to Secret returned the same client secret")
		}
		if iat := intClaim(t, claims2, "iat"); iat != t0.Unix()+1 {
			t.Errorf("the second client secret iat = %d, want %d", iat, t0.Unix()+1)
		}
		if exp := intClaim(t, claims2, "exp"); exp-intClaim(t, claims2, "iat") != 300 {
			t.Errorf("the second client secret lifetime is not 300 seconds")
		}
	})
}

func TestAppleKeyRefused(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the RSA key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating the Ed25519 key: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the P-384 key: %v", err)
	}
	sec1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the P-256 key: %v", err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(sec1Key)
	if err != nil {
		t.Fatalf("marshalling the SEC 1 key: %v", err)
	}
	_, p8 := appleP8(t)

	const (
		notP256  = "oidc: the Apple key is not an ECDSA P-256 key"
		notPEM   = "oidc: the Apple key is not PEM"
		notPKCS8 = "oidc: the Apple key is not a PKCS #8 private key"
		needsIDs = "oidc: Apple needs the team ID, the key ID and the services ID"
		redirect = "https://shop.example/apple/cb"
		empty    = ""
	)
	cases := []struct {
		name                      string
		teamID, keyID, servicesID string
		p8                        []byte
		want                      string
	}{
		{"rsa", teamID, keyID, servicesID, pemOf(t, rsaKey), notP256},
		{"ed25519", teamID, keyID, servicesID, pemOf(t, edKey), notP256},
		{"p384", teamID, keyID, servicesID, pemOf(t, p384), notP256},
		{"garbage", teamID, keyID, servicesID, []byte("not a key"), notPEM},
		{"baddr", teamID, keyID, servicesID, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}), notPKCS8},
		{"sec1", teamID, keyID, servicesID, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1DER}), notPKCS8},
		{"noteam", empty, keyID, servicesID, p8, needsIDs},
		{"nokey", teamID, empty, servicesID, p8, needsIDs},
		{"noservices", teamID, keyID, empty, p8, needsIDs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Apple(c.teamID, c.keyID, c.servicesID, c.p8, redirect)
			if err == nil {
				t.Fatal("Apple accepted the input, want an error")
			}
			if err.Error() != c.want {
				t.Errorf("Apple error = %q, want %q", err.Error(), c.want)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Error("the Apple error names key material")
			}
			if !reflect.ValueOf(p).IsZero() {
				t.Error("Apple returned a non-zero Provider with its error")
			}
		})
	}
}

type discoveryExtras struct {
	Scopes        []string `json:"scopes_supported"`
	AuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
	ResponseModes []string `json:"response_modes_supported"`
	PKCE          []string `json:"code_challenge_methods_supported"`
}

func readDiscovery(t *testing.T, name string) (gooidc.ProviderConfig, discoveryExtras) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name + "-discovery.json")
	if err != nil {
		t.Fatalf("reading the %s discovery document: %v", name, err)
	}
	var cfg gooidc.ProviderConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("decoding the %s discovery document: %v", name, err)
	}
	var extra discoveryExtras
	if err := json.Unmarshal(raw, &extra); err != nil {
		t.Fatalf("decoding the %s discovery document: %v", name, err)
	}
	return cfg, extra
}

func eq[T comparable](t *testing.T, field string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", field, got, want)
	}
}

func eqList(t *testing.T, field string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}

func subsetOf(t *testing.T, field string, got, supported []string) {
	t.Helper()
	for _, g := range got {
		if !slices.Contains(supported, g) {
			t.Errorf("%s has %q, which the provider does not support", field, g)
		}
	}
}

func TestGoogleEndpoints(t *testing.T) {
	p := Google("client-id", "client-secret", "https://shop.example/google/cb")
	cfg, doc := readDiscovery(t, "google")

	eq(t, "Name", p.Name, "google")
	eqList(t, "Issuers", p.Issuers, []string{"https://accounts.google.com", "accounts.google.com"})
	eq(t, "AuthURL", p.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
	eq(t, "TokenURL", p.TokenURL, "https://oauth2.googleapis.com/token")
	eq(t, "JWKSURL", p.JWKSURL, "https://www.googleapis.com/oauth2/v3/certs")
	eq(t, "ClientID", p.ClientID, "client-id")
	eq(t, "ClientSecret", p.ClientSecret, "client-secret")
	eq(t, "RedirectURL", p.RedirectURL, "https://shop.example/google/cb")
	eqList(t, "Scopes", p.Scopes, []string{"openid", "email", "profile"})
	eq(t, "SkipSecondFactor", p.SkipSecondFactor, true)
	if p.Secret != nil {
		t.Error("Secret is set, want nil")
	}
	eq(t, "AuthStyle", p.AuthStyle, oauth2.AuthStyleInParams)
	eq(t, "FormPost", p.FormPost, false)
	eq(t, "SameSite", p.SameSite, http.SameSiteLaxMode)

	eq(t, "the discovery issuer", cfg.IssuerURL, p.Issuers[0])
	eq(t, "the discovery AuthURL", p.AuthURL, cfg.AuthURL)
	eq(t, "the discovery TokenURL", p.TokenURL, cfg.TokenURL)
	eq(t, "the discovery JWKSURL", p.JWKSURL, cfg.JWKSURL)
	eqList(t, "the discovery algorithms", cfg.Algorithms, []string{"RS256"})
	subsetOf(t, "Scopes", p.Scopes, doc.Scopes)
	if !slices.Contains(doc.AuthMethods, "client_secret_post") {
		t.Error("the discovery document does not offer client_secret_post")
	}
	if !slices.Contains(doc.PKCE, "S256") {
		t.Error("the discovery document does not offer PKCE S256")
	}
}

func TestAppleEndpoints(t *testing.T) {
	_, p8 := appleP8(t)
	p, err := Apple(teamID, keyID, servicesID, p8, "https://shop.example/apple/cb")
	if err != nil {
		t.Fatalf("Apple: %v", err)
	}
	cfg, doc := readDiscovery(t, "apple")

	eq(t, "Name", p.Name, "apple")
	eqList(t, "Issuers", p.Issuers, []string{"https://appleid.apple.com"})
	eq(t, "AuthURL", p.AuthURL, "https://appleid.apple.com/auth/authorize")
	eq(t, "TokenURL", p.TokenURL, "https://appleid.apple.com/auth/token")
	eq(t, "JWKSURL", p.JWKSURL, "https://appleid.apple.com/auth/keys")
	eq(t, "ClientID", p.ClientID, servicesID)
	eq(t, "ClientSecret", p.ClientSecret, "")
	eq(t, "RedirectURL", p.RedirectURL, "https://shop.example/apple/cb")
	eqList(t, "Scopes", p.Scopes, []string{"openid", "email", "name"})
	eq(t, "SkipSecondFactor", p.SkipSecondFactor, true)
	if p.Secret == nil {
		t.Error("Secret is nil, want the Apple client secret signer")
	}
	eq(t, "AuthStyle", p.AuthStyle, oauth2.AuthStyleInParams)
	eq(t, "FormPost", p.FormPost, true)
	eq(t, "SameSite", p.SameSite, http.SameSiteNoneMode)

	eqList(t, "the discovery issuer", p.Issuers, []string{cfg.IssuerURL})
	eq(t, "the discovery AuthURL", p.AuthURL, cfg.AuthURL)
	eq(t, "the discovery TokenURL", p.TokenURL, cfg.TokenURL)
	eq(t, "the discovery JWKSURL", p.JWKSURL, cfg.JWKSURL)
	eqList(t, "the discovery algorithms", cfg.Algorithms, []string{"RS256"})
	subsetOf(t, "Scopes", p.Scopes, doc.Scopes)
	if !slices.Contains(doc.AuthMethods, "client_secret_post") {
		t.Error("the discovery document does not offer client_secret_post")
	}
	if !slices.Contains(doc.ResponseModes, "form_post") {
		t.Error("the discovery document does not offer form_post")
	}
}
