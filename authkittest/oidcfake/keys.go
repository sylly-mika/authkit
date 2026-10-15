package oidcfake

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	jose "github.com/go-jose/go-jose/v4"
)

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkcs8PEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const (
	appleAud              = "https://appleid.apple.com"
	appleSecretMaxSeconds = 15777000
)

func audienceIs(raw json.RawMessage, want string) bool {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && len(many) == 1 && many[0] == want
}

func (s *Server) verifyAppleSecret(secret string) bool {
	obj, err := jose.ParseSigned(secret, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(obj.Signatures) != 1 || obj.Signatures[0].Header.KeyID != s.keyID {
		return false
	}
	payload, err := obj.Verify(&s.appleKey.PublicKey)
	if err != nil {
		return false
	}
	var c struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Iat *float64        `json:"iat"`
		Exp *float64        `json:"exp"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Iat == nil || c.Exp == nil {
		return false
	}
	now := float64(s.now().Unix())
	return c.Iss == s.teamID && c.Sub == s.ClientID && audienceIs(c.Aud, appleAud) &&
		*c.Iat <= now && *c.Exp > now && *c.Exp-*c.Iat <= appleSecretMaxSeconds
}

func (s *Server) jwks() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.rsaKey.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"}}}
}

func (s *Server) sign(header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	sig, err := s.rsaKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
