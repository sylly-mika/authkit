package authkit

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"
)

func SetVerifyHook(s *Service, f func()) { s.onVerify = f }

func HoldHashSlot(ctx context.Context, s *Service) (release func(), err error) {
	return s.hasher.Acquire(ctx)
}

func PasskeyRP(s *Service, aud Audience) (*webauthn.WebAuthn, bool, error) {
	return s.relyingParty(aud)
}

func NewPasskeyUser(p Principal, creds []webauthn.Credential) webauthn.User {
	return passkeyUser{p: p, creds: creds}
}
