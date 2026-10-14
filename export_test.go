package authkit

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/sylly-mika/authkit/db"
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

func PasskeyOwnerHandler(ctx context.Context, q db.Querier, rawID, userHandle []byte) (webauthn.User, error) {
	var hit *passkeyRow
	var infraErr error
	return passkeyHandler(ctx, q, &hit, &infraErr)(rawID, userHandle)
}
