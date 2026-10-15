package passkey

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

func PasskeyRP(m *Module, aud authkit.Audience) (*webauthn.WebAuthn, bool, error) {
	return m.relyingParty(aud)
}

func NewPasskeyUser(p authkit.Principal, creds []webauthn.Credential) webauthn.User {
	return passkeyUser{p: p, creds: creds}
}

func PasskeyOwnerHandler(ctx context.Context, q db.Querier, rawID, userHandle []byte) (webauthn.User, error) {
	var hit *passkeyRow
	var infraErr error
	return passkeyHandler(ctx, q, &hit, &infraErr)(rawID, userHandle)
}
