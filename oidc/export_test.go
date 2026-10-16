package oidc

import (
	"context"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// BeginLink starts a link ceremony for principal through the named provider.
func BeginLink(m *Module, ctx context.Context, q db.Querier, provider string, aud authkit.Audience, principal uuid.UUID) (Redirect, error) {
	return m.begin(ctx, q, "link", provider, aud, &principal)
}
