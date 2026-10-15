package authkit

import (
	"context"

	"github.com/google/uuid"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/nsql"
)

// Q returns q with authkit's table names qualified by Config.Schema; q itself when Schema is "".
func (c *Core) Q(q db.Querier) db.Querier { return c.s.names.Q(q) }

// WHY: the app's Principals run their own SQL, so they get the caller's querier without the names wrapper.
type plainPrincipals struct{ app Principals }

func (pp plainPrincipals) Lookup(ctx context.Context, q db.Querier, login string, aud Audience) (Principal, error) {
	return pp.app.Lookup(ctx, nsql.Plain(q), login, aud)
}

func (pp plainPrincipals) ByID(ctx context.Context, q db.Querier, id uuid.UUID, aud Audience) (Principal, error) {
	return pp.app.ByID(ctx, nsql.Plain(q), id, aud)
}

func (pp plainPrincipals) Admit(ctx context.Context, q db.Querier, p Proposal) (Admission, error) {
	return pp.app.Admit(ctx, nsql.Plain(q), p)
}
