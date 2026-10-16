package invite

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// AcceptOIDC spends the link and an OIDC sign-up ticket for the invited address, creates the principal and signs it in.
// A refusal is Result.Refusal with a nil error: commit it. An error is returned: roll back.
func (m *Module) AcceptOIDC(ctx context.Context, q db.Querier, raw, ticket string, input json.RawMessage, meta authkit.Meta) (authkit.Result, error) {
	in := q
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if m.r.OIDC == nil {
		return authkit.Result{}, ErrNoOIDC
	}
	meta = meta.Clean()
	now := m.core.Now()

	email, private, err := m.r.OIDC.TicketEmail(ctx, in, ticket)
	if err != nil {
		return authkit.Result{}, err
	}

	inv, err := m.acceptLink(ctx, q, raw)
	switch {
	case refused(err):
		return authkit.Result{Refusal: err}, nil
	case err != nil:
		return authkit.Result{}, err
	}

	switch {
	case private:
		return authkit.Result{Refusal: ErrPrivateEmail}, nil
	case authkit.Normalize(email) != inv.Email:
		return authkit.Result{Refusal: ErrEmailMismatch}, nil
	}

	holder, err := m.held(ctx, q, inv.Email, inv.Audience)
	switch {
	case err != nil:
		return authkit.Result{}, err
	case holder != nil:
		return authkit.Result{Refusal: ErrSignInToAccept}, nil
	}

	refusal, err := m.checkAndSpend(ctx, in, q, raw, inv)
	switch {
	case err != nil:
		return authkit.Result{}, err
	case refusal != nil:
		return authkit.Result{Refusal: refusal}, nil
	}

	p, err := m.r.Create(ctx, in, inv.Pending, input)
	if err != nil {
		return authkit.Result{}, err
	}
	if err := markAccepted(ctx, q, inv.ID, p.ID, now); err != nil {
		return authkit.Result{}, err
	}
	if err := m.core.Record(ctx, q, authkit.SourceInvite, authkit.Event{PrincipalID: &p.ID, Audience: string(inv.Audience), Login: p.Login,
		Result: authkit.ResultRegistered, IP: meta.IP, UserAgent: meta.UserAgent}); err != nil {
		return authkit.Result{}, err
	}

	res, err := m.r.OIDC.SignUp(ctx, in, ticket, p.ID, inv.Audience, meta)
	if err != nil {
		return authkit.Result{}, err
	}
	if res.Refusal != nil {
		return authkit.Result{}, fmt.Errorf("invite: the new principal was not admitted: %w", res.Refusal)
	}
	return res, nil
}
