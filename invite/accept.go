package invite

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/pending"
	"github.com/sylly-mika/authkit/onetime"
	"github.com/sylly-mika/authkit/password"
)

// Accept spends the link, creates the principal with pw as its password and signs it in.
// A refusal is Result.Refusal with a nil error: commit it. An error from Rules.Create is returned: roll back.
func (m *Module) Accept(ctx context.Context, q db.Querier, raw, pw string, input json.RawMessage, meta authkit.Meta) (authkit.Result, error) {
	in := q
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	meta = meta.Clean()
	now := m.core.Now()

	h, err := m.pw.Hash(ctx, pw)
	var pe password.PolicyError
	switch {
	case errors.As(err, &pe):
		return authkit.Result{Refusal: err}, nil
	case errors.Is(err, password.ErrBusy):
		return authkit.Result{Refusal: password.ErrBusy}, nil
	case err != nil:
		return authkit.Result{}, err
	}

	inv, err := m.acceptLink(ctx, q, raw)
	switch {
	case refused(err):
		return authkit.Result{Refusal: err}, nil
	case err != nil:
		return authkit.Result{}, err
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
	if err := m.pw.SetHash(ctx, q, p, h); err != nil {
		return authkit.Result{}, err
	}
	if err := markAccepted(ctx, q, inv.ID, p.ID, now); err != nil {
		return authkit.Result{}, err
	}
	if err := m.core.Record(ctx, q, authkit.SourceInvite, authkit.Event{PrincipalID: &p.ID, Audience: string(inv.Audience), Login: p.Login,
		Result: authkit.ResultRegistered, IP: meta.IP, UserAgent: meta.UserAgent}); err != nil {
		return authkit.Result{}, err
	}

	a := m.core.BeginVerified(authkit.SourceInvite, inv.Audience, meta)
	a.SetPrincipal(&p)
	res, err := m.core.SignIn(ctx, q, a, p, authkit.FactorPassword)
	if err != nil {
		return authkit.Result{}, err
	}
	res.Principal = p
	return res, nil
}

// AcceptSignedIn spends the link for the signed-in principal that holds the invited address.
// A refusal is Result.Refusal with a nil error: commit it. An error from Rules.Join is returned: roll back.
func (m *Module) AcceptSignedIn(ctx context.Context, q db.Querier, cl *authkit.Claims, raw string, meta authkit.Meta) (authkit.Result, error) {
	return authkit.Result{}, errors.New("todo")
}

func (m *Module) acceptLink(ctx context.Context, q db.Querier, raw string) (Invite, error) {
	tok, ok, err := pending.Owner(ctx, q, m.links, raw, authkit.PurposeInvite)
	switch {
	case err != nil:
		return Invite{}, err
	case !ok:
		return Invite{}, authkit.ErrTokenUnknown
	}
	inv, err := m.lockRow(ctx, q, tok.Owner)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Invite{}, authkit.ErrTokenUnknown
	case err != nil:
		return Invite{}, err
	}
	switch inv.State {
	case "accepted":
		return Invite{}, authkit.ErrTokenGone{State: onetime.StateUsed}
	case "revoked":
		return Invite{}, authkit.ErrTokenGone{State: onetime.StateRevoked}
	case "expired":
		return Invite{}, authkit.ErrTokenGone{State: onetime.StateExpired}
	}
	if tok.State != onetime.StateLive {
		return Invite{}, authkit.ErrTokenGone{State: tok.State}
	}
	return inv, nil
}

func (m *Module) checkAndSpend(ctx context.Context, in, q db.Querier, raw string, inv Invite) (error, error) {
	if m.r.Check != nil {
		if cerr := m.r.Check(ctx, in, inv.Pending); cerr != nil {
			if err := m.void(ctx, q, inv.ID); err != nil {
				return nil, err
			}
			return cerr, nil
		}
	}
	_, err := m.links.Spend(ctx, q, raw, authkit.PurposeInvite)
	if refused(err) {
		return err, nil
	}
	return nil, err
}

func refused(err error) bool {
	var gone authkit.ErrTokenGone
	return errors.Is(err, authkit.ErrTokenUnknown) || errors.As(err, &gone)
}

func markAccepted(ctx context.Context, q db.Querier, id, by uuid.UUID, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE auth_invites SET accepted_at = $2, accepted_by = $3 WHERE id = $1`, id, now, by)
	return err
}
