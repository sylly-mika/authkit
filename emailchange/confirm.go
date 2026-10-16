package emailchange

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/onetime"
)

// Confirm spends the link and changes the principal's login to the new address.
// A refusal (authkit.ErrTokenUnknown, authkit.ErrTokenGone, ErrStale, ErrAddressHeld) is Changed.Refusal
// with a nil error: commit it. An error from Rules.Change is returned: roll back.
func (m *Module) Confirm(ctx context.Context, q db.Querier, raw string, meta authkit.Meta) (Changed, error) {
	in := q
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Changed{}, err
	}
	meta = meta.Clean()
	now := m.core.Now()

	tok, err := m.links.Peek(ctx, q, raw)
	switch {
	case errors.Is(err, authkit.ErrTokenUnknown), err == nil && tok.Purpose != authkit.PurposeEmailChange:
		return refused(authkit.ErrTokenUnknown), nil
	case err != nil:
		return Changed{}, err
	case tok.State != onetime.StateLive:
		return refused(authkit.ErrTokenGone{State: tok.State}), nil
	}
	var aud, oldEmail, newEmail string
	var starter *uuid.UUID
	err = q.QueryRow(ctx, `SELECT audience, old_email, new_email, session_id FROM auth_email_changes WHERE principal_id = $1 AND expires_at > $2 FOR UPDATE`,
		tok.Owner, now).Scan(&aud, &oldEmail, &newEmail, &starter)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return refused(authkit.ErrTokenUnknown), nil
	case err != nil:
		return Changed{}, err
	}
	_, err = m.links.Spend(ctx, q, raw, authkit.PurposeEmailChange)
	var gone authkit.ErrTokenGone
	switch {
	case errors.Is(err, authkit.ErrTokenUnknown):
		return refused(authkit.ErrTokenUnknown), nil
	case errors.As(err, &gone):
		return refused(gone), nil
	case err != nil:
		return Changed{}, err
	}
	a := authkit.Audience(aud)
	p, err := m.principals.ByID(ctx, q, tok.Owner, a)
	switch {
	case errors.Is(err, authkit.ErrUnknownLogin):
		return m.drop(ctx, q, tok.Owner, authkit.ErrTokenUnknown)
	case err != nil:
		return Changed{}, err
	case authkit.Normalize(p.Login) != oldEmail:
		return m.drop(ctx, q, p.ID, ErrStale)
	}
	_, err = m.principals.Lookup(ctx, q, newEmail, a)
	switch {
	case err == nil:
		return m.drop(ctx, q, p.ID, ErrAddressHeld)
	case !errors.Is(err, authkit.ErrUnknownLogin):
		return Changed{}, err
	}
	if err := m.r.Change(ctx, in, p, newEmail); err != nil {
		return Changed{}, err
	}
	if err := m.core.Throttle(oldEmail, a, now).MoveTo(ctx, q, m.core.Throttle(newEmail, a, now)); err != nil {
		return Changed{}, err
	}
	if _, err := q.Exec(ctx, `DELETE FROM auth_second_step_challenges WHERE principal_id = $1`, p.ID); err != nil {
		return Changed{}, err
	}
	if m.r.RevokeAll || starter == nil {
		err = m.core.RevokeAll(ctx, q, p.ID, authkit.ReasonEmailChanged, now)
	} else {
		err = m.core.RevokeOthers(ctx, q, p.ID, *starter, authkit.ReasonEmailChanged, now)
	}
	if err != nil {
		return Changed{}, err
	}
	if _, err := q.Exec(ctx, `DELETE FROM auth_email_changes WHERE principal_id = $1`, p.ID); err != nil {
		return Changed{}, err
	}
	if err := m.core.Record(ctx, q, authkit.SourceEmailChange, authkit.Event{PrincipalID: &p.ID, Audience: aud, Login: newEmail,
		Result: authkit.ResultEmailChanged, IP: meta.IP, UserAgent: meta.UserAgent}); err != nil {
		return Changed{}, err
	}
	old := p.Login
	p.Login = newEmail
	return Changed{Result: authkit.Result{Principal: p}, Old: old, New: newEmail}, nil
}

func (m *Module) drop(ctx context.Context, q db.Querier, principal uuid.UUID, refusal error) (Changed, error) {
	if _, err := q.Exec(ctx, `DELETE FROM auth_email_changes WHERE principal_id = $1`, principal); err != nil {
		return Changed{}, err
	}
	return refused(refusal), nil
}

func refused(err error) Changed { return Changed{Result: authkit.Result{Refusal: err}} }
