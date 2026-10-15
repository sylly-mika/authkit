package register

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/password"
)

// Activate spends a registration link, creates the principal with pw and signs it in.
// A refusal (PolicyError, ErrBusy, authkit.ErrTokenUnknown, ErrAddressHeld, an Admit refusal) is
// Result.Refusal with a nil error: commit it. An error from Rules.Create is returned: roll back.
func (m *Module) Activate(ctx context.Context, q db.Querier, raw, pw string, meta authkit.Meta) (authkit.Result, error) {
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

	tok, err := m.links.Peek(ctx, q, raw)
	switch {
	case errors.Is(err, authkit.ErrTokenUnknown), err == nil && tok.Purpose != authkit.PurposeRegister:
		return authkit.Result{Refusal: authkit.ErrTokenUnknown}, nil
	case err != nil:
		return authkit.Result{}, err
	}
	reg, ok, err := m.lockPending(ctx, q, tok.Owner, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrTokenUnknown}, nil
	}

	_, err = m.links.Spend(ctx, q, raw, authkit.PurposeRegister)
	var gone authkit.ErrTokenGone
	switch {
	case errors.Is(err, authkit.ErrTokenUnknown), errors.As(err, &gone):
		return authkit.Result{Refusal: authkit.ErrTokenUnknown}, nil
	case err != nil:
		return authkit.Result{}, err
	}

	p, err := m.core.Principals().Lookup(ctx, q, reg.Email, reg.Audience)
	switch {
	case err == nil:
		if _, err := q.Exec(ctx, `DELETE FROM auth_registrations WHERE id = $1`, reg.ID); err != nil {
			return authkit.Result{}, err
		}
		return authkit.Result{Refusal: ErrAddressHeld}, nil
	case !errors.Is(err, authkit.ErrUnknownLogin):
		return authkit.Result{}, err
	}

	p, err = m.r.Create(ctx, in, reg)
	if err != nil {
		return authkit.Result{}, err
	}
	if err := m.pw.SetHash(ctx, q, p, h); err != nil {
		return authkit.Result{}, err
	}
	if _, err := q.Exec(ctx, `DELETE FROM auth_registrations WHERE id = $1`, reg.ID); err != nil {
		return authkit.Result{}, err
	}
	if err := m.core.Record(ctx, q, authkit.SourceRegister, authkit.Event{PrincipalID: &p.ID, Audience: string(reg.Audience), Login: p.Login,
		Result: authkit.ResultRegistered, IP: meta.IP, UserAgent: meta.UserAgent}); err != nil {
		return authkit.Result{}, err
	}

	a := m.core.BeginVerified(authkit.SourceRegister, reg.Audience, meta)
	a.SetPrincipal(&p)
	res, err := m.core.SignIn(ctx, q, a, p, authkit.FactorPassword)
	if err != nil {
		return authkit.Result{}, err
	}
	res.Principal = p
	return res, nil
}

func (m *Module) lockPending(ctx context.Context, q db.Querier, id uuid.UUID, now time.Time) (Pending, bool, error) {
	var reg Pending
	var aud string
	var payload []byte
	err := q.QueryRow(ctx, `SELECT id, audience, email, payload, created_at FROM auth_registrations WHERE id = $1 AND expires_at > $2 FOR UPDATE`,
		id, now).Scan(&reg.ID, &aud, &reg.Email, &payload, &reg.CreatedAt)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Pending{}, false, nil
	case err != nil:
		return Pending{}, false, err
	}
	reg.Audience = authkit.Audience(aud)
	reg.Payload = json.RawMessage(payload)
	return reg, true, nil
}
