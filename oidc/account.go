package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// Identity is one linked provider account of a principal.
type Identity struct {
	Provider, Email string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

// Ticket returns the sign-up a live ticket stands for, without spending it.
func (m *Module) Ticket(ctx context.Context, q db.Querier, ticket string) (*SignUp, error) {
	q = m.core.Q(q)
	now := m.core.Now()
	s := &SignUp{Ticket: ticket}
	var profile []byte
	err := q.QueryRow(ctx, `SELECT provider, COALESCE(email, ''), profile FROM auth_ceremonies WHERE state_hash = $1 AND kind = 'signup' AND spent_at IS NULL AND expires_at > $2`,
		digest(ticket), now).Scan(&s.Provider, &s.Email, &profile)
	if errors.Is(err, db.ErrNoRows) {
		return nil, ErrTicketUnknown
	}
	if err != nil {
		return nil, err
	}
	var p struct {
		Name         string `json:"name"`
		GivenName    string `json:"given_name"`
		FamilyName   string `json:"family_name"`
		PrivateEmail bool   `json:"private_email"`
	}
	if err := json.Unmarshal(profile, &p); err != nil {
		return nil, err
	}
	s.Name, s.GivenName, s.FamilyName, s.PrivateEmail = p.Name, p.GivenName, p.FamilyName, p.PrivateEmail
	return s, nil
}

// SignUp spends the ticket, links its identity to principal and signs the principal in. Every error it returns means the caller should roll back, including ErrTicketUnknown and ErrIdentityTaken; only an Admit refusal is a Refusal, and the caller should roll back any principal it created for this sign-up.
func (m *Module) SignUp(ctx context.Context, q db.Querier, ticket string, principal uuid.UUID, aud authkit.Audience, meta authkit.Meta) (authkit.Result, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	now := m.core.Now()
	var provider, subject, email string
	err := q.QueryRow(ctx, `UPDATE auth_ceremonies SET spent_at = $3 WHERE state_hash = $1 AND kind = 'signup' AND audience = $2 AND spent_at IS NULL AND expires_at > $3 RETURNING provider, subject, COALESCE(email, '')`,
		digest(ticket), string(aud), now).Scan(&provider, &subject, &email)
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{}, ErrTicketUnknown
	}
	if err != nil {
		return authkit.Result{}, err
	}
	p, err := m.core.Principals().ByID(ctx, q, principal, aud)
	if err != nil {
		return authkit.Result{}, err
	}
	id, err := uuid.NewRandomFromReader(m.core.Rand())
	if err != nil {
		return authkit.Result{}, err
	}
	linked, err := linkIdentity(ctx, q, id, principal, provider, subject, email, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !linked {
		return authkit.Result{}, ErrIdentityTaken
	}
	a := m.core.BeginVerified(authkit.SourceOIDC, aud, meta)
	if pv, ok := m.providers[provider]; ok && pv.SkipSecondFactor {
		a.SkipSecondFactor()
	}
	return m.core.SignIn(ctx, q, a, p, authkit.FactorOIDC)
}

// Link starts linking provider to the caller's account; the app sends the browser to the Redirect.
func (m *Module) Link(ctx context.Context, q db.Querier, cl *authkit.Claims, provider string, meta authkit.Meta) (Redirect, error) {
	return Redirect{}, errors.ErrUnsupported
}

// Unlink removes the caller's identity at provider and ends the caller's other sessions.
func (m *Module) Unlink(ctx context.Context, q db.Querier, cl *authkit.Claims, provider string, meta authkit.Meta) error {
	return errors.ErrUnsupported
}

// Identities lists the principal's linked provider identities, oldest first.
func (m *Module) Identities(ctx context.Context, q db.Querier, principal uuid.UUID) ([]Identity, error) {
	q = m.core.Q(q)
	rows, err := q.Query(ctx, `SELECT provider, COALESCE(email, ''), created_at, last_used_at FROM auth_identities WHERE principal_id = $1 ORDER BY created_at, provider`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Identity{}
	for rows.Next() {
		var id Identity
		if err := rows.Scan(&id.Provider, &id.Email, &id.CreatedAt, &id.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
