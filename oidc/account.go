package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
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

// TicketEmail returns the email of a live sign-up ticket and whether it is a private relay address, without spending it.
func (m *Module) TicketEmail(ctx context.Context, q db.Querier, ticket string) (email string, private bool, err error) {
	s, err := m.Ticket(ctx, q, ticket)
	if err != nil {
		return "", false, err
	}
	return s.Email, s.PrivateEmail, nil
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
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Redirect{}, err
	}
	if _, ok := m.providers[provider]; !ok {
		return Redirect{}, ErrUnknownProvider
	}
	_, ok, err := m.core.Fresh(ctx, q, cl, m.rules.Reauth, m.core.Now())
	if err != nil {
		return Redirect{}, err
	}
	if !ok {
		return Redirect{}, authkit.ErrReauthRequired
	}
	return m.begin(ctx, q, "link", provider, authkit.Audience(cl.Audience), &cl.Subject)
}

// Unlink removes the caller's identity at provider and ends the caller's other sessions.
func (m *Module) Unlink(ctx context.Context, q db.Querier, cl *authkit.Claims, provider string, meta authkit.Meta) error {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return err
	}
	now := m.core.Now()
	// WHY: this lock orders Unlink against passkey Delete, ChangePassword and CompleteReset; without it two Unlinks from two sessions deadlock in RevokeOthers.
	var one int
	err := q.QueryRow(ctx, `SELECT 1 FROM auth_credentials WHERE principal_id = $1 FOR UPDATE`, cl.Subject).Scan(&one)
	hasPassword := err == nil
	if err != nil && !errors.Is(err, db.ErrNoRows) {
		return err
	}
	// WHY: the identity rows are locked here, before the checks, so a second Unlink waits and then decides on the rows that are left.
	providers, err := lockIdentities(ctx, q, cl.Subject)
	if err != nil {
		return err
	}
	sess, ok, err := m.core.Fresh(ctx, q, cl, m.rules.Reauth, now)
	if err != nil {
		return err
	}
	if !ok {
		return authkit.ErrReauthRequired
	}
	if !slices.Contains(providers, provider) {
		return ErrNotLinked
	}
	if len(providers) == 1 && !hasPassword {
		var passkeys int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM auth_passkeys WHERE principal_id = $1`, cl.Subject).Scan(&passkeys); err != nil {
			return err
		}
		if passkeys == 0 {
			return ErrLastCredential
		}
	}
	if _, err := q.Exec(ctx, `DELETE FROM auth_identities WHERE principal_id = $1 AND provider = $2`, cl.Subject, provider); err != nil {
		return err
	}
	if err := m.core.RevokeOthers(ctx, q, cl.Subject, cl.SessionID, authkit.ReasonIdentityRemoved, now); err != nil {
		return err
	}
	m2 := meta.Clean()
	return m.core.Record(ctx, q, authkit.SourceOIDC, authkit.Event{At: now, PrincipalID: &cl.Subject, SessionID: &cl.SessionID, ScopeID: sess.ScopeID,
		Audience: cl.Audience, Result: authkit.ResultIdentityUnlinked, IP: m2.IP, UserAgent: m2.UserAgent})
}

func lockIdentities(ctx context.Context, q db.Querier, principal uuid.UUID) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT provider FROM auth_identities WHERE principal_id = $1 ORDER BY provider FOR UPDATE`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
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
