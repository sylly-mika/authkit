package invite

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/token"
	"github.com/sylly-mika/authkit/onetime"
	"github.com/sylly-mika/authkit/password"
)

// Rules configures the invite module.
type Rules struct {
	// TTL is how long an invite and its link stay valid. Zero is 72 hours.
	TTL time.Duration
	// Create makes the principal an invite accepted without a sign-in creates.
	Create func(ctx context.Context, q db.Querier, p Pending, input json.RawMessage) (authkit.Principal, error)
	// Join adds the holder of the invited address to the invite's audience and scope at accept.
	Join func(ctx context.Context, q db.Querier, p Pending, holder authkit.Principal) error
	// Check says whether an invite may still be sent; an error voids the invite at Mint.
	Check func(ctx context.Context, q db.Querier, p Pending) error
	// OIDC accepts invites by an OpenID provider; nil refuses that path.
	OIDC Tickets
}

// Tickets is the OIDC module's side of accepting an invite by provider sign-in.
type Tickets interface {
	// TicketEmail returns the address a provider ticket vouches for and whether the provider hid it.
	TicketEmail(ctx context.Context, q db.Querier, ticket string) (email string, private bool, err error)
	// SignUp makes principal the holder of the ticket's sign-in and returns the result.
	SignUp(ctx context.Context, q db.Querier, ticket string, principal uuid.UUID, aud authkit.Audience, meta authkit.Meta) (authkit.Result, error)
}

// Pending is an invite as the app's Create, Join and Check see it.
type Pending struct {
	ID                   uuid.UUID
	Audience             authkit.Audience
	Email                string
	ScopeID, InvitedBy   *uuid.UUID
	Payload              json.RawMessage
	CreatedAt, ExpiresAt time.Time
}

// Request is one invite to send.
type Request struct {
	Audience           authkit.Audience
	Email              string
	ScopeID, InvitedBy *uuid.UUID
	Payload            json.RawMessage
}

// Invited is what Invite and Resend return: the invite, its link's id, and the principal already holding the address.
type Invited struct {
	ID, TokenID uuid.UUID
	Holder      *authkit.Principal
}

// State is where an invite stands. Its values are pending, expired, accepted and revoked.
type State string

// Invite is an invite row with its state.
type Invite struct {
	Pending
	State                 State
	AcceptedAt, RevokedAt *time.Time
	AcceptedBy            *uuid.UUID
}

// ErrInvitePending says an open invite already exists for the address.
var ErrInvitePending = errors.New("invite: an open invite exists for this address")

// ErrInviteClosed says the invite is already accepted or revoked, or does not exist.
var ErrInviteClosed = errors.New("invite: invite already accepted or revoked")

// ErrSignInToAccept says the invite needs a sign-in before it can be accepted.
var ErrSignInToAccept = errors.New("invite: sign in to accept this invite")

// ErrOtherAccount says the signed-in account is not the invited address.
var ErrOtherAccount = errors.New("invite: this invite is for another address")

// ErrAddressHeld says a principal already holds the invited address and the module cannot join it.
var ErrAddressHeld = errors.New("invite: address already has an account")

// ErrNothingToSend says the invite or its link is gone, so the mail job drops.
var ErrNothingToSend = errors.New("invite: nothing to send")

// ErrEmailMismatch says the provider's address differs from the invited address.
var ErrEmailMismatch = errors.New("invite: the provider's address is not the invited address")

// ErrPrivateEmail says the provider hid the address, so the invite must be accepted with the invited address.
var ErrPrivateEmail = errors.New("invite: the provider hid the address; accept with the invited address")

// ErrNoOIDC says accepting by OIDC is not configured.
var ErrNoOIDC = errors.New("invite: accept by OIDC is not configured")

// Module is the invite module; build it with New.
type Module struct {
	core       *authkit.Core
	pw         *password.Module
	links      *onetime.Store
	principals authkit.Principals
	r          Rules
}

// New attaches the invite module to svc as "invite"; pw sets the password at accept.
func New(svc *authkit.Service, pw *password.Module, r Rules) (*Module, error) {
	if r.Create == nil {
		return nil, errors.New("invite: Rules.Create is nil")
	}
	if pw == nil {
		return nil, errors.New("invite: the password module is nil")
	}
	if r.TTL < 0 {
		return nil, errors.New("invite: Rules.TTL is negative")
	}
	if r.TTL == 0 {
		r.TTL = 72 * time.Hour
	}
	core, err := svc.Attach("invite")
	if err != nil {
		return nil, err
	}
	return &Module{core: core, pw: pw, links: svc.OneTime(), principals: core.Principals(), r: r}, nil
}

// Invite records an invite for req.Email and creates its unsent link.
func (m *Module) Invite(ctx context.Context, q db.Querier, req Request) (Invited, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Invited{}, err
	}
	now := m.core.Now()
	n := authkit.Normalize(req.Email)
	payload := req.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	holder, err := m.held(ctx, q, n, req.Audience)
	if err != nil {
		return Invited{}, err
	}
	if holder != nil && m.r.Join == nil {
		return Invited{}, ErrAddressHeld
	}
	id, err := token.ID(m.core.Rand())
	if err != nil {
		return Invited{}, err
	}
	// WHY: TestNoInsertUsesReturning forbids RETURNING on this insert.
	affected, err := q.Exec(ctx, `
		INSERT INTO auth_invites (id, audience, email, scope_id, invited_by, payload, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8) ON CONFLICT DO NOTHING`,
		id, string(req.Audience), n, req.ScopeID, req.InvitedBy, string(payload), now, now.Add(m.r.TTL))
	if err != nil {
		return Invited{}, err
	}
	if affected == 0 {
		return Invited{}, ErrInvitePending
	}
	tok, err := m.links.Create(ctx, q, authkit.PurposeInvite, id, m.r.TTL)
	if err != nil {
		return Invited{}, err
	}
	return Invited{ID: id, TokenID: tok, Holder: holder}, nil
}

// Resend restarts an open invite's expiry and replaces its link.
func (m *Module) Resend(ctx context.Context, q db.Querier, id uuid.UUID) (Invited, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Invited{}, err
	}
	now := m.core.Now()
	row, err := m.lockRow(ctx, q, id)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Invited{}, ErrInviteClosed
	case err != nil:
		return Invited{}, err
	case row.AcceptedAt != nil || row.RevokedAt != nil:
		return Invited{}, ErrInviteClosed
	}
	holder, err := m.held(ctx, q, row.Email, row.Audience)
	if err != nil {
		return Invited{}, err
	}
	if holder != nil && m.r.Join == nil {
		return Invited{}, ErrAddressHeld
	}
	if _, err := q.Exec(ctx, `UPDATE auth_invites SET expires_at = $2 WHERE id = $1`, id, now.Add(m.r.TTL)); err != nil {
		return Invited{}, err
	}
	tok, err := m.links.Create(ctx, q, authkit.PurposeInvite, id, m.r.TTL)
	if err != nil {
		return Invited{}, err
	}
	return Invited{ID: id, TokenID: tok, Holder: holder}, nil
}

// Revoke closes an open invite; its link then answers revoked.
func (m *Module) Revoke(ctx context.Context, q db.Querier, id uuid.UUID) error {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return err
	}
	row, err := m.lockRow(ctx, q, id)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return ErrInviteClosed
	case err != nil:
		return err
	case row.AcceptedAt != nil || row.RevokedAt != nil:
		return ErrInviteClosed
	}
	return m.void(ctx, q, id)
}

// List returns the invites of an audience and scope, newest first.
func (m *Module) List(ctx context.Context, q db.Querier, aud authkit.Audience, scope *uuid.UUID, limit, offset int) ([]Invite, int, error) {
	q = m.core.Q(q)
	if limit < 0 || offset < 0 {
		return nil, 0, errors.New("invite: negative limit or offset")
	}
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM auth_invites WHERE audience = $1 AND scope_id IS NOT DISTINCT FROM $2::uuid`,
		string(aud), scope).Scan(&total); err != nil {
		return nil, 0, err
	}
	var lim any
	if limit != 0 {
		lim = limit
	}
	rows, err := q.Query(ctx, "SELECT "+cols+` FROM auth_invites WHERE audience = $1 AND scope_id IS NOT DISTINCT FROM $2::uuid
		ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4`, string(aud), scope, lim, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	now := m.core.Now()
	var out []Invite
	for rows.Next() {
		inv, err := scanInvite(rows, now)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (m *Module) held(ctx context.Context, q db.Querier, login string, aud authkit.Audience) (*authkit.Principal, error) {
	p, err := m.principals.Lookup(ctx, q, login, aud)
	switch {
	case err == nil:
		return &p, nil
	case errors.Is(err, authkit.ErrUnknownLogin):
		return nil, nil
	}
	return nil, err
}

const cols = `id, audience, email, scope_id, invited_by, payload::text, created_at, expires_at, accepted_at, accepted_by, revoked_at`

func scanInvite(r interface{ Scan(dest ...any) error }, now time.Time) (Invite, error) {
	var inv Invite
	var aud, payload string
	var scope, inviter, acceptor *uuid.UUID
	err := r.Scan(&inv.ID, &aud, &inv.Email, &scope, &inviter, &payload, &inv.CreatedAt, &inv.ExpiresAt,
		&inv.AcceptedAt, &acceptor, &inv.RevokedAt)
	if err != nil {
		return Invite{}, err
	}
	inv.Audience = authkit.Audience(aud)
	inv.ScopeID, inv.InvitedBy, inv.AcceptedBy = scope, inviter, acceptor
	inv.Payload = json.RawMessage(payload)
	switch {
	case inv.AcceptedAt != nil:
		inv.State = "accepted"
	case inv.RevokedAt != nil:
		inv.State = "revoked"
	case !inv.ExpiresAt.After(now):
		inv.State = "expired"
	default:
		inv.State = "pending"
	}
	return inv, nil
}

func (m *Module) readRow(ctx context.Context, q db.Querier, id uuid.UUID) (Invite, error) {
	return scanInvite(q.QueryRow(ctx, "SELECT "+cols+" FROM auth_invites WHERE id = $1", id), m.core.Now())
}

func (m *Module) lockRow(ctx context.Context, q db.Querier, id uuid.UUID) (Invite, error) {
	return scanInvite(q.QueryRow(ctx, "SELECT "+cols+" FROM auth_invites WHERE id = $1 FOR UPDATE", id), m.core.Now())
}

func (m *Module) void(ctx context.Context, q db.Querier, id uuid.UUID) error {
	if _, err := q.Exec(ctx, `UPDATE auth_invites SET revoked_at = $2 WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`,
		id, m.core.Now()); err != nil {
		return err
	}
	return m.links.Revoke(ctx, q, authkit.PurposeInvite, id)
}
