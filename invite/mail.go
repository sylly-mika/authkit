package invite

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/pending"
	"github.com/sylly-mika/authkit/onetime"
)

// Mail is the link the app mails for an invite.
type Mail struct {
	To, Raw string
	Invite  Pending
	Held    bool
}

// Opened is the invite a link stands for.
type Opened struct {
	Pending
	Held bool
}

// Mint makes the raw link for an unsent or resent invite.
func (m *Module) Mint(ctx context.Context, q db.Querier, tokenID uuid.UUID) (Mail, error) {
	in := q
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Mail{}, err
	}
	var owner uuid.UUID
	err := q.QueryRow(ctx, `SELECT owner_id FROM auth_tokens WHERE id = $1 AND purpose = $2`, tokenID, authkit.PurposeInvite).Scan(&owner)
	if errors.Is(err, db.ErrNoRows) {
		return Mail{}, ErrNothingToSend
	}
	if err != nil {
		return Mail{}, err
	}
	row, err := m.lockRow(ctx, q, owner)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Mail{}, ErrNothingToSend
	case err != nil:
		return Mail{}, err
	case row.State != "pending":
		return Mail{}, ErrNothingToSend
	}
	if m.r.Check != nil {
		if cerr := m.r.Check(ctx, in, row.Pending); cerr != nil {
			if err := m.void(ctx, q, row.ID); err != nil {
				return Mail{}, err
			}
			return Mail{}, fmt.Errorf("%w: %w", ErrNothingToSend, cerr)
		}
	}
	holder, err := m.held(ctx, q, row.Email, row.Audience)
	if err != nil {
		return Mail{}, err
	}
	mt, ok, err := pending.Mint(ctx, q, m.links, tokenID, row.ExpiresAt)
	if err != nil {
		return Mail{}, err
	}
	if !ok {
		return Mail{}, ErrNothingToSend
	}
	return Mail{To: row.Email, Raw: mt.Raw, Invite: row.Pending, Held: holder != nil}, nil
}

// Open reads the invite a link stands for without spending it.
func (m *Module) Open(ctx context.Context, q db.Querier, raw string) (Opened, error) {
	q = m.core.Q(q)
	tok, ok, err := pending.Owner(ctx, q, m.links, raw, authkit.PurposeInvite)
	if err != nil {
		return Opened{}, err
	}
	if !ok {
		return Opened{}, authkit.ErrTokenUnknown
	}
	if tok.State != onetime.StateLive {
		return Opened{}, authkit.ErrTokenGone{State: tok.State}
	}
	row, err := m.readRow(ctx, q, tok.Owner)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Opened{}, authkit.ErrTokenUnknown
	case err != nil:
		return Opened{}, err
	}
	switch row.State {
	case "accepted":
		return Opened{}, authkit.ErrTokenGone{State: onetime.StateUsed}
	case "revoked":
		return Opened{}, authkit.ErrTokenGone{State: onetime.StateRevoked}
	case "expired":
		return Opened{}, authkit.ErrTokenGone{State: onetime.StateExpired}
	}
	holder, err := m.held(ctx, q, row.Email, row.Audience)
	if err != nil {
		return Opened{}, err
	}
	return Opened{Pending: row.Pending, Held: holder != nil}, nil
}
