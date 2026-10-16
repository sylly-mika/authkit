// Package pending holds the link steps shared by modules that keep a pending row behind a one-time link.
package pending

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/onetime"
)

// Owner peeks at the link raw stands for; false when no link carries raw or the link is of another purpose.
func Owner(ctx context.Context, q db.Querier, links *onetime.Store, raw, purpose string) (onetime.Token, bool, error) {
	tok, err := links.Peek(ctx, q, raw)
	switch {
	case errors.Is(err, onetime.ErrUnknown):
		return onetime.Token{}, false, nil
	case err != nil:
		return onetime.Token{}, false, err
	case tok.Purpose != purpose:
		return onetime.Token{}, false, nil
	}
	return tok, true, nil
}

// Mint makes tokenID's raw link with its ExpiresAt capped at rowExpires; false when the link is unknown, superseded or spent.
func Mint(ctx context.Context, q db.Querier, links *onetime.Store, tokenID uuid.UUID, rowExpires time.Time) (onetime.Minted, bool, error) {
	mt, err := links.Mint(ctx, q, tokenID)
	var gone onetime.ErrGone
	switch {
	case errors.Is(err, onetime.ErrUnknown), errors.As(err, &gone):
		return onetime.Minted{}, false, nil
	case err != nil:
		return onetime.Minted{}, false, err
	}
	if rowExpires.Before(mt.ExpiresAt) {
		mt.ExpiresAt = rowExpires
	}
	return mt, true, nil
}
