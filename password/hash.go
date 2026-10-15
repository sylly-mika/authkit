package password

import (
	"context"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// Hash is a password hash made by Module.Hash. The zero value holds nothing.
type Hash struct{ encoded string }

// Hash checks pw against the module's policy and hashes it with the module's hasher. It touches no table.
func (s *Module) Hash(ctx context.Context, pw string) (Hash, error) {
	if err := s.cfg.Password.Check(pw); err != nil {
		return Hash{}, err
	}
	encoded, err := s.hasher.Hash(ctx, pw)
	if err != nil {
		return Hash{}, err
	}
	return Hash{encoded: encoded}, nil
}

// SetHash stores h as the principal's first password, in the caller's transaction. It records no event.
func (s *Module) SetHash(ctx context.Context, q db.Querier, p authkit.Principal, h Hash) error {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return err
	}
	if h.encoded == "" {
		return ErrNoHash
	}
	n, err := q.Exec(ctx, `
		INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)
		ON CONFLICT (principal_id) DO NOTHING`,
		p.ID, h.encoded, s.now())
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrCredentialExists
	}
	return nil
}
