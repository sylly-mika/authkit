package password

import (
	"context"
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
