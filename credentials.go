package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
)

func credentialOf(ctx context.Context, q db.Querier, id uuid.UUID) (hash string, ok bool, err error) {
	return scanCredential(q.QueryRow(ctx, `SELECT password_hash FROM auth_credentials WHERE principal_id = $1`, id))
}

func lockCredential(ctx context.Context, q db.Querier, id uuid.UUID) (hash string, ok bool, err error) {
	return scanCredential(q.QueryRow(ctx, `SELECT password_hash FROM auth_credentials WHERE principal_id = $1 FOR UPDATE`, id))
}

func scanCredential(row db.Row) (string, bool, error) {
	var hash string
	err := row.Scan(&hash)
	if errors.Is(err, db.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// rehashCredential re-encodes the hash Login verified, only while it is still
// the stored one: a change or reset committed since the read wins. A rehash
// is not a password change, so changed_at stays.
func rehashCredential(ctx context.Context, q db.Querier, id uuid.UUID, old, hash string) error {
	_, err := q.Exec(ctx, `UPDATE auth_credentials SET password_hash = $3 WHERE principal_id = $1 AND password_hash = $2`, id, old, hash)
	return err
}

// setCredential creates or replaces the principal's password hash. It passes
// the self policy on a pinned connection and the _auth policy without one.
func setCredential(ctx context.Context, q db.Querier, id uuid.UUID, hash string, now time.Time) error {
	_, err := q.Exec(ctx, `
		INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)
		ON CONFLICT (principal_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, changed_at = EXCLUDED.changed_at`,
		id, hash, now)
	return err
}
