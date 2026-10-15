package passkey

import (
	"context"
	"errors"

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
