package factor

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/token"
)

// Factor is one auth_second_factors row.
type Factor struct {
	Kind        string
	Secret      []byte
	LastStep    *int64
	CreatedAt   time.Time
	ConfirmedAt *time.Time
}

// Lock takes the principal's second-factor advisory lock until the transaction ends.
func Lock(ctx context.Context, q db.Querier, principal uuid.UUID) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('authkit second factors'), hashtext($1::text))`, principal)
	return err
}

// PutPendingTOTP stores a pending authenticator secret, replacing an unconfirmed one; false when a confirmed one exists.
func PutPendingTOTP(ctx context.Context, q db.Querier, principal uuid.UUID, sealed []byte, now time.Time) (bool, error) {
	n, err := q.Exec(ctx, `
		INSERT INTO auth_second_factors (principal_id, kind, secret, last_step, created_at, confirmed_at)
		VALUES ($1, 'totp', $2, NULL, $3, NULL)
		ON CONFLICT (principal_id, kind) DO UPDATE SET secret = EXCLUDED.secret, last_step = NULL, created_at = EXCLUDED.created_at
		WHERE auth_second_factors.confirmed_at IS NULL`,
		principal, sealed, now)
	return n == 1, err
}

// Load reads one of the principal's factors of a kind, locked for the transaction.
func Load(ctx context.Context, q db.Querier, principal uuid.UUID, kind string) (Factor, bool, error) {
	var f Factor
	err := q.QueryRow(ctx, `
		SELECT kind, secret, last_step, created_at, confirmed_at
		FROM auth_second_factors WHERE principal_id = $1 AND kind = $2 FOR UPDATE`,
		principal, kind).Scan(&f.Kind, &f.Secret, &f.LastStep, &f.CreatedAt, &f.ConfirmedAt)
	if errors.Is(err, db.ErrNoRows) {
		return Factor{}, false, nil
	}
	if err != nil {
		return Factor{}, false, err
	}
	return f, true, nil
}

// Confirm turns on a pending factor, recording the step it accepted when step is not nil.
func Confirm(ctx context.Context, q db.Querier, principal uuid.UUID, kind string, step *int64, now time.Time) (bool, error) {
	n, err := q.Exec(ctx, `
		UPDATE auth_second_factors SET confirmed_at = $3, last_step = $4
		WHERE principal_id = $1 AND kind = $2 AND confirmed_at IS NULL
		AND ($4::bigint IS NULL OR last_step IS NULL OR last_step < $4)`,
		principal, kind, now, step)
	return n == 1, err
}

// AcceptStep records a TOTP step as used, false when it is not later than the last one.
func AcceptStep(ctx context.Context, q db.Querier, principal uuid.UUID, step int64) (bool, error) {
	n, err := q.Exec(ctx, `
		UPDATE auth_second_factors SET last_step = $2
		WHERE principal_id = $1 AND kind = 'totp' AND confirmed_at IS NOT NULL
		AND (last_step IS NULL OR last_step < $2)`,
		principal, step)
	return n == 1, err
}

// ConfirmedKinds lists the principal's confirmed second-factor kinds.
func ConfirmedKinds(ctx context.Context, q db.Querier, principal uuid.UUID) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT kind FROM auth_second_factors WHERE principal_id = $1 AND confirmed_at IS NOT NULL ORDER BY kind`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			return nil, err
		}
		out = append(out, kind)
	}
	return out, rows.Err()
}

// ReplaceRecoveryCodes deletes the principal's recovery codes and stores the given hashes as unused ones.
func ReplaceRecoveryCodes(ctx context.Context, q db.Querier, r io.Reader, principal uuid.UUID, hashes [][]byte, now time.Time) error {
	if _, err := q.Exec(ctx, `DELETE FROM auth_recovery_codes WHERE principal_id = $1`, principal); err != nil {
		return err
	}
	for _, h := range hashes {
		id, err := token.ID(r)
		if err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `INSERT INTO auth_recovery_codes (id, principal_id, code_hash, used_at, created_at) VALUES ($1, $2, $3, NULL, $4)`,
			id, principal, h, now); err != nil {
			return err
		}
	}
	return nil
}

// RecoveryCodesLeft counts the principal's unused recovery codes.
func RecoveryCodesLeft(ctx context.Context, q db.Querier, principal uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NULL`, principal).Scan(&n)
	return n, err
}

// SpendRecoveryCode marks an unused recovery code as used, false when it is not one.
func SpendRecoveryCode(ctx context.Context, q db.Querier, principal uuid.UUID, hash []byte, now time.Time) (bool, error) {
	n, err := q.Exec(ctx, `UPDATE auth_recovery_codes SET used_at = $3 WHERE principal_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		principal, hash, now)
	return n == 1, err
}
