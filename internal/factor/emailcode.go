package factor

import (
	"context"
	"crypto/hmac"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/token"
)

// PurposeSignIn names the email code of a second-step sign-in.
const PurposeSignIn = "sign_in"

// PurposeEnable names the email code that turns the email factor on.
const PurposeEnable = "enable"

// PurposeProof names the email code given as proof to disable a factor.
const PurposeProof = "proof"

// EmailRules are the limits on one emailed code row.
type EmailRules struct {
	TTL, ResendEvery   time.Duration
	MaxSends, MaxTries int
}

// CodeCheck is the outcome of checking an emailed code.
type CodeCheck int

// The outcomes of CheckEmailCode.
const (
	CodeOK CodeCheck = iota
	CodeBad
	CodeEnded
)

// RequestEmailCode stores or replaces the emailed code row of a principal and purpose.
func RequestEmailCode(ctx context.Context, q db.Querier, r io.Reader, principal uuid.UUID, purpose string, now time.Time, rules EmailRules) (id uuid.UUID, exp time.Time, retryAfter time.Duration, err error) {
	id, err = token.ID(r)
	if err != nil {
		return uuid.Nil, time.Time{}, 0, err
	}
	if _, err := q.Exec(ctx, `INSERT INTO auth_email_codes (principal_id, purpose, id, code_hash, tries, sends, last_sent_at, expires_at) VALUES ($1, $2, $3, NULL, 0, 1, $4, $4) ON CONFLICT (principal_id, purpose) DO NOTHING`, principal, purpose, id, now); err != nil {
		return uuid.Nil, time.Time{}, 0, err
	}
	var sends int
	var lastSent, expires time.Time
	if err := q.QueryRow(ctx, `SELECT sends, last_sent_at, expires_at FROM auth_email_codes WHERE principal_id = $1 AND purpose = $2 FOR UPDATE`, principal, purpose).Scan(&sends, &lastSent, &expires); err != nil {
		return uuid.Nil, time.Time{}, 0, err
	}
	next := 1
	if expires.After(now) {
		if sends >= rules.MaxSends {
			return uuid.Nil, time.Time{}, expires.Sub(now), nil
		}
		if now.Before(lastSent.Add(rules.ResendEvery)) {
			return uuid.Nil, time.Time{}, lastSent.Add(rules.ResendEvery).Sub(now), nil
		}
		next = sends + 1
	}
	exp = now.Add(rules.TTL)
	if _, err := q.Exec(ctx, `UPDATE auth_email_codes SET id = $3, code_hash = NULL, tries = 0, sends = $6, last_sent_at = $4, expires_at = $5 WHERE principal_id = $1 AND purpose = $2`, principal, purpose, id, now, exp, next); err != nil {
		return uuid.Nil, time.Time{}, 0, err
	}
	return id, exp, 0, nil
}

// MintEmailCode makes the 6-digit code of a stored row and returns it with its principal and purpose.
func MintEmailCode(ctx context.Context, q db.Querier, r io.Reader, key []byte, id uuid.UUID, now time.Time, maxTries int) (principal uuid.UUID, purpose, code string, exp time.Time, ok bool, err error) {
	err = q.QueryRow(ctx, `SELECT principal_id, purpose, expires_at FROM auth_email_codes WHERE id = $1 AND expires_at > $2 AND tries < $3 FOR UPDATE`, id, now, maxTries).Scan(&principal, &purpose, &exp)
	if errors.Is(err, db.ErrNoRows) {
		return uuid.Nil, "", "", time.Time{}, false, nil
	}
	if err != nil {
		return uuid.Nil, "", "", time.Time{}, false, err
	}
	code, err = NewEmailCode(r)
	if err != nil {
		return uuid.Nil, "", "", time.Time{}, false, err
	}
	if _, err := q.Exec(ctx, `UPDATE auth_email_codes SET code_hash = $2 WHERE id = $1`, id, HashCode(key, principal, purpose, code)); err != nil {
		return uuid.Nil, "", "", time.Time{}, false, err
	}
	return principal, purpose, code, exp, true, nil
}

// CheckEmailCode compares a code with the stored row and spends it on a match.
func CheckEmailCode(ctx context.Context, q db.Querier, key []byte, principal uuid.UUID, purpose, code string, now time.Time, maxTries int) (CodeCheck, error) {
	var hash []byte
	var tries int
	err := q.QueryRow(ctx, `SELECT code_hash, tries FROM auth_email_codes WHERE principal_id = $1 AND purpose = $2 AND expires_at > $3 FOR UPDATE`, principal, purpose, now).Scan(&hash, &tries)
	if errors.Is(err, db.ErrNoRows) {
		return CodeEnded, nil
	}
	if err != nil {
		return CodeEnded, err
	}
	if hash == nil || tries >= maxTries {
		return CodeEnded, nil
	}
	if hmac.Equal(hash, HashCode(key, principal, purpose, strings.TrimSpace(code))) {
		if _, err := q.Exec(ctx, `DELETE FROM auth_email_codes WHERE principal_id = $1 AND purpose = $2`, principal, purpose); err != nil {
			return CodeEnded, err
		}
		return CodeOK, nil
	}
	if _, err := q.Exec(ctx, `UPDATE auth_email_codes SET tries = tries + 1 WHERE principal_id = $1 AND purpose = $2`, principal, purpose); err != nil {
		return CodeEnded, err
	}
	return CodeBad, nil
}

// DropEmailCodes removes every emailed code row of a principal.
func DropEmailCodes(ctx context.Context, q db.Querier, principal uuid.UUID) error {
	_, err := q.Exec(ctx, `DELETE FROM auth_email_codes WHERE principal_id = $1`, principal)
	return err
}
