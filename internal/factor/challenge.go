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

// Challenge is one unspent second-step challenge, as LockChallenge reads it.
type Challenge struct {
	ID          uuid.UUID
	PrincipalID uuid.UUID
	Origin      string
	ThrottleKey string
	Tries       int
}

// CreateChallenge stores a new second-step challenge for principal and returns its raw token and expiry.
func CreateChallenge(ctx context.Context, q db.Querier, r io.Reader, principal uuid.UUID, aud, origin, throttleKey string, now time.Time, ttl time.Duration) (raw string, exp time.Time, err error) {
	if err := db.RequireTx(q); err != nil {
		return "", time.Time{}, err
	}
	id, err := token.ID(r)
	if err != nil {
		return "", time.Time{}, err
	}
	raw, hash, err := token.New(r)
	if err != nil {
		return "", time.Time{}, err
	}
	exp = now.Add(ttl)
	if _, err := q.Exec(ctx, `INSERT INTO auth_second_step_challenges (id, challenge_hash, principal_id, audience, origin, throttle_key, tries, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8)`,
		id, hash, principal, aud, origin, throttleKey, now, exp); err != nil {
		return "", time.Time{}, err
	}
	return raw, exp, nil
}

// LockChallenge locks the unspent, unexpired challenge of aud that raw names, with fewer than maxTries wrong codes; false when there is none.
func LockChallenge(ctx context.Context, q db.Querier, raw, aud string, now time.Time, maxTries int) (Challenge, bool, error) {
	if err := db.RequireTx(q); err != nil {
		return Challenge{}, false, err
	}
	var ch Challenge
	err := q.QueryRow(ctx, `SELECT id, principal_id, origin, throttle_key, tries FROM auth_second_step_challenges
		WHERE challenge_hash = $1 AND audience = $2 AND used_at IS NULL AND expires_at > $3 AND tries < $4 FOR UPDATE`,
		token.Hash(raw), aud, now, maxTries).Scan(&ch.ID, &ch.PrincipalID, &ch.Origin, &ch.ThrottleKey, &ch.Tries)
	if errors.Is(err, db.ErrNoRows) {
		return Challenge{}, false, nil
	}
	if err != nil {
		return Challenge{}, false, err
	}
	return ch, true, nil
}

// FailChallenge counts one wrong code on the challenge.
func FailChallenge(ctx context.Context, q db.Querier, id uuid.UUID) error {
	if err := db.RequireTx(q); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE auth_second_step_challenges SET tries = tries + 1 WHERE id = $1`, id)
	return err
}

// SpendChallenge marks the challenge used at now, so it cannot be answered again.
func SpendChallenge(ctx context.Context, q db.Querier, id uuid.UUID, now time.Time) error {
	if err := db.RequireTx(q); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE auth_second_step_challenges SET used_at = $2 WHERE id = $1`, id, now)
	return err
}

// PruneChallenges deletes the second-step challenges that expired before before, used or not.
func PruneChallenges(ctx context.Context, q db.Querier, before time.Time) (int64, error) {
	if err := db.RequireTx(q); err != nil {
		return 0, err
	}
	return q.Exec(ctx, `DELETE FROM auth_second_step_challenges WHERE expires_at < $1`, before)
}
