// Package session is authkit's auth_sessions SQL. Every function runs on the
// caller's querier; the ones that lock or write are called inside its
// transaction by authkit.Service, which enforces the transaction rule. Apps
// call the Service, not this package.
package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
)

// Session is an auth_sessions row; Current marks the caller's own in a list.
type Session struct {
	ID              uuid.UUID
	PrincipalID     uuid.UUID
	Audience        string
	ScopeID         *uuid.UUID
	IP              string
	UserAgent       string
	AuthenticatedAt time.Time
	CreatedAt       time.Time
	LastSeenAt      *time.Time
	ExpiresAt       time.Time
	// AbsoluteExpiresAt is the cap set at sign-in; nil without one. Every
	// write of ExpiresAt is clamped to it.
	AbsoluteExpiresAt *time.Time
	RevokedAt         *time.Time
	RotatedAt         *time.Time
	Current           bool
}

// Create inserts a new session with its token's hash.
func Create(ctx context.Context, q db.Querier, s Session, tokenHash []byte) error {
	_, err := q.Exec(ctx, `
		INSERT INTO auth_sessions (id, principal_id, audience, scope_id, token_hash, authenticated_at, ip, user_agent, created_at, expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		s.ID, s.PrincipalID, s.Audience, s.ScopeID, tokenHash, s.AuthenticatedAt, s.IP, s.UserAgent, s.CreatedAt, s.ExpiresAt, s.AbsoluteExpiresAt)
	return err
}

// ErrRotationLost means the row stopped carrying the token it was locked
// under: the lock and the guarded UPDATE disagree, which only a bug causes.
var ErrRotationLost = errors.New("authkit: the session changed under its row lock")

const columns = `id, principal_id, audience, scope_id, ip, user_agent, authenticated_at, created_at,
	last_seen_at, expires_at, absolute_expires_at, revoked_at, rotated_at`

func scan(row interface{ Scan(...any) error }) (Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.PrincipalID, &s.Audience, &s.ScopeID, &s.IP, &s.UserAgent, &s.AuthenticatedAt, &s.CreatedAt,
		&s.LastSeenAt, &s.ExpiresAt, &s.AbsoluteExpiresAt, &s.RevokedAt, &s.RotatedAt)
	return s, err
}

// LockForRefresh locks the open session of aud whose current refresh token
// hashes to tokenHash (spec §7 Refresh). Concurrent refreshes of one token
// queue on this row lock; once the winner commits, each loser's re-check of
// token_hash fails and it finds no row (§8.1).
func LockForRefresh(ctx context.Context, q db.Querier, tokenHash []byte, aud string, now time.Time) (Session, error) {
	return scan(q.QueryRow(ctx, `SELECT `+columns+` FROM auth_sessions
		 WHERE token_hash = $1 AND audience = $2 AND revoked_at IS NULL AND expires_at > $3
		   FOR UPDATE`, tokenHash, aud, now))
}

// LockByPrevious locks the unrevoked session whose previous refresh token
// hashes to tokenHash (§8.3).
func LockByPrevious(ctx context.Context, q db.Querier, tokenHash []byte) (Session, error) {
	return scan(q.QueryRow(ctx, `SELECT `+columns+` FROM auth_sessions
		 WHERE prev_token_hash = $1 AND revoked_at IS NULL LIMIT 1 FOR UPDATE`, tokenHash))
}

// Rotate swaps in the next refresh token, keeps the old one's hash for reuse
// detection and slides the expiry (§8.1).
func Rotate(ctx context.Context, q db.Querier, id uuid.UUID, old, next []byte, now, expires time.Time) error {
	n, err := q.Exec(ctx, `
		UPDATE auth_sessions
		   SET prev_token_hash = token_hash, token_hash = $3, rotated_at = $4, expires_at = $5
		 WHERE id = $1 AND token_hash = $2`, id, old, next, now, expires)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrRotationLost
	}
	return nil
}

// ByToken reads the session of aud whose current token hashes to tokenHash,
// whatever its state (Session mode). It takes no lock: Swap's guard decides
// a race.
func ByToken(ctx context.Context, q db.Querier, tokenHash []byte, aud string) (Session, error) {
	return scan(q.QueryRow(ctx, `SELECT `+columns+` FROM auth_sessions WHERE token_hash = $1 AND audience = $2`, tokenHash, aud))
}

// Swap replaces the session token by compare-and-swap (spec §3.5 rule 7):
// only a row that still carries old, unrevoked, takes next, keeps old as the
// previous token and slides. It reports whether this call swapped.
func Swap(ctx context.Context, q db.Querier, id uuid.UUID, old, next []byte, now, expires time.Time) (bool, error) {
	n, err := q.Exec(ctx, `
		UPDATE auth_sessions
		   SET prev_token_hash = token_hash, token_hash = $3, rotated_at = $4, last_seen_at = $4, expires_at = $5
		 WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL`, id, old, next, now, expires)
	return n == 1, err
}

// Slide stamps last_seen_at and moves the idle expiry when last_seen_at is
// unset or not after staleBefore.
func Slide(ctx context.Context, q db.Querier, id uuid.UUID, now, staleBefore, expires time.Time) error {
	_, err := q.Exec(ctx, `
		UPDATE auth_sessions SET last_seen_at = $2, expires_at = $4
		 WHERE id = $1 AND revoked_at IS NULL AND (last_seen_at IS NULL OR last_seen_at <= $3)`, id, now, staleBefore, expires)
	return err
}

// Load reads the principal's session by id, whatever its state.
func Load(ctx context.Context, q db.Querier, id, principal uuid.UUID) (Session, error) {
	return scan(q.QueryRow(ctx, `SELECT `+columns+` FROM auth_sessions WHERE id = $1 AND principal_id = $2`, id, principal))
}

// LockOpen locks the principal's session while it is open, so a concurrent
// revoke waits for the caller's transaction.
func LockOpen(ctx context.Context, q db.Querier, id, principal uuid.UUID, now time.Time) (Session, error) {
	return scan(q.QueryRow(ctx, `SELECT `+columns+` FROM auth_sessions
		 WHERE id = $1 AND principal_id = $2 AND revoked_at IS NULL AND expires_at > $3 FOR UPDATE`, id, principal, now))
}

// Revoke revokes the session for reason unless it is revoked already.
func Revoke(ctx context.Context, q db.Querier, id uuid.UUID, reason string, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE auth_sessions SET revoked_at = $3, revoke_reason = $2 WHERE id = $1 AND revoked_at IS NULL`, id, reason, now)
	return err
}

// RevokeOpen ends one open session of the principal and reports whether it did.
func RevokeOpen(ctx context.Context, q db.Querier, id, principal uuid.UUID, reason string, now time.Time) (bool, error) {
	n, err := q.Exec(ctx, `
		UPDATE auth_sessions SET revoked_at = $4, revoke_reason = $3
		 WHERE id = $1 AND principal_id = $2 AND revoked_at IS NULL AND expires_at > $4`, id, principal, reason, now)
	return n == 1, err
}

// RevokeOthers revokes every unrevoked session of the principal but keep.
func RevokeOthers(ctx context.Context, q db.Querier, principal, keep uuid.UUID, reason string, now time.Time) error {
	_, err := q.Exec(ctx, `
		UPDATE auth_sessions SET revoked_at = $4, revoke_reason = $3
		 WHERE principal_id = $1 AND id <> $2 AND revoked_at IS NULL`, principal, keep, reason, now)
	return err
}

// RevokeAll revokes every unrevoked session of the principal.
func RevokeAll(ctx context.Context, q db.Querier, principal uuid.UUID, reason string, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE auth_sessions SET revoked_at = $3, revoke_reason = $2 WHERE principal_id = $1 AND revoked_at IS NULL`,
		principal, reason, now)
	return err
}

// RevokeOpenAll ends every open session of the principal for reason and
// returns them as they were before.
func RevokeOpenAll(ctx context.Context, q db.Querier, principal uuid.UUID, reason string, now time.Time) ([]Session, error) {
	rows, err := q.Query(ctx, `
		UPDATE auth_sessions SET revoked_at = $3, revoke_reason = $2
		 WHERE principal_id = $1 AND revoked_at IS NULL AND expires_at > $3
		RETURNING `+columns, principal, reason, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SetAuthenticated records now as the session's latest password proof.
func SetAuthenticated(ctx context.Context, q db.Querier, id uuid.UUID, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE auth_sessions SET authenticated_at = $2 WHERE id = $1`, id, now)
	return err
}

// Touch stamps last_seen_at when it is unset or not after staleBefore.
func Touch(ctx context.Context, q db.Querier, id uuid.UUID, now, staleBefore time.Time) error {
	_, err := q.Exec(ctx, `UPDATE auth_sessions SET last_seen_at = $2 WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at <= $3)`,
		id, now, staleBefore)
	return err
}

// ListOpen is the principal's open sessions, newest first, and their count.
func ListOpen(ctx context.Context, q db.Querier, principal uuid.UUID, now time.Time, limit, offset int) ([]Session, int, error) {
	const open = ` FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL AND expires_at > $2`
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*)`+open, principal, now).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := q.Query(ctx, `SELECT `+columns+open+` ORDER BY created_at DESC, id LIMIT $3 OFFSET $4`, principal, now, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

// Prune deletes sessions revoked or expired before before.
func Prune(ctx context.Context, q db.Querier, before time.Time) (int64, error) {
	return q.Exec(ctx, `DELETE FROM auth_sessions WHERE revoked_at < $1 OR expires_at < $1`, before)
}
