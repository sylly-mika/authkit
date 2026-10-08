// Package events is authkit's sign-in log, auth_events. authkit.Service
// writes it inside the caller's transaction; apps call the Service.
package events

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
)

// Event is one auth_events row: a sign-in attempt or an account change.
type Event struct {
	ID          uuid.UUID
	At          time.Time
	PrincipalID *uuid.UUID
	SessionID   *uuid.UUID
	ScopeID     *uuid.UUID
	Audience    string
	Login       string
	Result      string
	IP          string
	UserAgent   string
}

// Record inserts without RETURNING: on a pinned connection the insert passes
// a self-insert policy only.
func Record(ctx context.Context, q db.Querier, e Event) error {
	_, err := q.Exec(ctx, `
		INSERT INTO auth_events (id, at, principal_id, session_id, audience, scope_id, login, result, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		e.ID, e.At, e.PrincipalID, e.SessionID, e.Audience, e.ScopeID, e.Login, e.Result, e.IP, e.UserAgent)
	return err
}

// Prune deletes the events recorded before before.
func Prune(ctx context.Context, q db.Querier, before time.Time) (int64, error) {
	return q.Exec(ctx, `DELETE FROM auth_events WHERE at < $1`, before)
}

// List is the principal's events, newest first, without the excluded results,
// and their count. Result names never contain a comma (the Service checks).
func List(ctx context.Context, q db.Querier, principal uuid.UUID, exclude []string, limit, offset int) ([]Event, int, error) {
	const where = ` FROM auth_events WHERE principal_id = $1 AND NOT (result = ANY (string_to_array($2, ',')))`
	ex := strings.Join(exclude, ",")
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*)`+where, principal, ex).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := q.Query(ctx, `SELECT id, at, principal_id, session_id, scope_id, audience, login, result, ip, user_agent`+where+
		` ORDER BY at DESC, id LIMIT $3 OFFSET $4`, principal, ex, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.At, &e.PrincipalID, &e.SessionID, &e.ScopeID, &e.Audience, &e.Login, &e.Result, &e.IP, &e.UserAgent); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
