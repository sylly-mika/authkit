package register

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// CountMail counts one mail to email and returns how long to wait when over the cap. The count is kept whether or not the mail goes, so a refused send still counts toward the cap.
func (m *Module) CountMail(ctx context.Context, q db.Querier, aud authkit.Audience, email string) (time.Duration, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return 0, err
	}
	now := m.core.Now()
	n := authkit.Normalize(email)
	key := sha256.Sum256([]byte(n))
	if _, err := q.Exec(ctx, `
		INSERT INTO auth_mail_counts AS c (audience, email_key, window_started_at, sent)
		VALUES ($1, $2, $3, 1)
		ON CONFLICT (audience, email_key) DO UPDATE SET
		  window_started_at = CASE WHEN c.window_started_at <= $4 THEN EXCLUDED.window_started_at ELSE c.window_started_at END,
		  sent = CASE WHEN c.window_started_at <= $4 THEN 1 ELSE c.sent + 1 END`,
		string(aud), key[:], now, now.Add(-m.r.MailWindow)); err != nil {
		return 0, err
	}
	var started time.Time
	var sent int
	if err := q.QueryRow(ctx, `SELECT window_started_at, sent FROM auth_mail_counts WHERE audience = $1 AND email_key = $2`,
		string(aud), key[:]).Scan(&started, &sent); err != nil {
		return 0, err
	}
	if sent > m.r.MailCap {
		return started.Add(m.r.MailWindow).Sub(now), nil
	}
	return 0, nil
}
