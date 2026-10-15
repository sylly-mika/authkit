package register

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/onetime"
)

// Mail is what the app's worker puts in the activation email.
type Mail struct {
	To, Raw   string
	Payload   json.RawMessage
	ExpiresAt time.Time
}

// ErrNothingToSend says the registration or its link is gone, so the mail job drops.
var ErrNothingToSend = errors.New("register: registration gone")

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

// Mint returns the raw activation token for a TokenID at send time. Its ExpiresAt is capped at the registration's expiry; ErrNothingToSend when the registration or its link is gone.
func (m *Module) Mint(ctx context.Context, q db.Querier, tokenID uuid.UUID) (Mail, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Mail{}, err
	}
	now := m.core.Now()
	var owner uuid.UUID
	err := q.QueryRow(ctx, `SELECT owner_id FROM auth_tokens WHERE id = $1 AND purpose = $2`,
		tokenID, authkit.PurposeRegister).Scan(&owner)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Mail{}, ErrNothingToSend
	case err != nil:
		return Mail{}, err
	}
	var email, payload string
	var expires time.Time
	err = q.QueryRow(ctx, `SELECT email, payload::text, expires_at FROM auth_registrations WHERE id = $1 AND expires_at > $2 FOR UPDATE`,
		owner, now).Scan(&email, &payload, &expires)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Mail{}, ErrNothingToSend
	case err != nil:
		return Mail{}, err
	}
	mt, err := m.links.Mint(ctx, q, tokenID)
	var gone onetime.ErrGone
	switch {
	case errors.Is(err, onetime.ErrUnknown), errors.As(err, &gone):
		return Mail{}, ErrNothingToSend
	case err != nil:
		return Mail{}, err
	}
	expiresAt := mt.ExpiresAt
	if expires.Before(expiresAt) {
		expiresAt = expires
	}
	return Mail{To: email, Raw: mt.Raw, Payload: json.RawMessage(payload), ExpiresAt: expiresAt}, nil
}
