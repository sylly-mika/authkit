// Package ceremony stores WebAuthn ceremonies: SessionData under the hash of a random id, spent once.
package ceremony

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/token"
)

// Kind is the purpose of a ceremony: register, login or reverify.
type Kind string

const (
	KindRegister Kind = "register"
	KindLogin    Kind = "login"
	KindReverify Kind = "reverify"
)

// Create saves a ceremony's SessionData under the hash of a new random id and returns the id and its expiry.
func Create(ctx context.Context, q db.Querier, r io.Reader, kind Kind, aud string, principal, session *uuid.UUID, data webauthn.SessionData, now time.Time, ttl time.Duration) (id string, exp time.Time, err error) {
	if err := db.RequireTx(q); err != nil {
		return "", time.Time{}, err
	}
	rowID, err := token.ID(r)
	if err != nil {
		return "", time.Time{}, err
	}
	raw, hash, err := token.New(r)
	if err != nil {
		return "", time.Time{}, err
	}
	body, err := json.Marshal(data)
	if err != nil {
		return "", time.Time{}, err
	}
	exp = now.Add(ttl)
	if _, err := q.Exec(ctx, `
		INSERT INTO auth_passkey_ceremonies (id, ceremony_hash, kind, audience, principal_id, session_id, data, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, ($7::text)::jsonb, $8)`,
		rowID, hash, string(kind), aud, principal, session, string(body), exp); err != nil {
		return "", time.Time{}, err
	}
	return raw, exp, nil
}

// Spend uses a ceremony exactly once, only for its kind, audience, principal and session and before it expires; false is every refusal.
func Spend(ctx context.Context, q db.Querier, kind Kind, aud, id string, principal, session *uuid.UUID, now time.Time) (webauthn.SessionData, bool, error) {
	if err := db.RequireTx(q); err != nil {
		return webauthn.SessionData{}, false, err
	}
	var text string
	err := q.QueryRow(ctx, `
		UPDATE auth_passkey_ceremonies SET used_at = $6
		 WHERE ceremony_hash = $1 AND kind = $2 AND audience = $3
		   AND principal_id IS NOT DISTINCT FROM $4 AND session_id IS NOT DISTINCT FROM $5
		   AND used_at IS NULL AND expires_at > $6
		RETURNING data::text`, token.Hash(id), string(kind), aud, principal, session, now).Scan(&text)
	if errors.Is(err, db.ErrNoRows) {
		return webauthn.SessionData{}, false, nil
	}
	if err != nil {
		return webauthn.SessionData{}, false, err
	}
	var data webauthn.SessionData
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return webauthn.SessionData{}, false, err
	}
	return data, true, nil
}

// Prune deletes ceremonies that expired before before.
func Prune(ctx context.Context, q db.Querier, before time.Time) (int64, error) {
	if err := db.RequireTx(q); err != nil {
		return 0, err
	}
	return q.Exec(ctx, `DELETE FROM auth_passkey_ceremonies WHERE expires_at < $1`, before)
}
