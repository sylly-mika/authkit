package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// ceremony is one stored sign-in or link, as Finish reads it back.
type ceremony struct {
	id                     uuid.UUID
	kind, provider         string
	audience               authkit.Audience
	bindingHash, nonceHash []byte
	verifier               string
	principal              uuid.NullUUID
}

func digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func insertCeremony(ctx context.Context, q db.Querier, c ceremony, stateHash []byte, now, expires time.Time) error {
	_, err := q.Exec(ctx, `INSERT INTO auth_ceremonies (id, kind, provider, audience, state_hash, binding_hash, nonce_hash, verifier, principal_id, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		c.id, c.kind, c.provider, string(c.audience), stateHash, c.bindingHash, c.nonceHash, c.verifier, c.principal, now, expires)
	return err
}

func spendCeremony(ctx context.Context, q db.Querier, stateHash []byte, now time.Time) (*ceremony, error) {
	var c ceremony
	var aud string
	err := q.QueryRow(ctx, `UPDATE auth_ceremonies SET spent_at = $2 WHERE state_hash = $1 AND kind IN ('signin', 'link') AND spent_at IS NULL AND expires_at > $2 RETURNING id, kind, provider, audience, binding_hash, nonce_hash, verifier, principal_id`,
		stateHash, now).Scan(&c.id, &c.kind, &c.provider, &aud, &c.bindingHash, &c.nonceHash, &c.verifier, &c.principal)
	if errors.Is(err, db.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.audience = authkit.Audience(aud)
	return &c, nil
}

func insertSignup(ctx context.Context, q db.Querier, id uuid.UUID, ticketHash []byte, s *SignUp, subject string, aud authkit.Audience, now, expires time.Time) error {
	profile, err := json.Marshal(map[string]any{"name": s.Name, "given_name": s.GivenName, "family_name": s.FamilyName, "private_email": s.PrivateEmail})
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO auth_ceremonies (id, kind, provider, audience, state_hash, subject, email, profile, created_at, expires_at) VALUES ($1, 'signup', $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, s.Provider, string(aud), ticketHash, subject, s.Email, string(profile), now, expires)
	return err
}

func findIdentity(ctx context.Context, q db.Querier, provider, subject string) (uuid.UUID, bool, error) {
	var principal uuid.UUID
	err := q.QueryRow(ctx, `SELECT principal_id FROM auth_identities WHERE provider = $1 AND subject = $2`, provider, subject).Scan(&principal)
	if errors.Is(err, db.ErrNoRows) {
		return uuid.UUID{}, false, nil
	}
	if err != nil {
		return uuid.UUID{}, false, err
	}
	return principal, true, nil
}

func touchIdentity(ctx context.Context, q db.Querier, provider, subject string, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE auth_identities SET last_used_at = $3 WHERE provider = $1 AND subject = $2`, provider, subject, now)
	return err
}
