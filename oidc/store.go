package oidc

import (
	"context"
	"crypto/sha256"
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
