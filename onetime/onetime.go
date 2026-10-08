// Package onetime is authkit's one-time links (spec §5.2): rows that hold only
// a token's hash, one live row per owner and purpose, minted at send time and
// spent once. No raw token is stored or queued.
package onetime

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/token"
)

// State is where a token stands: live, used, revoked or expired.
type State string

const (
	StateLive    State = "live"
	StateUsed    State = "used"
	StateRevoked State = "revoked"
	StateExpired State = "expired"
)

// ErrUnknown is a token or row id the store does not know; Spend also
// answers it for a token of another purpose.
var ErrUnknown = errors.New("authkit: unknown token")

// ErrGone is a token that exists but can no longer be minted or spent.
type ErrGone struct{ State State }

func (e ErrGone) Error() string { return "authkit: token " + string(e.State) }

// Token is a one-time link's row, without its hash.
type Token struct {
	ID        uuid.UUID
	Purpose   string
	Owner     uuid.UUID
	State     State
	ExpiresAt time.Time
}

// Minted is a row's fresh link: Raw goes into the email and nowhere else.
type Minted struct {
	Token
	Raw string
}

// Store is the auth_tokens SQL; an app reaches it through Service.OneTime.
type Store struct {
	now  func() time.Time
	rand io.Reader
}

// New builds a Store on the given clock and random source.
func New(now func() time.Time, rand io.Reader) *Store { return &Store{now: now, rand: rand} }

// Lock takes the transaction-scoped advisory lock Create takes, for a caller
// that reads before it creates (RequestReset's cap).
func (s *Store) Lock(ctx context.Context, q db.Querier, purpose string, owner uuid.UUID) error {
	if err := db.RequireTx(q); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2::text))`, purpose, owner)
	return err
}

// Create supersedes the owner's live row for purpose, whose link becomes
// unknown and whose queued mail can no longer mint, and inserts an unsent row.
// Concurrent Creates for one owner and purpose queue on the advisory lock, so
// both succeed. The caller enqueues its email in the same transaction.
func (s *Store) Create(ctx context.Context, q db.Querier, purpose string, owner uuid.UUID, ttl time.Duration) (uuid.UUID, error) {
	if err := s.Lock(ctx, q, purpose, owner); err != nil {
		return uuid.Nil, err
	}
	now := s.now()
	if _, err := q.Exec(ctx, `
		UPDATE auth_tokens SET revoked_at = $3, token_hash = NULL
		 WHERE purpose = $1 AND owner_id = $2 AND used_at IS NULL AND revoked_at IS NULL`, purpose, owner, now); err != nil {
		return uuid.Nil, err
	}
	id, err := token.ID(s.rand)
	if err != nil {
		return uuid.Nil, err
	}
	_, err = q.Exec(ctx, `
		INSERT INTO auth_tokens (id, purpose, owner_id, ttl, expires_at, created_at)
		VALUES ($1, $2, $3, make_interval(secs => $4), $5::timestamptz + make_interval(secs => $4), $5)`,
		id, purpose, owner, ttl.Seconds(), now)
	return id, err
}

// CreatedSince counts the owner's rows of purpose created after since, live or not.
func (s *Store) CreatedSince(ctx context.Context, q db.Querier, purpose string, owner uuid.UUID, since time.Time) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM auth_tokens WHERE purpose = $1 AND owner_id = $2 AND created_at > $3`,
		purpose, owner, since).Scan(&n)
	return n, err
}

// Mint is the send-time step: it stores a fresh token's hash on an unused,
// unrevoked row, restarts its expiry by the row's ttl and returns the raw
// token. A re-mint replaces the row's earlier hash.
func (s *Store) Mint(ctx context.Context, q db.Querier, id uuid.UUID) (Minted, error) {
	if err := db.RequireTx(q); err != nil {
		return Minted{}, err
	}
	var m Minted
	var used, revoked bool
	err := q.QueryRow(ctx, `
		SELECT purpose, owner_id, used_at IS NOT NULL, revoked_at IS NOT NULL
		  FROM auth_tokens WHERE id = $1 FOR UPDATE`, id).Scan(&m.Purpose, &m.Owner, &used, &revoked)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Minted{}, ErrUnknown
	case err != nil:
		return Minted{}, err
	case used:
		return Minted{}, ErrGone{State: StateUsed}
	case revoked:
		return Minted{}, ErrGone{State: StateRevoked}
	}
	raw, hash, err := token.New(s.rand)
	if err != nil {
		return Minted{}, err
	}
	if err := q.QueryRow(ctx, `UPDATE auth_tokens SET token_hash = $2, expires_at = $3::timestamptz + ttl WHERE id = $1 RETURNING expires_at`,
		id, hash, s.now()).Scan(&m.ExpiresAt); err != nil {
		return Minted{}, err
	}
	m.ID, m.State, m.Raw = id, StateLive, raw
	return m, nil
}

// Peek finds any row carrying the token's hash, spent, revoked and expired
// ones included; ErrUnknown when none does.
func (s *Store) Peek(ctx context.Context, q db.Querier, raw string) (Token, error) {
	return s.peek(ctx, q, raw, s.now())
}

func (s *Store) peek(ctx context.Context, q db.Querier, raw string, now time.Time) (Token, error) {
	var t Token
	var used, revoked *time.Time
	err := q.QueryRow(ctx, `SELECT id, purpose, owner_id, expires_at, used_at, revoked_at FROM auth_tokens WHERE token_hash = $1`,
		token.Hash(raw)).Scan(&t.ID, &t.Purpose, &t.Owner, &t.ExpiresAt, &used, &revoked)
	if errors.Is(err, db.ErrNoRows) {
		return Token{}, ErrUnknown
	}
	if err != nil {
		return Token{}, err
	}
	t.State = state(used, revoked, t.ExpiresAt, now)
	return t, nil
}

func state(used, revoked *time.Time, expires, now time.Time) State {
	switch {
	case used != nil:
		return StateUsed
	case revoked != nil:
		return StateRevoked
	case !expires.After(now):
		return StateExpired
	}
	return StateLive
}

// Spend uses a live token of purpose exactly once (spec §8.2). The guarded
// UPDATE is the whole decision: of any number of concurrent spends, one
// matches and the rest re-check a spent row and match nothing. A refused
// spend writes nothing; a peek at the same instant then decides unknown (no
// row, or a row of another purpose) or gone.
func (s *Store) Spend(ctx context.Context, q db.Querier, raw, purpose string) (Token, error) {
	if err := db.RequireTx(q); err != nil {
		return Token{}, err
	}
	now := s.now()
	t := Token{Purpose: purpose, State: StateUsed}
	err := q.QueryRow(ctx, `
		UPDATE auth_tokens SET used_at = $3
		 WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $3
		RETURNING id, owner_id, expires_at`, token.Hash(raw), purpose, now).Scan(&t.ID, &t.Owner, &t.ExpiresAt)
	if err == nil {
		return t, nil
	}
	if !errors.Is(err, db.ErrNoRows) {
		return Token{}, err
	}
	found, err := s.peek(ctx, q, raw, now)
	switch {
	case errors.Is(err, ErrUnknown):
		return Token{}, ErrUnknown
	case err != nil:
		return Token{}, err
	case found.Purpose != purpose:
		return Token{}, ErrUnknown
	}
	return Token{}, ErrGone{State: found.State}
}

// Revoke closes the owner's live row for purpose and keeps its hash, so its
// link answers revoked (an app revoking or deleting what the link was for).
func (s *Store) Revoke(ctx context.Context, q db.Querier, purpose string, owner uuid.UUID) error {
	if err := db.RequireTx(q); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		UPDATE auth_tokens SET revoked_at = $3
		 WHERE purpose = $1 AND owner_id = $2 AND used_at IS NULL AND revoked_at IS NULL`, purpose, owner, s.now())
	return err
}

// Prune deletes rows used, revoked or expired before before.
func (s *Store) Prune(ctx context.Context, q db.Querier, before time.Time) (int64, error) {
	if err := db.RequireTx(q); err != nil {
		return 0, err
	}
	return q.Exec(ctx, `DELETE FROM auth_tokens WHERE used_at < $1 OR revoked_at < $1 OR expires_at < $1`, before)
}
