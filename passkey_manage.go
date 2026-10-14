package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/session"
)

// ListPasskeys is the principal's passkeys, oldest first. A bare pinned connection is fine.
func (s *Service) ListPasskeys(ctx context.Context, q db.Querier, principal uuid.UUID) ([]Passkey, error) {
	if s.cfg.Passkeys.RPID == "" {
		return nil, ErrPasskeysOff
	}
	rows, err := q.Query(ctx, `SELECT id, label, created_at, last_used_at, data FROM auth_passkeys WHERE principal_id = $1 ORDER BY created_at, id`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RenamePasskey sets the label of one of the caller's passkeys; ErrPasskeyNotFound when the caller has no such passkey.
func (s *Service) RenamePasskey(ctx context.Context, q db.Querier, c *Claims, id uuid.UUID, label string) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if s.cfg.Passkeys.RPID == "" {
		return Result{}, ErrPasskeysOff
	}
	label, ok := renameLabel(label)
	if !ok {
		return Result{Refusal: ErrPasskeyLabel}, nil
	}
	p, err := scanPasskey(q.QueryRow(ctx, `UPDATE auth_passkeys SET label = $3 WHERE id = $1 AND principal_id = $2 RETURNING id, label, created_at, last_used_at, data`, id, c.Subject, label))
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrPasskeyNotFound}, nil
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Passkey: &p}, nil
}

// DeletePasskey removes one of the caller's passkeys and revokes the principal's other sessions (passkey_removed). It needs a sign-in within Passkeys.Reauth; ErrPasskeyNotFound when the caller has no such passkey.
func (s *Service) DeletePasskey(ctx context.Context, q db.Querier, c *Claims, id uuid.UUID, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if s.cfg.Passkeys.RPID == "" {
		return Result{}, ErrPasskeysOff
	}
	m = m.clean()
	now := s.now()
	// WHY: the credential row orders this against another delete, ChangePassword and CompleteReset of the principal; without it two deletes from two sessions deadlock in RevokeOthers.
	if _, _, err := lockCredential(ctx, q, c.Subject); err != nil {
		return Result{}, err
	}
	sess, ok, err := s.freshSession(ctx, q, c, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrReauthRequired}, nil
	}
	p, err := scanPasskey(q.QueryRow(ctx, `DELETE FROM auth_passkeys WHERE id = $1 AND principal_id = $2 RETURNING id, label, created_at, last_used_at, data`, id, c.Subject))
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrPasskeyNotFound}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if err := session.RevokeOthers(ctx, q, c.Subject, c.SessionID, ReasonPasskeyRemoved, now); err != nil {
		return Result{}, err
	}
	if err := s.record(ctx, q, now, SourceDeletePasskey, events.Event{PrincipalID: &c.Subject, SessionID: &c.SessionID,
		ScopeID: sess.ScopeID, Audience: c.Audience, Result: ResultPasskeyRemoved, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	return Result{Passkey: &p}, nil
}

func renameLabel(label string) (string, bool) {
	l := strings.TrimSpace(label)
	if l == "" {
		return "", false
	}
	return passkeyLabel(l, time.Time{})
}

func scanPasskey(row db.Row) (Passkey, error) {
	var p Passkey
	var lastUsed *time.Time
	var data []byte
	if err := row.Scan(&p.ID, &p.Label, &p.CreatedAt, &lastUsed, &data); err != nil {
		return Passkey{}, err
	}
	var cred webauthn.Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return Passkey{}, err
	}
	p.LastUsedAt = lastUsed
	p.BackedUp = cred.Flags.BackupState
	return p, nil
}

func deleteAllPasskeys(ctx context.Context, q db.Querier, principal uuid.UUID) (int, error) {
	n, err := q.Exec(ctx, `DELETE FROM auth_passkeys WHERE principal_id = $1`, principal)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}
