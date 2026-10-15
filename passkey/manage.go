package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// ListPasskeys is the principal's passkeys, oldest first. A bare pinned connection is fine.
func (mod *Module) ListPasskeys(ctx context.Context, q db.Querier, principal uuid.UUID) ([]authkit.Passkey, error) {
	if mod.rules.RPID == "" {
		return nil, authkit.ErrPasskeysOff
	}
	rows, err := q.Query(ctx, `SELECT id, label, created_at, last_used_at, data FROM auth_passkeys WHERE principal_id = $1 ORDER BY created_at, id`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authkit.Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RenamePasskey sets the label of one of the caller's passkeys; authkit.ErrPasskeyNotFound when the caller has no such passkey.
func (mod *Module) RenamePasskey(ctx context.Context, q db.Querier, c *authkit.Claims, id uuid.UUID, label string) (authkit.Result, error) {
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if mod.rules.RPID == "" {
		return authkit.Result{}, authkit.ErrPasskeysOff
	}
	label, ok := renameLabel(label)
	if !ok {
		return authkit.Result{Refusal: authkit.ErrPasskeyLabel}, nil
	}
	p, err := scanPasskey(q.QueryRow(ctx, `UPDATE auth_passkeys SET label = $3 WHERE id = $1 AND principal_id = $2 RETURNING id, label, created_at, last_used_at, data`, id, c.Subject, label))
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrPasskeyNotFound}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Passkey: &p}, nil
}

// DeletePasskey removes one of the caller's passkeys and revokes the principal's other sessions (passkey_removed). It needs a sign-in within Passkeys.Reauth; authkit.ErrPasskeyNotFound when the caller has no such passkey.
func (mod *Module) DeletePasskey(ctx context.Context, q db.Querier, c *authkit.Claims, id uuid.UUID, m authkit.Meta) (authkit.Result, error) {
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if mod.rules.RPID == "" {
		return authkit.Result{}, authkit.ErrPasskeysOff
	}
	m = m.Clean()
	now := mod.core.Now()
	// WHY: the credential row orders this against another delete, ChangePassword and CompleteReset of the principal; without it two deletes from two sessions deadlock in RevokeOthers.
	if _, _, err := lockCredential(ctx, q, c.Subject); err != nil {
		return authkit.Result{}, err
	}
	sess, ok, err := mod.core.Fresh(ctx, q, c, mod.rules.Reauth, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrReauthRequired}, nil
	}
	p, err := scanPasskey(q.QueryRow(ctx, `DELETE FROM auth_passkeys WHERE id = $1 AND principal_id = $2 RETURNING id, label, created_at, last_used_at, data`, id, c.Subject))
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrPasskeyNotFound}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	if err := mod.core.RevokeOthers(ctx, q, c.Subject, c.SessionID, authkit.ReasonPasskeyRemoved, now); err != nil {
		return authkit.Result{}, err
	}
	if err := mod.core.Record(ctx, q, authkit.SourceDeletePasskey, authkit.Event{At: now, PrincipalID: &c.Subject, SessionID: &c.SessionID,
		ScopeID: sess.ScopeID, Audience: c.Audience, Result: authkit.ResultPasskeyRemoved, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Passkey: &p}, nil
}

func renameLabel(label string) (string, bool) {
	l := strings.TrimSpace(label)
	if l == "" {
		return "", false
	}
	return passkeyLabel(l, time.Time{})
}

func scanPasskey(row db.Row) (authkit.Passkey, error) {
	var p authkit.Passkey
	var lastUsed *time.Time
	var data []byte
	if err := row.Scan(&p.ID, &p.Label, &p.CreatedAt, &lastUsed, &data); err != nil {
		return authkit.Passkey{}, err
	}
	var cred webauthn.Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return authkit.Passkey{}, err
	}
	p.LastUsedAt = lastUsed
	p.BackedUp = cred.Flags.BackupState
	return p, nil
}
