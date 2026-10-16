package authkit

import (
	"context"
	"slices"

	"github.com/sylly-mika/authkit/db"
)

// Forgotten counts what Forget deleted and names the providers the principal had linked.
type Forgotten struct {
	Sessions, Passkeys, Identities int
	Providers                      []string
}

// Forget deletes every authkit row that belongs to p, in every audience, inside the caller's transaction.
func (s *Service) Forget(ctx context.Context, q db.Querier, p Principal) (Forgotten, error) {
	q = s.names.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Forgotten{}, err
	}
	login := Normalize(p.Login)
	key := s.throttleKey(login)
	// WHY: rows lock in the order the invite accept and the email-change confirm take
	// them (their own row, then the token), so a racing one waits instead of deadlocking.
	steps := []struct {
		query string
		args  []any
	}{
		{`SELECT id FROM auth_invites WHERE email = $1 ORDER BY id FOR UPDATE`, []any{login}},
		{`DELETE FROM auth_email_changes WHERE principal_id = $1`, []any{p.ID}},
		{`DELETE FROM auth_tokens WHERE owner_id = $1 OR (purpose = $2 AND owner_id IN (SELECT id FROM auth_invites WHERE email = $3))`, []any{p.ID, PurposeInvite, login}},
		{`DELETE FROM auth_invites WHERE email = $1`, []any{login}},
		{`DELETE FROM auth_registrations WHERE email = $1`, []any{login}},
		{`DELETE FROM auth_ceremonies WHERE principal_id = $1`, []any{p.ID}},
		// WHY: passkey ceremonies with a principal always have a session and go with it
		// (the CHECK, then ON DELETE CASCADE from auth_sessions).
		{`DELETE FROM auth_second_step_challenges WHERE principal_id = $1`, []any{p.ID}},
		{`DELETE FROM auth_email_codes WHERE principal_id = $1`, []any{p.ID}},
		{`DELETE FROM auth_recovery_codes WHERE principal_id = $1`, []any{p.ID}},
		{`DELETE FROM auth_second_factors WHERE principal_id = $1`, []any{p.ID}},
		{`DELETE FROM auth_credentials WHERE principal_id = $1`, []any{p.ID}},
		{`DELETE FROM auth_throttle WHERE login = $1`, []any{key}},
	}
	for _, st := range steps {
		if _, err := q.Exec(ctx, st.query, st.args...); err != nil {
			return Forgotten{}, err
		}
	}
	var out Forgotten
	passkeys, err := deleteAllPasskeys(ctx, q, p.ID)
	if err != nil {
		return Forgotten{}, err
	}
	out.Passkeys = passkeys
	rows, err := q.Query(ctx, "DELETE FROM auth_identities WHERE principal_id = $1 RETURNING provider", p.ID)
	if err != nil {
		return Forgotten{}, err
	}
	for rows.Next() {
		var provider string
		if err := rows.Scan(&provider); err != nil {
			rows.Close()
			return Forgotten{}, err
		}
		out.Providers = append(out.Providers, provider)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Forgotten{}, err
	}
	if err := rows.Close(); err != nil {
		return Forgotten{}, err
	}
	slices.Sort(out.Providers)
	out.Identities = len(out.Providers)
	if s.cfg.EventRetention < 0 {
		if _, err := q.Exec(ctx, `DELETE FROM auth_events WHERE principal_id = $1`, p.ID); err != nil {
			return Forgotten{}, err
		}
	} else if _, err := q.Exec(ctx, `UPDATE auth_events SET principal_id = NULL, session_id = NULL WHERE principal_id = $1`, p.ID); err != nil {
		return Forgotten{}, err
	}
	sessions, err := q.Exec(ctx, `DELETE FROM auth_sessions WHERE principal_id = $1`, p.ID)
	if err != nil {
		return Forgotten{}, err
	}
	out.Sessions = int(sessions)
	return out, nil
}
