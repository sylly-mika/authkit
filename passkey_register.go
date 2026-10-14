package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/internal/ceremony"
	"github.com/sylly-mika/authkit/internal/token"
	"github.com/sylly-mika/authkit/session"
)

// BeginPasskeyRegistration starts adding a passkey for a signed-in principal with a password and a recent sign-in, and returns the options for the browser.
func (s *Service) BeginPasskeyRegistration(ctx context.Context, q db.Querier, c *Claims, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if s.cfg.Passkeys.RPID == "" {
		return Result{}, ErrPasskeysOff
	}
	now := s.now()
	_, has, err := credentialOf(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if !has {
		return Result{Refusal: ErrNoPassword}, nil
	}
	sess, ok, err := s.freshSession(ctx, q, c, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrReauthRequired}, nil
	}
	aud := Audience(sess.Audience)
	rp, ok, err := s.relyingParty(aud)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrPasskeyInvalid}, nil
	}
	n, err := countPasskeys(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if n >= s.cfg.Passkeys.Max {
		return Result{Refusal: ErrPasskeyLimit}, nil
	}
	p, err := s.principals.ByID(ctx, q, c.Subject, aud)
	if err != nil {
		return Result{}, err
	}
	exclude, err := passkeyExclusions(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	creation, data, err := rp.BeginRegistration(passkeyUser{p: p}, webauthn.WithExclusions(exclude))
	if err != nil {
		return Result{}, err
	}
	id, exp, err := ceremony.Create(ctx, q, s.cfg.Rand, ceremony.KindRegister, string(aud), &c.Subject, &sess.ID, *data, now, s.cfg.Passkeys.CeremonyTTL)
	if err != nil {
		return Result{}, err
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		return Result{}, err
	}
	return Result{Principal: p, Session: &sess, Ceremony: &Ceremony{ID: id, Options: opts, ExpiresAt: exp}}, nil
}

// FinishPasskeyRegistration stores the passkey the browser created for a begun ceremony and records a passkey_added event.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, q db.Querier, c *Claims, ceremonyID string, response []byte, label string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if s.cfg.Passkeys.RPID == "" {
		return Result{}, ErrPasskeysOff
	}
	m = m.clean()
	label, ok := passkeyLabel(label, s.now())
	if !ok {
		return Result{Refusal: ErrPasskeyLabel}, nil
	}
	now := s.now()
	_, has, err := lockCredential(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if !has {
		return Result{Refusal: ErrNoPassword}, nil
	}
	sess, ok, err := s.freshSession(ctx, q, c, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrReauthRequired}, nil
	}
	aud := Audience(sess.Audience)
	rp, ok, err := s.relyingParty(aud)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrPasskeyInvalid}, nil
	}
	n, err := countPasskeys(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if n >= s.cfg.Passkeys.Max {
		return Result{Refusal: ErrPasskeyLimit}, nil
	}
	data, ok, err := ceremony.Spend(ctx, q, ceremony.KindRegister, string(aud), ceremonyID, &c.Subject, &sess.ID, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrPasskeyInvalid}, nil
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Result{Refusal: ErrPasskeyInvalid}, nil
	}
	p, err := s.principals.ByID(ctx, q, c.Subject, aud)
	if err != nil {
		return Result{}, err
	}
	cred, err := rp.CreateCredential(passkeyUser{p: p}, data, parsed)
	if err != nil {
		return Result{Refusal: ErrPasskeyInvalid}, nil
	}
	known, err := credentialKnown(ctx, q, cred.ID)
	if err != nil {
		return Result{}, err
	}
	if known {
		return Result{Refusal: ErrPasskeyExists}, nil
	}
	id, err := token.ID(s.cfg.Rand)
	if err != nil {
		return Result{}, err
	}
	pk := Passkey{ID: id, Label: label, CreatedAt: now, BackedUp: cred.Flags.BackupState}
	inserted, err := insertPasskey(ctx, q, pk, c.Subject, cred)
	if err != nil {
		return Result{}, err
	}
	if !inserted {
		return Result{Refusal: ErrPasskeyExists}, nil
	}
	if err := s.record(ctx, q, now, SourcePasskeyRegister, events.Event{PrincipalID: &p.ID, SessionID: &sess.ID,
		ScopeID: sess.ScopeID, Audience: sess.Audience, Login: p.Login, Result: ResultPasskeyAdded, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	return Result{Principal: p, Session: &sess, Passkey: &pk}, nil
}

func (s *Service) freshSession(ctx context.Context, q db.Querier, c *Claims, now time.Time) (session.Session, bool, error) {
	sess, err := session.LockOpen(ctx, q, c.SessionID, c.Subject, now)
	if errors.Is(err, db.ErrNoRows) {
		return session.Session{}, false, nil
	}
	if err != nil {
		return session.Session{}, false, err
	}
	if now.Sub(sess.AuthenticatedAt) > s.cfg.Passkeys.Reauth {
		return session.Session{}, false, nil
	}
	return sess, true, nil
}

func countPasskeys(ctx context.Context, q db.Querier, principal uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM auth_passkeys WHERE principal_id = $1`, principal).Scan(&n)
	return n, err
}

func passkeyExclusions(ctx context.Context, q db.Querier, principal uuid.UUID) ([]protocol.CredentialDescriptor, error) {
	rows, err := q.Query(ctx, `SELECT credential_id, data FROM auth_passkeys WHERE principal_id = $1 ORDER BY created_at, id`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.CredentialDescriptor
	for rows.Next() {
		var id, data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(data, &cred); err != nil {
			return nil, err
		}
		out = append(out, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: id, Transport: cred.Transport})
	}
	return out, rows.Err()
}

func credentialKnown(ctx context.Context, q db.Querier, id []byte) (bool, error) {
	var known bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth_passkeys WHERE credential_id = $1)`, id).Scan(&known)
	return known, err
}

func insertPasskey(ctx context.Context, q db.Querier, pk Passkey, principal uuid.UUID, cred *webauthn.Credential) (bool, error) {
	body, err := json.Marshal(*cred)
	if err != nil {
		return false, err
	}
	n, err := q.Exec(ctx, `
		INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at)
		VALUES ($1, $2, $3, $4, ($5::text)::jsonb, $6)
		ON CONFLICT (credential_id) DO NOTHING`,
		pk.ID, principal, cred.ID, pk.Label, string(body), pk.CreatedAt)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func passkeyLabel(raw string, now time.Time) (string, bool) {
	l := strings.TrimSpace(raw)
	if l == "" {
		return "Passkey " + now.UTC().Format("2006-01-02"), true
	}
	if utf8.RuneCountInString(l) > 64 {
		return "", false
	}
	for _, r := range l {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return l, true
}
