package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"time"

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
	p, err := s.principals.ByID(ctx, q, c.Subject, aud)
	if err != nil {
		return Result{}, err
	}
	creation, data, err := rp.BeginRegistration(passkeyUser{p: p})
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
	now := s.now()
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
	return sess, true, nil
}

func insertPasskey(ctx context.Context, q db.Querier, pk Passkey, principal uuid.UUID, cred *webauthn.Credential) (bool, error) {
	body, err := json.Marshal(*cred)
	if err != nil {
		return false, err
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at)
		VALUES ($1, $2, $3, $4, ($5::text)::jsonb, $6)`,
		pk.ID, principal, cred.ID, pk.Label, string(body), pk.CreatedAt); err != nil {
		return false, err
	}
	return true, nil
}
