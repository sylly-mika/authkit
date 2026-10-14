package authkit

import (
	"bytes"
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
)

type passkeyRow struct {
	id, principal uuid.UUID
	cred          webauthn.Credential
}

var (
	errUnknownPasskey = errors.New("authkit: unknown passkey")
	errPasskeyOwner   = errors.New("authkit: passkey owner mismatch")
)

// BeginPasskeyLogin starts a passkey sign-in on the audience: it stores a ceremony and returns its ID and the browser's request options. It takes no login. Needs a transaction.
func (s *Service) BeginPasskeyLogin(ctx context.Context, q db.Querier, aud Audience, m Meta) (Result, error) {
	rp, now, ok, err := s.passkeyStart(ctx, q, aud)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrPasskeyRejected}, nil
	}
	assertion, sd, err := rp.BeginDiscoverableLogin()
	if err != nil {
		return Result{}, err
	}
	opts, err := json.Marshal(assertion)
	if err != nil {
		return Result{}, err
	}
	id, exp, err := ceremony.Create(ctx, q, s.cfg.Rand, ceremony.KindLogin, string(aud), nil, nil, *sd, now, s.cfg.Passkeys.CeremonyTTL)
	if err != nil {
		return Result{}, err
	}
	return Result{Ceremony: &Ceremony{ID: id, Options: opts, ExpiresAt: exp}}, nil
}

// FinishPasskeyLogin completes a passkey sign-in with the ceremony ID and the browser's JSON response: the passkey's owner passes Admit and gets a session, as with Login. Every refusal is ErrPasskeyRejected except Admit's own. Needs a transaction.
func (s *Service) FinishPasskeyLogin(ctx context.Context, q db.Querier, aud Audience, ceremonyID string, response []byte, m Meta) (Result, error) {
	m = m.clean()
	rp, now, ok, err := s.passkeyStart(ctx, q, aud)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrPasskeyRejected}, nil
	}
	sd, ok, err := ceremony.Spend(ctx, q, ceremony.KindLogin, string(aud), ceremonyID, nil, nil, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrPasskeyRejected}, nil
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return Result{Refusal: ErrPasskeyRejected}, nil
	}
	var hit *passkeyRow
	var infraErr error
	handler := passkeyHandler(ctx, q, &hit, &infraErr)
	_, cred, err := rp.ValidatePasskeyLogin(handler, sd, parsed)
	if infraErr != nil {
		return Result{}, infraErr
	}
	if err != nil || cred.Authenticator.CloneWarning {
		return s.refusePasskey(ctx, q, hit, aud, m, now)
	}
	p, err := s.principals.ByID(ctx, q, hit.principal, aud)
	if errors.Is(err, ErrUnknownLogin) {
		return s.refusePasskey(ctx, q, hit, aud, m, now)
	}
	if err != nil {
		return Result{}, err
	}
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: aud, SecondFactor: FactorPasskey})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		if err := s.record(ctx, q, now, SourcePasskeyLogin, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login, Result: refusal.Result, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
			return Result{}, err
		}
		return Result{Refusal: refusal.Err}, nil
	}
	res, err := s.openSession(ctx, q, p, aud, adm, m, now, FactorPasskey)
	if err != nil {
		return Result{}, err
	}
	data, err := json.Marshal(*cred)
	if err != nil {
		return Result{}, err
	}
	if _, err := q.Exec(ctx, "UPDATE auth_passkeys SET data = $2, last_used_at = $3 WHERE id = $1", hit.id, string(data), now); err != nil {
		return Result{}, err
	}
	if err := s.record(ctx, q, now, SourcePasskeyLogin, events.Event{PrincipalID: &p.ID, SessionID: &res.Session.ID, ScopeID: adm.ScopeID, Audience: string(aud), Login: p.Login, Result: ResultSignedIn, IP: m.IP, UserAgent: m.UserAgent, SecondFactor: string(FactorPasskey)}); err != nil {
		return Result{}, err
	}
	return res, nil
}

func passkeyHandler(ctx context.Context, q db.Querier, hit **passkeyRow, infraErr *error) func(rawID, userHandle []byte) (webauthn.User, error) {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		row, found, err := loadPasskeyForUpdate(ctx, q, rawID)
		if err != nil {
			*infraErr = err
			return nil, err
		}
		if !found {
			return nil, errUnknownPasskey
		}
		*hit = &row
		if !bytes.Equal(userHandle, row.principal[:]) {
			return nil, errPasskeyOwner
		}
		return passkeyUser{p: Principal{ID: row.principal}, creds: []webauthn.Credential{row.cred}}, nil
	}
}

func (s *Service) refusePasskey(ctx context.Context, q db.Querier, hit *passkeyRow, aud Audience, m Meta, now time.Time) (Result, error) {
	if hit == nil {
		return Result{Refusal: ErrPasskeyRejected}, nil
	}
	if err := s.record(ctx, q, now, SourcePasskeyLogin, events.Event{PrincipalID: &hit.principal, Audience: string(aud), Result: ResultBadPasskey, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	return Result{Refusal: ErrPasskeyRejected}, nil
}

func (s *Service) passkeyStart(ctx context.Context, q db.Querier, aud Audience) (rp *webauthn.WebAuthn, now time.Time, ok bool, err error) {
	if err := db.RequireTx(q); err != nil {
		return nil, time.Time{}, false, err
	}
	if s.cfg.Passkeys.RPID == "" {
		return nil, time.Time{}, false, ErrPasskeysOff
	}
	now = s.now()
	rp, ok, err = s.relyingParty(aud)
	if err != nil {
		return nil, time.Time{}, false, err
	}
	return rp, now, ok, nil
}

func loadPasskeyForUpdate(ctx context.Context, q db.Querier, credID []byte) (passkeyRow, bool, error) {
	var row passkeyRow
	var data []byte
	err := q.QueryRow(ctx, "SELECT id, principal_id, data FROM auth_passkeys WHERE credential_id = $1 FOR UPDATE", credID).Scan(&row.id, &row.principal, &data)
	if errors.Is(err, db.ErrNoRows) {
		return passkeyRow{}, false, nil
	}
	if err != nil {
		return passkeyRow{}, false, err
	}
	if err := json.Unmarshal(data, &row.cred); err != nil {
		return passkeyRow{}, false, err
	}
	return row, true, nil
}
