package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/sylly-mika/authkit/db"
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
	_, _, ok, err := s.passkeyStart(ctx, q, aud)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrPasskeyRejected}, nil
	}
	return Result{}, errors.New("authkit: passkey sign-in not built")
}

// passkeyStart runs the checks both passkey methods share, in order: a transaction, a configured RPID, then the audience's relying party. ok is false when the audience has no origins.
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
