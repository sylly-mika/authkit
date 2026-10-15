package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/sylly-mika/authkit"
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
func (mod *Module) BeginPasskeyLogin(ctx context.Context, q db.Querier, aud authkit.Audience, m authkit.Meta) (authkit.Result, error) {
	rp, now, ok, err := mod.passkeyStart(ctx, q, aud)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	assertion, sd, err := rp.BeginDiscoverableLogin()
	if err != nil {
		return authkit.Result{}, err
	}
	opts, err := json.Marshal(assertion)
	if err != nil {
		return authkit.Result{}, err
	}
	id, exp, err := ceremony.Create(ctx, q, mod.core.Rand(), ceremony.KindLogin, string(aud), nil, nil, *sd, now, mod.rules.CeremonyTTL)
	if err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Ceremony: &authkit.Ceremony{ID: id, Options: opts, ExpiresAt: exp}}, nil
}

// FinishPasskeyLogin completes a passkey sign-in with the ceremony ID and the browser's JSON response: the passkey's owner passes Admit and gets a session, as with Login. Every refusal is authkit.ErrPasskeyRejected except Admit's own. Needs a transaction.
func (mod *Module) FinishPasskeyLogin(ctx context.Context, q db.Querier, aud authkit.Audience, ceremonyID string, response []byte, m authkit.Meta) (authkit.Result, error) {
	m = m.Clean()
	rp, now, ok, err := mod.passkeyStart(ctx, q, aud)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	sd, ok, err := ceremony.Spend(ctx, q, ceremony.KindLogin, string(aud), ceremonyID, nil, nil, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	var hit *passkeyRow
	var infraErr error
	handler := passkeyHandler(ctx, q, &hit, &infraErr)
	_, cred, err := rp.ValidatePasskeyLogin(handler, sd, parsed)
	if infraErr != nil {
		return authkit.Result{}, infraErr
	}
	if err != nil || cred.Authenticator.CloneWarning {
		return mod.refusePasskey(ctx, q, hit, aud, m, now)
	}
	p, err := mod.core.Principals().ByID(ctx, q, hit.principal, aud)
	if errors.Is(err, authkit.ErrUnknownLogin) {
		return mod.refusePasskey(ctx, q, hit, aud, m, now)
	}
	if err != nil {
		return authkit.Result{}, err
	}
	a := mod.core.BeginVerified(authkit.SourcePasskeyLogin, aud, m)
	a.SetPrincipal(&p)
	a.Commit(func(ctx context.Context, q db.Querier) error {
		data, err := json.Marshal(*cred)
		if err != nil {
			return err
		}
		_, err = q.Exec(ctx, "UPDATE auth_passkeys SET data = $2, last_used_at = $3 WHERE id = $1", hit.id, string(data), now)
		return err
	})
	return mod.core.SignIn(ctx, q, a, p, authkit.FactorPasskey)
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
		return passkeyUser{p: authkit.Principal{ID: row.principal}, creds: []webauthn.Credential{row.cred}}, nil
	}
}

func (mod *Module) refusePasskey(ctx context.Context, q db.Querier, hit *passkeyRow, aud authkit.Audience, m authkit.Meta, now time.Time) (authkit.Result, error) {
	if hit == nil {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	if err := mod.core.Record(ctx, q, authkit.SourcePasskeyLogin, authkit.Event{At: now, PrincipalID: &hit.principal, Audience: string(aud), Result: authkit.ResultBadPasskey, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
}

func (mod *Module) passkeyStart(ctx context.Context, q db.Querier, aud authkit.Audience) (rp *webauthn.WebAuthn, now time.Time, ok bool, err error) {
	if err := db.RequireTx(q); err != nil {
		return nil, time.Time{}, false, err
	}
	if mod.rules.RPID == "" {
		return nil, time.Time{}, false, authkit.ErrPasskeysOff
	}
	now = mod.core.Now()
	rp, ok, err = mod.relyingParty(aud)
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
