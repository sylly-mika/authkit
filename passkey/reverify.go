package passkey

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/ceremony"
)

// BeginReverify starts a passkey assertion bound to the caller's session. Needs a transaction.
func (mod *Module) BeginReverify(ctx context.Context, q db.Querier, c *authkit.Claims) (authkit.Result, error) {
	q = mod.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if mod.rules.RPID == "" {
		return authkit.Result{}, authkit.ErrPasskeysOff
	}
	now := mod.core.Now()
	sess, err := mod.core.LockSession(ctx, q, c, now)
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrSessionEnded}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	aud := authkit.Audience(sess.Audience)
	rp, ok, err := mod.relyingParty(aud)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	n, err := countPasskeys(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	if n == 0 {
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
	id, exp, err := ceremony.Create(ctx, q, mod.core.Rand(), ceremony.KindReverify, string(aud), &c.Subject, &sess.ID, *sd, now, mod.rules.CeremonyTTL)
	if err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Ceremony: &authkit.Ceremony{ID: id, Options: opts, ExpiresAt: exp}}, nil
}
