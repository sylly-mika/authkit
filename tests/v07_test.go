package tests

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/emailchange"
	"github.com/sylly-mika/authkit/invite"
)

const v7Pass = "an invited password"

func (w *world) withInvite(totp bool) {
	w.T.Helper()
	w.Cfg.Invite = &invite.Rules{
		Create: func(ctx context.Context, q db.Querier, p invite.Pending, _ json.RawMessage) (authkit.Principal, error) {
			id := uuid.New()
			n, err := q.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING`, id, p.Email)
			if err != nil {
				return authkit.Principal{}, err
			}
			if n == 0 {
				return authkit.Principal{}, fmt.Errorf("users: %w", invite.ErrAddressHeld)
			}
			if totp {
				if _, err := q.Exec(ctx, w.D.SQL(`INSERT INTO auth_second_factors (principal_id, kind, secret, created_at, confirmed_at) VALUES ($1, 'totp', '\x01'::bytea, $2, $2)`), id, w.Clock.Now()); err != nil {
					return authkit.Principal{}, err
				}
			}
			return authkit.Principal{ID: id, Login: p.Email}, nil
		},
		Join: func(context.Context, db.Querier, invite.Pending, authkit.Principal) error { return nil },
	}
	w.Svc = w.Build(w.Cfg)
}

func (w *world) withEmailChange() {
	w.T.Helper()
	w.Cfg.EmailChange = &emailchange.Rules{Change: func(ctx context.Context, q db.Querier, p authkit.Principal, newLogin string) error {
		_, err := q.Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, p.ID, newLogin)
		return err
	}}
	w.Svc = w.Build(w.Cfg)
}

func (w *world) inviteLink(email string) string {
	w.T.Helper()
	var raw string
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		inv, err := w.Svc.Invite.Invite(w.Ctx, q, invite.Request{Audience: "staff", Email: email})
		if err != nil {
			return err
		}
		mail, err := w.Svc.Invite.Mint(w.Ctx, q, inv.TokenID)
		raw = mail.Raw
		return err
	}); err != nil {
		w.T.Fatalf("invite link: %v", err)
	}
	return raw
}

func (w *world) acceptInvite(raw, pass string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Invite.Accept(w.Ctx, q, raw, pass, nil, authkit.Meta{})
	})
}

func (w *world) acceptInviteOIDC(raw, ticket string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Invite.AcceptOIDC(w.Ctx, q, raw, ticket, nil, authkit.Meta{})
	})
}
