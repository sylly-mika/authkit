package invite_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/invite"
)

const aud authkit.Audience = "staff"

const (
	addr = "ada@example.invalid"
	bob  = "bob@example.invalid"
)

type counted struct {
	db.Querier
	n *int
}

func (c counted) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	*c.n++
	return c.Querier.Exec(ctx, query, args...)
}

func (c counted) Query(ctx context.Context, query string, args ...any) (db.Rows, error) {
	*c.n++
	return c.Querier.Query(ctx, query, args...)
}

func (c counted) QueryRow(ctx context.Context, query string, args ...any) db.Row {
	*c.n++
	return c.Querier.QueryRow(ctx, query, args...)
}

type fixture struct {
	*kittest.World
	Inv *invite.Module
}

func newFixture(t *testing.T, tweaks ...func(*invite.Rules)) *fixture {
	t.Helper()
	w := kittest.New(t)
	r := invite.Rules{Create: stub}
	for _, tweak := range tweaks {
		tweak(&r)
	}
	inv, err := invite.New(w.Svc.Service, w.Svc.Password, r)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{World: w, Inv: inv}
}

func stub(context.Context, db.Querier, invite.Pending, json.RawMessage) (authkit.Principal, error) {
	return authkit.Principal{}, errors.New("invite test: Create runs only at accept")
}

func joinOK(context.Context, db.Querier, invite.Pending, authkit.Principal) error { return nil }

func req(email string) invite.Request { return invite.Request{Audience: aud, Email: email} }

func (f *fixture) invite(r invite.Request) (invite.Invited, error) {
	f.T.Helper()
	var inv invite.Invited
	var err error
	if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		inv, err = f.Inv.Invite(f.Ctx, q, r)
		return nil
	}); e != nil {
		f.T.Fatal(e)
	}
	return inv, err
}
