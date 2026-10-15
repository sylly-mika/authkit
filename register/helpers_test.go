package register_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/onetime"
	"github.com/sylly-mika/authkit/register"
)

const (
	addr     = "ada@example.invalid"
	pAda     = "{\"given_name\":\"Ada\"}"
	pAugusta = "{\"given_name\":\"Augusta\"}"
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
	Reg *register.Module
}

func newFixture(t *testing.T, tweaks ...func(*register.Rules)) *fixture {
	t.Helper()
	w := kittest.New(t)
	r := register.Rules{Create: stub}
	for _, tweak := range tweaks {
		tweak(&r)
	}
	reg, err := register.New(w.Svc.Service, w.Svc.Password, r)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{World: w, Reg: reg}
}

func stub(context.Context, db.Querier, register.Pending) (authkit.Principal, error) {
	return authkit.Principal{}, errors.New("register test: Create runs only at activation")
}

func (f *fixture) start(aud authkit.Audience, email, payload string) register.Started {
	f.T.Helper()
	var st register.Started
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		st, err = f.Reg.Start(f.Ctx, q, aud, email, json.RawMessage(payload))
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	return st
}

func (f *fixture) count(aud authkit.Audience, email string) time.Duration {
	f.T.Helper()
	var d time.Duration
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		d, err = f.Reg.CountMail(f.Ctx, q, aud, email)
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	return d
}

func (f *fixture) mint(id uuid.UUID) (register.Mail, error) {
	f.T.Helper()
	var mail register.Mail
	var err error
	if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		mail, err = f.Reg.Mint(f.Ctx, q, id)
		return nil
	}); e != nil {
		f.T.Fatal(e)
	}
	return mail, err
}

func (f *fixture) spend(raw string) (onetime.Token, error) {
	f.T.Helper()
	var tok onetime.Token
	var err error
	if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		tok, err = f.Svc.OneTime().Spend(f.Ctx, q, raw, authkit.PurposeRegister)
		return nil
	}); e != nil {
		f.T.Fatal(e)
	}
	return tok, err
}

func (f *fixture) regID(aud, email string) uuid.UUID {
	f.T.Helper()
	var id uuid.UUID
	if err := f.D.Row(f.T, "SELECT id FROM auth_registrations WHERE audience = $1 AND email = $2", aud, email).Scan(&id); err != nil {
		f.T.Fatal(err)
	}
	return id
}
