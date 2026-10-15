package register_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
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
