package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sylly-mika/authkit/db"
)

type fake struct{ tx bool }

func (f fake) Exec(context.Context, string, ...any) (int64, error)    { return 0, nil }
func (f fake) Query(context.Context, string, ...any) (db.Rows, error) { return nil, nil }
func (f fake) QueryRow(context.Context, string, ...any) db.Row        { return nil }
func (f fake) InTx() bool                                             { return f.tx }

func TestRequireTx(t *testing.T) {
	if err := db.RequireTx(fake{tx: true}); err != nil {
		t.Fatalf("a transaction was refused: %v", err)
	}
	if err := db.RequireTx(fake{}); !errors.Is(err, db.ErrTxRequired) {
		t.Fatalf("a bare connection = %v, want ErrTxRequired", err)
	}
	if err := db.RequireTx(nil); !errors.Is(err, db.ErrTxRequired) {
		t.Fatalf("nil = %v, want ErrTxRequired", err)
	}
}
