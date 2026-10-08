package sqldb_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
)

func TestTxIsATransactionAndConnIsNot(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	conn := d.Pinned(t, uuid.New(), uuid.New(), "staff")
	if sqldb.Conn(conn).InTx() {
		t.Fatal("a bare connection reports InTx")
	}
	if err := authkittest.InConnTx(ctx, conn, func(q db.Querier) error {
		if !q.InTx() {
			return errors.New("a transaction does not report InTx")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQueryRowMapsNoRowsAndExecCountsRows(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	if err := d.InAuthTx(ctx, func(q db.Querier) error {
		var id uuid.UUID
		if err := q.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, "nobody@example.invalid").Scan(&id); !errors.Is(err, db.ErrNoRows) {
			t.Errorf("an empty QueryRow = %v, want db.ErrNoRows", err)
		}
		n, err := q.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2), ($3, $4)`,
			uuid.New(), "one@example.invalid", uuid.New(), "two@example.invalid")
		if err != nil || n != 2 {
			t.Errorf("Exec = %d, %v; want 2 rows", n, err)
		}
		rows, err := q.Query(ctx, `SELECT email FROM users ORDER BY email`)
		if err != nil {
			return err
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				return err
			}
			got = append(got, e)
		}
		if len(got) != 2 || got[0] != "one@example.invalid" {
			t.Errorf("Query = %v", got)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUnwrapReturnsTheStdlibValue(t *testing.T) {
	d := authkittest.NewDB(t)
	conn := d.Pinned(t, uuid.New(), uuid.New(), "staff")
	std, ok := sqldb.Unwrap(sqldb.Conn(conn))
	if !ok || std.(*sql.Conn) != conn {
		t.Fatalf("Unwrap = %v, %v; want the *sql.Conn it wraps", std, ok)
	}
	if _, ok := sqldb.Unwrap(nil); ok {
		t.Fatal("Unwrap(nil) reported ok")
	}
}

func TestTheCallersContextReachesTheDriver(t *testing.T) {
	d := authkittest.NewDB(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.InAuthTx(context.Background(), func(q db.Querier) error {
		if _, err := q.Exec(cancelled, `SELECT 1`); !errors.Is(err, context.Canceled) {
			t.Errorf("Exec on a cancelled context = %v, want context.Canceled", err)
		}
		rows, err := q.Query(cancelled, `SELECT 1`)
		if err == nil {
			rows.Close()
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Query on a cancelled context = %v, want context.Canceled", err)
		}
		var n int
		if err := q.QueryRow(cancelled, `SELECT 1`).Scan(&n); !errors.Is(err, context.Canceled) {
			t.Errorf("QueryRow on a cancelled context = %v, want context.Canceled", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestANilHandleIsANilQuerier(t *testing.T) {
	if q := sqldb.Tx(nil); q != nil || !errors.Is(db.RequireTx(q), db.ErrTxRequired) {
		t.Fatalf("Tx(nil) = %#v, want a nil Querier that RequireTx refuses", q)
	}
	if q := sqldb.Conn(nil); q != nil {
		t.Fatalf("Conn(nil) = %#v, want a nil Querier", q)
	}
}
