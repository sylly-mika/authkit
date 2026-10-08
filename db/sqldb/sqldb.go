// Package sqldb adapts database/sql to db.Querier: a *sql.Tx for every method,
// a pinned *sql.Conn for authkit's reads and Guard's touch.
package sqldb

import (
	"context"
	"database/sql"
	"errors"

	"github.com/sylly-mika/authkit/db"
)

// Std is the method set *sql.Tx and *sql.Conn share, the one an app's own
// repositories usually take.
type Std interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type querier struct {
	std Std
	tx  bool
}

// Tx and Conn of nil are a nil Querier, so a caller's nil check sees an
// unbound request.
func Tx(tx *sql.Tx) db.Querier {
	if tx == nil {
		return nil
	}
	return querier{std: tx, tx: true}
}

func Conn(conn *sql.Conn) db.Querier {
	if conn == nil {
		return nil
	}
	return querier{std: conn}
}

// Unwrap hands an app's Principals implementation the *sql.Tx or *sql.Conn
// behind q, so its own repositories run on the same transaction.
func Unwrap(q db.Querier) (Std, bool) {
	s, ok := q.(querier)
	return s.std, ok
}

func (q querier) InTx() bool { return q.tx }

func (q querier) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	res, err := q.std.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (q querier) Query(ctx context.Context, query string, args ...any) (db.Rows, error) {
	rows, err := q.std.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (q querier) QueryRow(ctx context.Context, query string, args ...any) db.Row {
	return row{q.std.QueryRowContext(ctx, query, args...)}
}

type row struct{ r *sql.Row }

func (r row) Scan(dest ...any) error {
	err := r.r.Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return db.ErrNoRows
	}
	return err
}
