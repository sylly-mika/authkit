// Package pgxdb adapts pgx v5 to db.Querier, as db/sqldb adapts database/sql:
// a pgx.Tx for every method; a pinned *pgxpool.Conn, or for an app without
// RLS settings the pool itself, for authkit's reads.
package pgxdb

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sylly-mika/authkit/db"
)

// std is the method set pgx.Tx, *pgxpool.Conn and *pgxpool.Pool share.
type std interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type querier struct {
	std std
	tx  pgx.Tx
}

// Tx is a transaction: every Service method runs on it. Tx, Conn and Pool of
// nil are a nil Querier, so a caller's nil check sees an unbound request.
func Tx(tx pgx.Tx) db.Querier {
	if tx == nil {
		return nil
	}
	return querier{std: tx, tx: tx}
}

// Conn is a pinned pool connection, for the reads.
func Conn(conn *pgxpool.Conn) db.Querier {
	if conn == nil {
		return nil
	}
	return querier{std: conn}
}

// Pool is the pool itself, for the reads of an app without RLS settings.
func Pool(pool *pgxpool.Pool) db.Querier {
	if pool == nil {
		return nil
	}
	return querier{std: pool}
}

// Unwrap hands the app the pgx.Tx behind a Tx Querier, so its own pgx
// repositories run on authkit's transaction (in Principals, in OnEvent).
func Unwrap(q db.Querier) (pgx.Tx, bool) {
	p, ok := q.(querier)
	if !ok || p.tx == nil {
		return nil, false
	}
	return p.tx, true
}

func (q querier) InTx() bool { return q.tx != nil }

func (q querier) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	tag, err := q.std.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (q querier) Query(ctx context.Context, query string, args ...any) (db.Rows, error) {
	r, err := q.std.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return rows{r}, nil
}

func (q querier) QueryRow(ctx context.Context, query string, args ...any) db.Row {
	return row{q.std.QueryRow(ctx, query, args...)}
}

// rows is pgx.Rows with the error-returning Close db.Rows wants.
type rows struct{ pgx.Rows }

func (r rows) Close() error {
	r.Rows.Close()
	return nil
}

type row struct{ r pgx.Row }

func (r row) Scan(dest ...any) error {
	err := r.r.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.ErrNoRows
	}
	return err
}
