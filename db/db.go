// Package db is the narrow SQL surface authkit runs on. A Querier is the
// caller's transaction or pinned connection, never a pool: authkit opens no
// transaction and binds no RLS setting of its own.
package db

import (
	"context"
	"errors"
)

var (
	// ErrNoRows is what Row.Scan returns for an empty result, whatever the driver.
	ErrNoRows = errors.New("db: no rows in result set")
	// ErrTxRequired refuses a method that writes, locks or takes an advisory
	// lock when it is handed a bare connection (spec §5 "Writes need a transaction").
	ErrTxRequired = errors.New("authkit: this method writes or locks and needs the caller's transaction")
)

// Querier is the caller's transaction or pinned connection; db/sqldb adapts
// database/sql to it.
type Querier interface {
	Exec(ctx context.Context, query string, args ...any) (int64, error)
	Query(ctx context.Context, query string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) Row
	// InTx reports whether the querier is a transaction.
	InTx() bool
}

// Rows is a Query result, read like *sql.Rows.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

// Row is a QueryRow result; Scan returns ErrNoRows for an empty one.
type Row interface {
	Scan(dest ...any) error
}

// RequireTx is the first line of every method that writes or locks.
func RequireTx(q Querier) error {
	if q == nil || !q.InTx() {
		return ErrTxRequired
	}
	return nil
}
