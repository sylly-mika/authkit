// Package authkittest is authkit's Postgres test harness (spec §12): a
// throwaway database per test, cloned from a template that holds the
// library's migrations between an ino-tasks-shaped principals table and
// ino-tasks-shaped policies, run as a non-owner role; plus a fake clock and
// deterministic randomness.
package authkittest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/lib/pq/pqerror"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/migrations"
)

const (
	OwnerRole       = "authkit_owner"
	AppRole         = "authkit_app"
	lockKey   int64 = 0x61757468 // serialises template builds and clones across test binaries
)

var (
	//go:embed principals.sql
	principalsSQL string
	//go:embed policies.sql
	policiesSQL string

	templateOnce sync.Once
	templateName string
	templateErr  error
)

// AdminDSN is the superuser DSN of the throwaway cluster: $AUTHKIT_PG, else
// postgres://postgres:postgres@127.0.0.1:5446/postgres?sslmode=disable.
func AdminDSN() string {
	if dsn := os.Getenv("AUTHKIT_PG"); dsn != "" {
		return dsn
	}
	return "postgres://postgres:postgres@127.0.0.1:5446/postgres?sslmode=disable"
}

// DB is one test's database. Owner owns every table and, under FORCE RLS, is
// bound like ino-tasks' app role; App is a non-owner with DML grants only.
type DB struct {
	Name  string
	Owner *sql.DB
	App   *sql.DB
}

// NewDB clones a fresh database from the template and drops it when the test
// ends. It skips when Postgres is unreachable, unless AUTHKIT_REQUIRE_DB or CI
// is set.
func NewDB(t testing.TB) *DB {
	t.Helper()
	ctx := context.Background()
	admin, err := sql.Open("postgres", AdminDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := admin.PingContext(ctx); err != nil {
		if os.Getenv("AUTHKIT_REQUIRE_DB") != "" || os.Getenv("CI") != "" {
			t.Fatalf("authkittest: Postgres is unreachable: %v", err)
		}
		t.Skipf("authkittest: Postgres is unreachable (%v); run make start-db", err)
	}
	name := "t_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := clone(ctx, admin, name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { drop(t, name) })
	return &DB{Name: name, Owner: open(t, OwnerRole, name), App: open(t, AppRole, name)}
}

func clone(ctx context.Context, admin *sql.DB, name string) error {
	conn, err := admin.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, lockKey) }()
	templateOnce.Do(func() { templateName, templateErr = buildTemplate(ctx, conn) })
	if templateErr != nil {
		return fmt.Errorf("authkittest: building the template: %w", templateErr)
	}
	create := fmt.Sprintf(`CREATE DATABASE %s TEMPLATE %s OWNER %s`,
		pq.QuoteIdentifier(name), pq.QuoteIdentifier(templateName), pq.QuoteIdentifier(OwnerRole))
	_, err = conn.ExecContext(ctx, create)
	var pe *pq.Error
	if errors.As(err, &pe) && pe.Code == pqerror.ObjectInUse {
		if err := terminate(ctx, conn, templateName); err != nil {
			return err
		}
		_, err = conn.ExecContext(ctx, create)
	}
	return err
}

// buildTemplate runs under the advisory lock. The schema goes into a _build
// database that takes the content-addressed name only once complete, so a
// killed run never leaves a broken template behind.
func buildTemplate(ctx context.Context, admin *sql.Conn) (string, error) {
	schema, err := templateSchema()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(schema))
	name := "authkit_tpl_" + hex.EncodeToString(sum[:])[:12]
	var exists bool
	if err := admin.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, name).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		return name, nil
	}
	build := name + "_build"
	if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+pq.QuoteIdentifier(build)+` WITH (FORCE)`); err != nil {
		return "", err
	}
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+pq.QuoteIdentifier(build)+` OWNER `+pq.QuoteIdentifier(OwnerRole)); err != nil {
		return "", err
	}
	if err := applySchema(ctx, build, schema); err != nil {
		_, _ = admin.ExecContext(ctx, `DROP DATABASE `+pq.QuoteIdentifier(build)+` WITH (FORCE)`)
		return "", fmt.Errorf("applying the schema: %w", err)
	}
	if err := terminate(ctx, admin, build); err != nil {
		return "", err
	}
	if _, err := admin.ExecContext(ctx, `ALTER DATABASE `+pq.QuoteIdentifier(build)+` RENAME TO `+pq.QuoteIdentifier(name)); err != nil {
		return "", err
	}
	return name, nil
}

func templateSchema() (string, error) {
	parts := []string{principalsSQL}
	for _, m := range migrations.All() {
		up, err := migrations.Render(m.Up, "users")
		if err != nil {
			return "", err
		}
		parts = append(parts, up)
	}
	return strings.Join(append(parts, policiesSQL), "\n"), nil
}

// applySchema sends the whole schema without arguments, so lib/pq runs it as
// one simple query in one implicit transaction.
func applySchema(ctx context.Context, name, schema string) error {
	dsn, err := roleDSN(OwnerRole, name)
	if err != nil {
		return err
	}
	owner, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer owner.Close()
	_, err = owner.ExecContext(ctx, schema)
	return err
}

// terminate ends every other session on a database: sql.DB.Close does not wait
// for the server, and a clone or rename of a database in use fails with 55006.
func terminate(ctx context.Context, admin *sql.Conn, name string) error {
	_, err := admin.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, name)
	return err
}

func roleDSN(role, name string) (string, error) {
	u, err := url.Parse(AdminDSN())
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(role, role)
	u.Path = "/" + name
	return u.String(), nil
}

// DSN is role's DSN for d (OwnerRole or AppRole), for a driver other than
// lib/pq or a migration tool.
func (d *DB) DSN(role string) string {
	dsn, err := roleDSN(role, d.Name)
	if err != nil {
		panic(err)
	}
	return dsn
}

func open(t testing.TB, role, name string) *sql.DB {
	t.Helper()
	dsn, err := roleDSN(role, name)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	pool.SetMaxOpenConns(24)
	if err := pool.PingContext(context.Background()); err != nil {
		t.Fatalf("authkittest: %s on %s: %v", role, name, err)
	}
	return pool
}

func drop(t testing.TB, name string) {
	admin, err := sql.Open("postgres", AdminDSN())
	if err == nil {
		defer admin.Close()
		_, err = admin.ExecContext(context.Background(), `DROP DATABASE `+pq.QuoteIdentifier(name)+` WITH (FORCE)`)
	}
	if err != nil {
		t.Errorf("authkittest: dropping %s: %v", name, err)
	}
}

type beginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

func inTx(ctx context.Context, b beginner, fn func(q db.Querier) error, setup string, args ...any) error {
	tx, err := b.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if setup != "" {
		if _, err := tx.ExecContext(ctx, setup, args...); err != nil {
			return err
		}
	}
	if err := fn(sqldb.Tx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// InAuthTx is ino-tasks' InAuthTx: a transaction on App with no setting bound,
// so only the _auth policies admit rows.
func (d *DB) InAuthTx(ctx context.Context, fn func(q db.Querier) error) error {
	return inTx(ctx, d.App, fn, "")
}

// InSystemTx binds the scope and the system principal for one transaction.
func (d *DB) InSystemTx(ctx context.Context, scope uuid.UUID, fn func(q db.Querier) error) error {
	return inTx(ctx, d.App, fn,
		`SELECT set_config('app.workspace_id', $1, true), set_config('app.principal', 'system', true)`, scope.String())
}

// InGlobalSystemTx binds the system principal and no scope.
func (d *DB) InGlobalSystemTx(ctx context.Context, fn func(q db.Querier) error) error {
	return inTx(ctx, d.App, fn, `SELECT set_config('app.principal', 'system', true)`)
}

// Pinned is a request's connection: an App connection with the scope, the
// principal and its kind set for the session. The test's cleanup discards it,
// so the settings never reach the pool.
func (d *DB) Pinned(t testing.TB, principal, scope uuid.UUID, kind string) *sql.Conn {
	t.Helper()
	if kind != "staff" && kind != "client" {
		t.Fatalf("authkittest: Pinned kind %q, want staff or client", kind)
	}
	ctx := context.Background()
	conn, err := d.App.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
	})
	set := fmt.Sprintf(`SET app.workspace_id = '%s'; SET app.user_id = '%s'; SET app.principal = '%s'`,
		scope.String(), principal.String(), kind)
	if _, err := conn.ExecContext(ctx, set); err != nil {
		t.Fatal(err)
	}
	return conn
}

// InConnTx is ino-tasks' InConnTx: a transaction on a pinned connection.
func InConnTx(ctx context.Context, conn *sql.Conn, fn func(q db.Querier) error) error {
	return inTx(ctx, conn, fn, "")
}

func (d *DB) NewPrincipal(t testing.TB, login string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := d.App.ExecContext(context.Background(), `INSERT INTO users (id, email) VALUES ($1, $2)`, id, login); err != nil {
		t.Fatalf("authkittest: NewPrincipal(%q): %v", login, err)
	}
	return id
}

func (d *DB) NewInvite(t testing.TB, scope uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if err := d.InSystemTx(ctx, scope, func(q db.Querier) error {
		_, err := q.Exec(ctx, `INSERT INTO invites (id, scope_id) VALUES ($1, $2)`, id, scope)
		return err
	}); err != nil {
		t.Fatalf("authkittest: NewInvite: %v", err)
	}
	return id
}

// Exec runs on Owner with no setting bound and returns the rows affected.
func (d *DB) Exec(t testing.TB, query string, args ...any) int64 {
	t.Helper()
	res, err := d.Owner.ExecContext(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("authkittest: Exec: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("authkittest: Exec: %v", err)
	}
	return n
}

// Row runs on Owner with no setting bound.
func (d *DB) Row(t testing.TB, query string, args ...any) *sql.Row {
	t.Helper()
	row := d.Owner.QueryRowContext(context.Background(), query, args...)
	if err := row.Err(); err != nil {
		t.Fatalf("authkittest: Row: %v", err)
	}
	return row
}

// WaitForLockWaiters waits until n sessions on the test's database wait on a
// lock. It asks as the superuser: pg_stat_activity hides another role's
// wait_event_type, and the waiters run as App while Owner is another role.
func (d *DB) WaitForLockWaiters(t testing.TB, n int) {
	t.Helper()
	admin, err := sql.Open("postgres", AdminDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := admin.QueryRowContext(context.Background(),
			`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, d.Name).Scan(&waiting); err != nil {
			t.Fatalf("authkittest: WaitForLockWaiters: %v", err)
		}
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("authkittest: %d of %d sessions wait on a lock after 10s", waiting, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
