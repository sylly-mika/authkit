// Package roundtrip_test runs authkit-gen's output through the two migration
// tools it writes for, against a real database (P3 spec §3.4). It is a module
// of its own, so authkit's go.mod requires neither tool.
package roundtrip_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/pressly/goose/v3"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/migrations"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// generate runs authkit-gen, as an app does, into dir for an admins table.
func generate(t *testing.T, format, dir string) {
	t.Helper()
	out, err := exec.Command("go", "run", "github.com/sylly-mika/authkit/cmd/authkit-gen",
		"-format", format, "-principals", "admins", "-out", dir, "-lock", filepath.Join(t.TempDir(), "authkit.lock")).CombinedOutput()
	if err != nil {
		t.Fatalf("authkit-gen -format %s: %v\n%s", format, err, out)
	}
}

// schema is auth_schema's version, -1 without the table, and whether
// auth_sessions has 0002's column.
func schema(t *testing.T, d *authkittest.DB) (int, bool) {
	t.Helper()
	var exists, capped bool
	if err := d.Row(t, `SELECT to_regclass('auth_schema') IS NOT NULL,
		EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'auth_sessions' AND column_name = 'absolute_expires_at')`).Scan(&exists, &capped); err != nil {
		t.Fatal(err)
	}
	if !exists {
		return -1, capped
	}
	var v int
	if err := d.Row(t, `SELECT version FROM auth_schema`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v, capped
}

func TestGooseRoundTrip(t *testing.T) {
	d := authkittest.NewEmptyDB(t)
	dir := t.TempDir()
	write(t, dir, "00001_admins.sql", "-- +goose Up\nCREATE TABLE admins (id uuid PRIMARY KEY);\n\n-- +goose Down\nDROP TABLE admins;\n")
	generate(t, "goose", dir)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, d.Owner, os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if _, err := p.Up(ctx); err != nil {
			t.Fatalf("goose up (round %d): %v", i+1, err)
		}
		if v, capped := schema(t, d); v != 2 || !capped {
			t.Fatalf("after goose up: auth_schema %d, absolute_expires_at %v; want 2 and the column", v, capped)
		}
		if _, err := p.DownTo(ctx, 0); err != nil {
			t.Fatalf("goose down (round %d): %v", i+1, err)
		}
		if v, capped := schema(t, d); v != -1 || capped {
			t.Fatalf("after goose down: auth_schema %d, absolute_expires_at %v; want neither", v, capped)
		}
	}
}

func TestGolangMigrateRoundTrip(t *testing.T) {
	d := authkittest.NewEmptyDB(t)
	dir := t.TempDir()
	write(t, dir, "000001_admins.up.sql", "CREATE TABLE admins (id uuid PRIMARY KEY);\n")
	write(t, dir, "000001_admins.down.sql", "DROP TABLE admins;\n")
	generate(t, "golang-migrate", dir)
	m, err := migrate.New("file://"+dir, d.DSN(authkittest.OwnerRole))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i := range 2 {
		if err := m.Up(); err != nil {
			t.Fatalf("migrate up (round %d): %v", i+1, err)
		}
		if v, capped := schema(t, d); v != 2 || !capped {
			t.Fatalf("after migrate up: auth_schema %d, absolute_expires_at %v; want 2 and the column", v, capped)
		}
		if err := m.Down(); err != nil {
			t.Fatalf("migrate down (round %d): %v", i+1, err)
		}
		if v, capped := schema(t, d); v != -1 || capped {
			t.Fatalf("after migrate down: auth_schema %d, absolute_expires_at %v; want neither", v, capped)
		}
	}
}

// TestGooseRunsADollarQuotedStatement: unwrapped, goose would split this
// function at PERFORM 1; and fail.
func TestGooseRunsADollarQuotedStatement(t *testing.T) {
	d := authkittest.NewEmptyDB(t)
	dir := t.TempDir()
	write(t, dir, "00001_authkit_fn.sql", migrations.Goose(
		"CREATE FUNCTION authkit_rt() RETURNS int AS $$\nBEGIN\n    PERFORM 1;\n    RETURN 7;\nEND;\n$$ LANGUAGE plpgsql;\n",
		"DROP FUNCTION authkit_rt();\n"))
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, d.Owner, os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("goose up of a $$ function: %v", err)
	}
	var n int
	if err := d.Row(t, `SELECT authkit_rt()`).Scan(&n); err != nil || n != 7 {
		t.Fatalf("authkit_rt() = %d, %v", n, err)
	}
	if _, err := p.DownTo(ctx, 0); err != nil {
		t.Fatalf("goose down: %v", err)
	}
}
