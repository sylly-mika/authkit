package authkit

import (
	"context"
	"errors"
	"fmt"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/migrations"
)

// CheckSchema refuses a database whose auth_schema.version is older than this
// library's migrations (spec §5.3). The app calls it once at startup.
func CheckSchema(ctx context.Context, q db.Querier) error {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('auth_schema') IS NOT NULL`).Scan(&exists); err != nil {
		return fmt.Errorf("authkit: look for auth_schema: %w", err)
	}
	if !exists {
		return fmt.Errorf("%w (no auth_schema table)", ErrSchemaBehind)
	}
	var v int
	err := q.QueryRow(ctx, `SELECT version FROM auth_schema WHERE id`).Scan(&v)
	if errors.Is(err, db.ErrNoRows) {
		return fmt.Errorf("%w (no auth_schema row visible; call CheckSchema with no workspace bound)", ErrSchemaBehind)
	}
	if err != nil {
		return fmt.Errorf("authkit: read auth_schema: %w", err)
	}
	if v < migrations.Version {
		return fmt.Errorf("%w (database %d, library %d)", ErrSchemaBehind, v, migrations.Version)
	}
	return nil
}
