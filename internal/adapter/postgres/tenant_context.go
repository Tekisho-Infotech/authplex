package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// WithTenantTx executes fn within a transaction with the tenant context set.
// This ensures Postgres RLS policies filter by tenant_id automatically.
// SET LOCAL is scoped to the current transaction — resets after COMMIT/ROLLBACK.
func WithTenantTx(ctx context.Context, db *sql.DB, tenantID string, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var ignored string
	if err := tx.QueryRowContext(
		ctx,
		"SELECT set_config('app.tenant_id', $1, true)",
		tenantID,
	).Scan(&ignored); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}
