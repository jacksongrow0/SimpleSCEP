package acme

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/worker"
)

// RunOrderExpiry retires abandoned orders and clears spent nonces.
//
// Neither is urgent — an expired order is already refused at finalize by its own
// expires_at, and an unspent nonce is harmless — so this exists to keep the
// tables from growing without bound and to make the status a client polls agree
// with what finalize would tell it. Hourly is ample for both.
func RunOrderExpiry(ctx context.Context, db *sql.DB) {
	worker.Run(ctx, "acme expiry sweep", time.Hour, func(ctx context.Context) error {
		return ExpireOnce(ctx, db)
	})
}

// ExpireOnce runs one sweep across every organization.
func ExpireOnce(ctx context.Context, db *sql.DB) error {
	orgs, err := organizations(ctx, db)
	if err != nil {
		return err
	}
	repo := NewRepository(db)
	for _, orgID := range orgs {
		// One transaction per organization rather than one for the sweep: a
		// failure on one customer's rows must not roll back the work done for
		// everybody else, and each needs its own app.organization_id anyway.
		if err := withOrg(ctx, db, orgID, func(ctx context.Context) error {
			if _, err := repo.ExpireOrders(ctx, orgID); err != nil {
				return err
			}
			_, err := repo.DeleteExpiredNonces(ctx, time.Now().Add(-NonceTTL))
			return err
		}); err != nil {
			log.Printf("acme expiry org=%s failed: %v", orgID, err)
		}
	}
	return nil
}

// organizations lists every tenant. Enumerating across tenants is the one thing
// row-level security is designed to prevent, so it is done the way
// pki.revocationOrganizations does it: inside the auth flow, which is the only
// context the policies admit a cross-tenant read from.
func organizations(ctx context.Context, db *sql.DB) ([]string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txCtx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txCtx, "app.auth_flow", "true"); err != nil {
		return nil, err
	}
	out, err := database.OrganizationIDs(txCtx, database.Queryable(txCtx, db))
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func withOrg(ctx context.Context, db *sql.DB, orgID string, fn func(context.Context) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	txCtx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txCtx, "app.organization_id", orgID); err != nil {
		return err
	}
	if err := fn(txCtx); err != nil {
		return err
	}
	return tx.Commit()
}
