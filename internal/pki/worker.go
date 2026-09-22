package pki

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/worker"
)

func RunCRLRenewal(ctx context.Context, db *sql.DB, provider KeyProvider, publicURL string) {
	worker.Run(ctx, "CRL renewal", time.Hour, func(ctx context.Context) error {
		return RenewCRLsOnce(ctx, db, provider, publicURL)
	})
}

func RenewCRLsOnce(ctx context.Context, db *sql.DB, provider KeyProvider, publicURL string) error {
	orgs, err := revocationOrganizations(ctx, db)
	if err != nil {
		return err
	}
	for _, orgID := range orgs {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		txctx := database.WithTx(ctx, tx)
		if err = database.SetLocal(txctx, "app.organization_id", orgID); err == nil {
			repo := NewRepository(db)
			service := NewServiceWithURL(repo, provider, publicURL)
			var cas []CertificateAuthority
			cas, err = repo.CAs(txctx, orgID)
			for _, ca := range cas {
				if ca.Type != CATypeIssuing {
					continue
				}
				p, pErr := repo.CRLPublication(txctx, orgID, ca.ID)
				if pErr != nil || p.LastError != "" || p.NextUpdate == nil || p.NextUpdate.Before(time.Now().UTC().Add(time.Hour)) {
					if publishErr := service.PublishCRL(txctx, orgID, ca.ID); publishErr != nil {
						log.Printf("CRL publication failed for CA %s: %v", ca.ID, publishErr)
					}
				}
			}
		}
		if err != nil {
			tx.Rollback()
			continue
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func revocationOrganizations(ctx context.Context, db *sql.DB) ([]string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	txctx := database.WithTx(ctx, tx)
	defer tx.Rollback()
	if err := database.SetLocal(txctx, "app.auth_flow", "true"); err != nil {
		return nil, err
	}
	orgs, err := database.OrganizationIDs(ctx, tx)
	if err != nil {
		return nil, err
	}
	return orgs, tx.Commit()
}
