package scep

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/jacksongrow0/SimpleSCEP/internal/worker"
)

// RunIntuneRevocations polls no more frequently than Microsoft's 60-minute
// cooldown and reports every downloaded request back to Intune.
func RunIntuneRevocations(ctx context.Context, db *sql.DB, keys pki.KeyProvider, publicURL string, app IntuneApp) {
	if !app.Deployed() {
		return
	}
	client := NewIntuneClient(&http.Client{Timeout: 30 * time.Second})
	worker.Run(ctx, "scep intune_revocation_sync", time.Hour, func(ctx context.Context) error {
		return syncIntuneRevocations(ctx, db, keys, publicURL, app, client)
	})
}

func syncIntuneRevocations(ctx context.Context, db *sql.DB, keys pki.KeyProvider, publicURL string, app IntuneApp, client *IntuneClient) error {
	orgs, err := scepOrganizations(ctx, db)
	if err != nil {
		return err
	}
	for _, orgID := range orgs {
		if err := syncIntuneOrganization(ctx, db, keys, publicURL, app, client, orgID); err != nil {
			log.Printf("scep org=%s intune_revocation_sync failed: %v", orgID, err)
		}
	}
	return nil
}

func syncIntuneOrganization(ctx context.Context, db *sql.DB, keys pki.KeyProvider, publicURL string, app IntuneApp, client *IntuneClient, orgID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txctx := database.WithTx(ctx, tx)
	defer tx.Rollback()
	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		return err
	}
	repo := NewRepository(db)
	endpoints, err := repo.IntuneEndpoints(txctx, orgID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Endpoints sharing an issuing CA share one revocation queue, because
	// Microsoft filters the queue by issuer name. Downloading per endpoint would
	// let one endpoint report a sibling's certificate as "certificate not
	// found" and acknowledge it, after which that certificate is never revoked.
	// The organization's directory is single, so grouping by CA is grouping by
	// (tenant, CA).
	groups := map[string][]Endpoint{}
	for _, e := range endpoints {
		groups[e.CAID] = append(groups[e.CAID], e)
	}
	for caID, group := range groups {
		if err := syncIntuneCAGroup(ctx, db, keys, publicURL, app, client, orgID, caID, group); err != nil {
			log.Printf("scep org=%s ca=%s intune_revocation_sync failed: %v", orgID, caID, err)
		}
	}
	return nil
}

// syncIntuneCAGroup drains the revocation queue for one issuing CA on behalf of
// every endpoint that issues from it.
func syncIntuneCAGroup(ctx context.Context, db *sql.DB, keys pki.KeyProvider, publicURL string, app IntuneApp,
	client *IntuneClient, orgID, caID string, endpoints []Endpoint) error {
	endpointIDs := make([]string, len(endpoints))
	for i, e := range endpoints {
		endpointIDs[i] = e.ID
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txctx := database.WithTx(ctx, tx)
	defer tx.Rollback()
	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		return err
	}
	repo := NewRepository(db)
	service := NewService(repo, db, keys, publicURL, client, app)
	integration, err := service.intuneIntegration(txctx, orgID)
	if err != nil {
		return err
	}
	pkiRepo := pki.NewRepository(db)
	ca, err := pkiRepo.CA(txctx, orgID, caID)
	if err != nil {
		return err
	}
	issuer, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return err
	}
	transactionID := uuid.NewString()
	// One download now serves every endpoint on this CA, so take the largest
	// batch Microsoft allows rather than a per-endpoint share of it.
	requests, err := client.DownloadRevocations(txctx, integration, transactionID, issuer.Subject.String(), maxRevocationBatch)
	if err != nil || len(requests) == 0 {
		return err
	}
	pkiService := pki.NewServiceWithURL(pkiRepo, keys, publicURL)
	results := make([]IntuneRevocationResult, 0, len(requests))
	for _, request := range requests {
		cert, certErr := pkiRepo.CertificateBySerial(txctx, orgID, caID, request.SerialNumber)
		issuedInGroup := false
		if certErr == nil {
			issuedInGroup, certErr = repo.CertificateIssuedByEndpoints(txctx, endpointIDs, cert.ID)
		}
		results = append(results, classifyRevocation(request, certErr == nil, issuedInGroup,
			cert.Status == pki.CertStatusRevoked, func() error {
				return pkiService.Revoke(txctx, pki.RevokeRequest{OrgID: orgID, CertificateID: cert.ID, Reason: "unspecified"})
			}))
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := client.UploadRevocations(ctx, integration, transactionID, results); err != nil {
		return fmt.Errorf("upload results: %w", err)
	}
	log.Printf("scep org=%s ca=%s endpoints=%d intune_revocation_sync requests=%d", orgID, caID, len(endpointIDs), len(results))
	return nil
}

// classifyRevocation decides what to report to Intune for one revocation
// request. It is separated from the I/O around it because a "certificate not
// found" verdict is acknowledged to Microsoft and never retried: reporting it
// for a certificate that a sibling endpoint on this CA issued would mean that
// certificate is never revoked at all.
func classifyRevocation(request IntuneRevocationRequest, found, issuedInGroup, alreadyRevoked bool,
	revoke func() error) IntuneRevocationResult {
	result := IntuneRevocationResult{RequestContext: request.RequestContext}
	switch {
	case !found || !issuedInGroup:
		result.ErrorCode, result.ErrorMessage = RevokeErrorCertificateNotFound, "certificate not found"
	case alreadyRevoked:
		result.Succeeded = true
	default:
		if err := revoke(); err != nil {
			result.ErrorCode, result.ErrorMessage = RevokeErrorRetryable, "certificate revocation failed"
		} else {
			result.Succeeded = true
		}
	}
	return result
}

func scepOrganizations(ctx context.Context, db *sql.DB) ([]string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txctx, "app.auth_flow", "true"); err != nil {
		return nil, err
	}
	return database.OrganizationIDs(ctx, tx)
}
