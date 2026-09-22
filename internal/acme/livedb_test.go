//go:build livedb

// Package-level live-database checks. These exercise the things an in-memory
// store cannot: that row-level security scopes a lookup to its organization,
// that the client-facing policy exposes exactly the endpoint row and nothing
// else, and that a nonce can be spent only once under concurrency.
//
// Run with a database available:
//
//	go test -tags livedb ./internal/acme/ -run LiveDB -v
package acme

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

func liveDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("LIVEDB_URL")
	if url == "" {
		t.Skip("set LIVEDB_URL to run live-database checks")
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	return db
}

func liveEnv(t *testing.T) (orgID, caID string) {
	t.Helper()
	orgID, caID = os.Getenv("LIVEDB_ORG"), os.Getenv("LIVEDB_CA")
	if orgID == "" || caID == "" {
		t.Skip("set LIVEDB_ORG and LIVEDB_CA")
	}
	return orgID, caID
}

// seedEndpoint creates an enabled endpoint inside the caller's transaction. It
// is never committed, so nothing here outlives the test.
func seedEndpoint(t *testing.T, ctx context.Context, repo Repository, orgID, caID string) Endpoint {
	t.Helper()
	e := Endpoint{ID: uuid.NewString(), OrganizationID: orgID, CAID: caID,
		Name: "livedb " + uuid.NewString()[:8], Enabled: true, ValidityDays: DefaultValidityDays,
		AllowedEKUs: "server_auth", SubjectPattern: ".+"}
	if err := repo.InsertEndpoint(ctx, e); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if err := repo.SetEnabled(ctx, orgID, e.ID, true); err != nil {
		t.Fatalf("enable endpoint: %v", err)
	}
	return e
}

// TestLiveDBClientPolicyExposesOnlyTheEndpoint is the RLS check that matters
// most. The client path sets app.acme_endpoint_id and nothing else before it
// reads the endpoint, so that GUC alone must unlock the endpoint row and
// nothing underneath it — an accounts or credentials table readable under the
// same disjunct would be a cross-tenant leak to an unauthenticated caller.
func TestLiveDBClientPolicyExposesOnlyTheEndpoint(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)

	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	e := seedEndpoint(t, txctx, repo, orgID, caID)
	credential := EABCredential{ID: uuid.NewString(), OrganizationID: orgID, EndpointID: e.ID,
		KID: uuid.NewString(), MACKeyCiphertext: []byte("sealed")}
	if err := repo.CreateCredential(txctx, credential); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	// Drop to what an unauthenticated client actually has: the endpoint id only.
	if err := database.SetLocal(txctx, "app.organization_id", ""); err != nil {
		t.Fatal(err)
	}
	if err := database.SetLocal(txctx, "app.acme_endpoint_id", e.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.Endpoint(txctx, e.ID); err != nil {
		t.Errorf("a client cannot read its own endpoint: %v", err)
	}
	if _, err := repo.CredentialByKID(txctx, e.ID, credential.KID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("credentials are readable with only the endpoint id: %v", err)
	}
	if orders, err := repo.Orders(txctx, e.ID, 10); err == nil && len(orders) > 0 {
		t.Errorf("orders are readable with only the endpoint id")
	}
}

// TestLiveDBDisabledEndpointIsInvisible: the policy's disjunct carries "AND
// enabled", so turning an endpoint off has to remove it from the client path
// entirely rather than relying on a check in Go.
func TestLiveDBDisabledEndpointIsInvisible(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)

	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	e := seedEndpoint(t, txctx, repo, orgID, caID)
	if err := repo.SetEnabled(txctx, orgID, e.ID, false); err != nil {
		t.Fatal(err)
	}

	if err := database.SetLocal(txctx, "app.organization_id", ""); err != nil {
		t.Fatal(err)
	}
	if err := database.SetLocal(txctx, "app.acme_endpoint_id", e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Endpoint(txctx, e.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("a disabled endpoint is still visible to a client: %v", err)
	}
}

// TestLiveDBAnotherOrganizationCannotSeeEndpoints is the ordinary tenant
// isolation check, made against a second real organization rather than a
// forged GUC.
func TestLiveDBAnotherOrganizationCannotSeeEndpoints(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	other := os.Getenv("LIVEDB_OTHER_ORG")
	if other == "" {
		t.Skip("set LIVEDB_OTHER_ORG")
	}
	repo := NewRepository(db)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)

	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	e := seedEndpoint(t, txctx, repo, orgID, caID)

	if err := database.SetLocal(txctx, "app.organization_id", other); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.EndpointByID(txctx, other, e.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("another organization can read the endpoint: %v", err)
	}
	// Not merely scoped by the predicate: the row must be invisible even when
	// the query asks for it by the owning organization's id.
	if _, err := repo.EndpointByID(txctx, orgID, e.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("RLS did not hide the row from another organization's session: %v", err)
	}
}

// TestLiveDBNonceIsSpentExactlyOnce proves the DELETE ... RowsAffected pattern
// under real concurrency. Two transactions racing on one nonce must not both
// succeed; a SELECT-then-DELETE would let them.
func TestLiveDBNonceIsSpentExactlyOnce(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// The endpoint and nonce have to be committed for a second transaction to
	// see them, so this test cleans up after itself explicitly.
	setup, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	setupCtx := database.WithTx(ctx, setup)
	if err := database.SetLocal(setupCtx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	e := seedEndpoint(t, setupCtx, repo, orgID, caID)
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	if err := repo.IssueNonce(setupCtx, orgID, e.ID, value); err != nil {
		t.Fatal(err)
	}
	if err := setup.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			return
		}
		cleanupCtx := database.WithTx(context.Background(), cleanup)
		_ = database.SetLocal(cleanupCtx, "app.organization_id", orgID)
		_ = repo.DeleteEndpoint(cleanupCtx, orgID, e.ID)
		_ = cleanup.Commit()
	})

	spend := func() error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		txctx := database.WithTx(ctx, tx)
		if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
			return err
		}
		if err := repo.ConsumeNonce(txctx, e.ID, value); err != nil {
			return err
		}
		return tx.Commit()
	}

	results := make(chan error, 2)
	for range 2 {
		go func() { results <- spend() }()
	}
	var succeeded int
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				succeeded++
			} else if !errors.Is(err, sql.ErrNoRows) {
				t.Errorf("unexpected error spending the nonce: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for a nonce spend")
		}
	}
	if succeeded != 1 {
		t.Errorf("the nonce was spent %d times, want exactly 1", succeeded)
	}
}
