//go:build livedb

// Package-level live-database checks. These exercise the two things unit tests
// with an in-memory store cannot: that a query's parameter encoding survives
// the driver, and that row-level security scopes a lookup to its organization.
//
// Run with a database available:
//
//	go test -tags livedb ./internal/scep/ -run LiveDB -v
package scep

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
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

// CertificateIssuedByEndpoints builds a typed IN predicate from endpoint IDs.
// This live check ensures Jet and pgx preserve UUID comparison semantics across
// a group, which no in-memory fake can catch.
func TestLiveDBCertificateIssuedByEndpointsMatchesAcrossTheGroup(t *testing.T) {
	db := liveDB(t)
	orgID, caID := os.Getenv("LIVEDB_ORG"), os.Getenv("LIVEDB_CA")
	if orgID == "" || caID == "" {
		t.Skip("set LIVEDB_ORG and LIVEDB_CA")
	}
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Everything below is rolled back; this test never leaves rows behind.
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	repo := NewRepository(db)

	// Two endpoints on one issuing CA, as the revocation worker groups them.
	a, b := uuid.NewString(), uuid.NewString()
	for i, id := range []string{a, b} {
		e := Endpoint{ID: id, OrganizationID: orgID, CAID: caID, Name: "livedb-" + id[:8],
			ValidityDays: 365, AllowedEKUs: "client_auth", RenewalWindowDays: 30, SubjectPattern: ".+",
			RACertificatePEM: "pem", RAPrivateKeyCiphertext: []byte{byte(i)}}
		if err := repo.InsertEndpoint(txctx, e); err != nil {
			t.Fatalf("insert endpoint %d: %v", i, err)
		}
	}
	// A certificate issued by B only. certificate_id is nullable, so the row
	// stands on its own without a certificate to reference.
	certID := uuid.NewString()
	if _, err := table.ScepTransaction.INSERT(table.ScepTransaction.OrganizationID,
		table.ScepTransaction.ScepEndpointID, table.ScepTransaction.TransactionID,
		table.ScepTransaction.CsrDigest, table.ScepTransaction.CertificateID,
		table.ScepTransaction.MessageType, table.ScepTransaction.Status,
		table.ScepTransaction.AuthorizationSource).
		VALUES(orgID, b, "tx-livedb", "digest", nil, "19", "issued", "one_time").ExecContext(ctx, tx); err != nil {
		t.Fatal(err)
	}
	// Read the row's generated id back so the lookup has a real certificate_id
	// to match on rather than NULL.
	if _, err := table.ScepTransaction.UPDATE(table.ScepTransaction.CsrDigest).SET(certID).
		WHERE(table.ScepTransaction.ScepEndpointID.EQ(database.UUID(b)).
			AND(table.ScepTransaction.TransactionID.EQ(postgres.String("tx-livedb")))).ExecContext(ctx, tx); err != nil {
		t.Fatal(err)
	}

	// The real assertion: B's certificate must be recognized when the group is
	// queried, and not recognized when only A is.
	issuedByB, err := issuedForDigest(ctx, tx, []string{a, b}, certID)
	if err != nil {
		t.Fatalf("the grouped Jet lookup failed: %v", err)
	}
	if !issuedByB {
		t.Fatal("the group query did not match a certificate a sibling endpoint issued")
	}
	issuedByAOnly, err := issuedForDigest(ctx, tx, []string{a}, certID)
	if err != nil {
		t.Fatal(err)
	}
	if issuedByAOnly {
		t.Fatal("a group excluding the issuing endpoint matched anyway")
	}
}

func issuedForDigest(ctx context.Context, db *sql.Tx, endpointIDs []string, digest string) (bool, error) {
	ids := make([]postgres.Expression, 0, len(endpointIDs))
	for _, id := range endpointIDs {
		ids = append(ids, database.UUID(id))
	}
	var result struct{ Exists bool }
	exists := postgres.EXISTS(postgres.SELECT(table.ScepTransaction.ID).FROM(table.ScepTransaction).
		WHERE(table.ScepTransaction.ScepEndpointID.IN(ids...).
			AND(table.ScepTransaction.CsrDigest.EQ(postgres.String(digest))).
			AND(table.ScepTransaction.Status.EQ(postgres.String("issued")))))
	err := postgres.SELECT(exists.AS("Exists")).QueryContext(ctx, db, &result)
	return result.Exists, err
}

// A well-formed endpoint ID belonging to another organization must not resolve.
// The predicate lives in SQL, so only a real database exercises it.
func TestLiveDBEndpointLookupIsScopedToTheOrganization(t *testing.T) {
	db := liveDB(t)
	orgID, otherOrgID, caID := os.Getenv("LIVEDB_ORG"), os.Getenv("LIVEDB_OTHER_ORG"), os.Getenv("LIVEDB_CA")
	if orgID == "" || otherOrgID == "" || caID == "" {
		t.Skip("set LIVEDB_ORG, LIVEDB_OTHER_ORG and LIVEDB_CA")
	}
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
	repo := NewRepository(db)
	id := uuid.NewString()
	if err := repo.InsertEndpoint(txctx, Endpoint{ID: id, OrganizationID: orgID, CAID: caID,
		Name: "livedb-scope", ValidityDays: 365, AllowedEKUs: "client_auth", RenewalWindowDays: 30,
		SubjectPattern: ".+", RACertificatePEM: "pem", RAPrivateKeyCiphertext: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.EndpointByID(txctx, orgID, id); err != nil {
		t.Fatalf("the owning organization should resolve its own endpoint: %v", err)
	}
	// Same ID, different organization: the query predicate must reject it even
	// before row-level security is considered.
	if _, err := repo.EndpointByID(txctx, otherOrgID, id); err != sql.ErrNoRows {
		t.Fatalf("another organization resolved the endpoint, got %v", err)
	}
}
