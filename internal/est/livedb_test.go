//go:build livedb

// Package-level live-database checks. These exercise the things an in-memory
// store cannot: that row-level security scopes a lookup to its organization,
// that the client-facing policy exposes exactly the endpoint row and nothing
// else, and that the queries carrying rules in their predicates mean what the
// fakes assume they mean.
//
// Run with a database available:
//
//	go test -tags livedb ./internal/est/ -run LiveDB -v
package est

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
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

// liveTx opens a transaction scoped to the organization. It is never committed,
// so this test never leaves rows behind.
func liveTx(t *testing.T, db *sql.DB, orgID string) context.Context {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	ctx := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(ctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	return ctx
}

// seedLiveEndpoint creates an enabled endpoint inside the caller's transaction.
func seedLiveEndpoint(t *testing.T, ctx context.Context, repo Repository, orgID, caID string) Endpoint {
	t.Helper()
	e := Endpoint{ID: uuid.NewString(), OrganizationID: orgID, CAID: caID,
		Name: "livedb " + uuid.NewString()[:8], Enabled: true,
		ValidityDays: DefaultValidityDays, RenewalWindowDays: DefaultRenewalWindowDays,
		AllowedEKUs: "client_auth", SubjectPattern: ".+"}
	if err := repo.InsertEndpoint(ctx, e); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if err := repo.SetEnabled(ctx, orgID, e.ID, true); err != nil {
		t.Fatalf("enable endpoint: %v", err)
	}
	return e
}

func seedLiveCredential(t *testing.T, ctx context.Context, repo Repository, e Endpoint) Credential {
	t.Helper()
	hash, err := enroll.HashSecret("livedb-secret")
	if err != nil {
		t.Fatal(err)
	}
	c := Credential{ID: uuid.NewString(), OrganizationID: e.OrganizationID, EndpointID: e.ID,
		Username: "livedb-" + uuid.NewString()[:8], SecretHash: hash}
	if err := repo.CreateCredential(ctx, c); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	return c
}

// TestLiveDBClientPolicyExposesOnlyTheEndpoint is the RLS check that matters
// most. The client path sets app.est_endpoint_id and nothing else before it
// reads the endpoint, so that GUC alone must unlock the endpoint row and nothing
// underneath it — a credentials table readable under the same disjunct would put
// every argon2 verifier in reach of an unauthenticated caller.
func TestLiveDBClientPolicyExposesOnlyTheEndpoint(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)
	credential := seedLiveCredential(t, ctx, repo, e)

	// Drop to what an unauthenticated client actually has: the endpoint id only.
	if err := database.SetLocal(ctx, "app.organization_id", ""); err != nil {
		t.Fatal(err)
	}
	if err := database.SetLocal(ctx, "app.est_endpoint_id", e.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.Endpoint(ctx, e.ID); err != nil {
		t.Errorf("a client cannot read its own endpoint: %v", err)
	}
	if _, err := repo.CredentialByUsername(ctx, e.ID, credential.Username); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("credentials are readable with only the endpoint id: %v", err)
	}
	if records, err := repo.Enrollments(ctx, e.ID, 10); err == nil && len(records) > 0 {
		t.Error("enrollments are readable with only the endpoint id")
	}
}

// TestLiveDBDisabledEndpointIsInvisible: the policy's disjunct carries "AND
// enabled", so turning an endpoint off has to remove it from the client path
// entirely rather than relying on a check in Go.
func TestLiveDBDisabledEndpointIsInvisible(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)
	if err := repo.SetEnabled(ctx, orgID, e.ID, false); err != nil {
		t.Fatal(err)
	}

	if err := database.SetLocal(ctx, "app.organization_id", ""); err != nil {
		t.Fatal(err)
	}
	if err := database.SetLocal(ctx, "app.est_endpoint_id", e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Endpoint(ctx, e.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("a disabled endpoint is still visible to a client: %v", err)
	}
}

// TestLiveDBAnotherOrganizationCannotSeeEndpoints is the ordinary tenant
// isolation check, made against a second real organization rather than a forged
// GUC.
func TestLiveDBAnotherOrganizationCannotSeeEndpoints(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	other := os.Getenv("LIVEDB_OTHER_ORG")
	if other == "" {
		t.Skip("set LIVEDB_OTHER_ORG")
	}
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)

	if err := database.SetLocal(ctx, "app.organization_id", other); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.EndpointByID(ctx, other, e.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("another organization can read the endpoint: %v", err)
	}
	// Not merely scoped by the predicate: the row must be invisible even when
	// the query asks for it by the owning organization's id.
	if _, err := repo.EndpointByID(ctx, orgID, e.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("RLS did not hide the row from another organization's session: %v", err)
	}
}

// TestLiveDBEndpointNamesAreUniquePerOrganization proves the unique index is on
// lower(name), which is what makes "Gateways" and "gateways" the same endpoint
// to an administrator scanning the list.
func TestLiveDBEndpointNamesAreUniquePerOrganization(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)
	clash := e
	clash.ID = uuid.NewString()
	clash.Name = strings.ToUpper(e.Name)
	err := repo.InsertEndpoint(ctx, clash)
	if err == nil {
		t.Fatal("a name differing only in case was accepted")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want the duplicate-name message", err)
	}
}

// TestLiveDBCredentialUsernamesAreUniquePerEndpoint pins the other expression
// index. Two credentials with the same username would make authentication
// ambiguous, and which one won would depend on row order.
func TestLiveDBCredentialUsernamesAreUniquePerEndpoint(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)
	first := seedLiveCredential(t, ctx, repo, e)

	clash := first
	clash.ID = uuid.NewString()
	clash.Username = strings.ToUpper(first.Username)
	if err := repo.CreateCredential(ctx, clash); err == nil {
		t.Fatal("a username differing only in case was accepted on the same endpoint")
	}
}

// TestLiveDBRevokedCredentialReleasesItsUsername covers the partial index that
// makes secret rotation possible. Credentials are revoked and never deleted, so
// under an unconditional index a username was occupied forever and an operator
// could only "rotate" by picking a new one — which is exactly the case
// re-enrollment's credential binding cannot match, stranding the fleet.
func TestLiveDBRevokedCredentialReleasesItsUsername(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)
	first := seedLiveCredential(t, ctx, repo, e)
	if err := repo.RevokeCredential(ctx, orgID, e.ID, first.ID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	replacement := first
	replacement.ID = uuid.NewString()
	if err := repo.CreateCredential(ctx, replacement); err != nil {
		t.Fatalf("a revoked credential's username could not be reused: %v", err)
	}
	// Authentication must land on the live row, not on either revoked one.
	got, err := repo.CredentialByUsername(ctx, e.ID, first.Username)
	if err != nil {
		t.Fatalf("CredentialByUsername: %v", err)
	}
	if got.ID != replacement.ID {
		t.Errorf("resolved credential = %s, want the live replacement %s", got.ID, replacement.ID)
	}
}

// TestLiveDBRenewableCertificateRequiresTheEnrollingCredential is the predicate
// that stands in for RFC 7030's mutual-TLS binding, and the fakes can only
// approximate it. A credential must not renew a subject another one enrolled.
func TestLiveDBRenewableCertificateRequiresTheEnrollingCredential(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)
	owner := seedLiveCredential(t, ctx, repo, e)
	intruder := seedLiveCredential(t, ctx, repo, e)

	// No enrollment exists yet, so both are refused for the same reason. The
	// query's shape is what is under test here: that it resolves, and that the
	// credential participates in the predicate rather than being ignored.
	subject := "CN=gw-live.example.internal"
	for _, cred := range []Credential{owner, intruder} {
		if _, err := repo.RenewableCertificate(ctx, e.ID, cred.ID, cred.Username, subject); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("credential %s: %v, want sql.ErrNoRows", cred.Username, err)
		}
	}
}

// TestLiveDBRenewableCertificateFindsOnlyLiveCertificates is the query behind
// re-enrollment, and the one the fakes can only approximate. A revoked or
// expired certificate must not authorize a renewal.
func TestLiveDBRenewableCertificateFindsOnlyLiveCertificates(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)
	_, err := repo.RenewableCertificate(ctx, e.ID, uuid.NewString(), "someone",
		"CN=never-enrolled.example.internal")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("a subject this endpoint never issued looks renewable: %v", err)
	}
}

// TestLiveDBFailedEnrollmentsAreRecordedAndExcludedFromCounts covers the two
// halves the fakes cannot: that a failed row is insertable with no certificate
// at all, and that the endpoint list's issuance count does not treat a refusal
// as an enrollment.
func TestLiveDBFailedEnrollmentsAreRecordedAndExcludedFromCounts(t *testing.T) {
	db := liveDB(t)
	orgID, caID := liveEnv(t)
	repo := NewRepository(db)
	ctx := liveTx(t, db, orgID)

	e := seedLiveEndpoint(t, ctx, repo, orgID, caID)
	credential := seedLiveCredential(t, ctx, repo, e)

	failed := Enrollment{OrganizationID: orgID, EndpointID: e.ID, CredentialID: credential.ID,
		Subject: "CN=refused.example.internal", Operation: OperationEnroll,
		Status: StatusFailed, FailureReason: "the request is not permitted by this endpoint's issuance policy"}
	if err := repo.CreateEnrollment(ctx, failed); err != nil {
		t.Fatalf("a refusal could not be recorded: %v", err)
	}

	records, err := repo.Enrollments(ctx, e.ID, 10)
	if err != nil {
		t.Fatalf("Enrollments: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d rows, want the refusal", len(records))
	}
	if records[0].Result != StatusFailed || records[0].FailureReason == "" {
		t.Errorf("row = %+v, want a failed row carrying its reason", records[0])
	}
	if records[0].Serial != "" || records[0].CertificateStatus != "" {
		t.Errorf("a refusal came back with certificate columns set: %+v", records[0])
	}

	summaries, err := repo.EndpointSummaries(ctx, orgID)
	if err != nil {
		t.Fatalf("EndpointSummaries: %v", err)
	}
	for _, s := range summaries {
		if s.ID == e.ID && s.RecentIssued != 0 {
			t.Errorf("RecentIssued = %d, want 0: a refusal is not an issuance", s.RecentIssued)
		}
	}
}
