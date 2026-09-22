//go:build livedb

// Live-database checks for the overview page's queries.
//
// Run with a database available:
//
//	go test -tags livedb ./internal/home/ -run LiveDB -v
package home

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jacksongrow0/SimpleSCEP/internal/acme"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/est"
	"github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/jacksongrow0/SimpleSCEP/internal/scep"
)

func overviewLiveDB(t *testing.T) *sql.DB {
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

// TestLiveDBOverviewQueriesExecute runs every query the overview path
// makes and requires each to execute.
//
// It needs no fixtures and asserts nothing about the numbers, which is the
// whole point: what it catches is a statement Postgres refuses to plan, and a
// planning error is raised whether or not a single row exists. An empty
// database is therefore full coverage for this class of bug.
//
// It exists because pki.ExpiringIdentityCount could not be planned at all, and
// nothing noticed until the page every user lands on first answered "overview
// failed" and the only detail went to the server log.
//
// Each query is run and reported separately rather than short-circuiting. The
// first failure aborts the transaction, so a single-error version would report
// "current transaction is aborted" for every query after it and bury the one
// that actually broke.
func TestLiveDBOverviewQueriesExecute(t *testing.T) {
	db := overviewLiveDB(t)
	// Any organization id will do. These queries are being checked for whether
	// the server will plan them, not for what they return.
	orgID := uuid.NewString()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(ctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}

	p := pki.NewRepository(db)
	sc, ac, es := scep.NewRepository(db), acme.NewRepository(db), est.NewRepository(db)
	for _, q := range []struct {
		name string
		run  func() error
	}{
		{"pki.CAs", func() error { _, err := p.CAs(ctx, orgID); return err }},
		{"pki.ActiveIdentityCount", func() error { _, err := p.ActiveIdentityCount(ctx, orgID); return err }},
		{"pki.ExpiringIdentityCount", func() error { _, err := p.ExpiringIdentityCount(ctx, orgID, 30); return err }},
		{"pki.Certificates", func() error { _, err := p.Certificates(ctx, orgID); return err }},
		{"scep.EndpointSummaries", func() error { _, err := sc.EndpointSummaries(ctx, orgID); return err }},
		{"acme.EndpointSummaries", func() error { _, err := ac.EndpointSummaries(ctx, orgID); return err }},
		{"est.EndpointSummaries", func() error { _, err := es.EndpointSummaries(ctx, orgID); return err }},
	} {
		if err := q.run(); err != nil {
			t.Errorf("%s could not be executed, so the overview page answers "+
				"\"overview failed\" for every organization: %v", q.name, err)
			// The transaction is poisoned once a statement fails, so restart it
			// rather than reporting the same abort for everything that follows.
			tx.Rollback()
			if tx, err = db.BeginTx(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			ctx = database.WithTx(context.Background(), tx)
			if err := database.SetLocal(ctx, "app.organization_id", orgID); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestLiveDBAdminQueriesExecute is the same planning check for the queries the
// overview does not touch: the counts consulted when a CA or an endpoint is
// created, and the reads behind the audit page.
//
// The counts are here because pki.Repository.count was built on
// COUNT(Int(1)). jet renders a literal as a bind parameter, so that went to
// Postgres as COUNT($1) — a parameter with no inferable type — and every one of
// these five queries failed with "could not determine data type of parameter
// $1".
//
// Like the overview test this needs no fixtures: a statement Postgres will not
// plan is refused whether or not any rows exist.
func TestLiveDBAdminQueriesExecute(t *testing.T) {
	db := overviewLiveDB(t)
	orgID, caID := uuid.NewString(), uuid.NewString()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(ctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	restart := func() {
		tx.Rollback()
		var err error
		if tx, err = db.BeginTx(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		ctx = database.WithTx(context.Background(), tx)
		if err := database.SetLocal(ctx, "app.organization_id", orgID); err != nil {
			t.Fatal(err)
		}
	}

	p := pki.NewRepository(db)
	sc := scep.NewRepository(db)
	au := audit.NewRepository(db)
	for _, q := range []struct {
		name string
		run  func() error
	}{
		// Every caller of pki.Repository.count.
		{"pki.IssuingCACount", func() error { _, err := p.IssuingCACount(ctx, orgID); return err }},
		{"pki.ActiveChildCount", func() error { _, err := p.ActiveChildCount(ctx, orgID, caID); return err }},
		{"pki.EnabledSCEPEndpointCount", func() error { _, err := p.EnabledSCEPEndpointCount(ctx, orgID, caID); return err }},
		{"pki.EnabledACMEEndpointCount", func() error { _, err := p.EnabledACMEEndpointCount(ctx, orgID, caID); return err }},
		{"pki.EnabledESTEndpointCount", func() error { _, err := p.EnabledESTEndpointCount(ctx, orgID, caID); return err }},
		// The remaining reads behind the pages an administrator lands on.
		{"pki.RootCA", func() error { _, err := p.RootCA(ctx, orgID); return err }},
		{"scep.EndpointCount", func() error { _, err := sc.EndpointCount(ctx, orgID); return err }},
		{"audit.Events", func() error { _, err := au.Events(ctx, orgID, audit.Filter{}); return err }},
		{"audit.Count", func() error { _, err := au.Count(ctx, orgID); return err }},
	} {
		// ErrNoRows means the server planned and ran the statement and the org
		// simply has nothing — which is the expected answer here and not a
		// failure. What this test is looking for is a statement Postgres
		// refuses outright.
		if err := q.run(); err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("%s could not be executed: %v", q.name, err)
			restart()
		}
	}
}
