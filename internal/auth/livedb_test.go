//go:build livedb

// Live-database checks for the session lookup. This is the one query whose
// failure mode cannot be reproduced against a fake: go-jet decides how to map a
// result set onto a destination at runtime, using the destination's type, so a
// store that never runs the mapper cannot tell that the mapping is wrong.
//
// Run with a database available:
//
//	LIVEDB_URL=postgres://... go test -tags livedb ./internal/auth/ -run LiveDB -v
package auth

import (
	"context"
	"database/sql"
	"os"
	"testing"

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

// liveSession seeds an organization, a user and a session, and removes them
// afterwards. Deletion is child-first: there is no cascade from organization
// down to user or session.
func liveSession(t *testing.T, db *sql.DB) (sessionID uuid.UUID, userID, orgID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := database.WithTx(ctx, tx)
	if err := database.SetLocal(seed, "app.auth_flow", "true"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	err = tx.QueryRowContext(seed, `INSERT INTO organization (name) VALUES ('LiveDB Session Org') RETURNING id`).Scan(&orgID)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	err = tx.QueryRowContext(seed,
		`INSERT INTO "user" (organization_id, email, name, role) VALUES ($1, $2, 'Live Tester', 'administrator') RETURNING id`,
		orgID, "livedb-"+uuid.NewString()+"@example.com").Scan(&userID)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	var id string
	err = tx.QueryRowContext(seed,
		`INSERT INTO session (user_id, organization_id, expires_at) VALUES ($1, $2, localtimestamp + interval '1 hour') RETURNING id`,
		userID, orgID).Scan(&id)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			return
		}
		ctx := database.WithTx(context.Background(), cleanup)
		if err := database.SetLocal(ctx, "app.auth_flow", "true"); err != nil {
			cleanup.Rollback()
			return
		}
		for _, statement := range []string{
			`DELETE FROM session WHERE organization_id = $1`,
			`DELETE FROM "user" WHERE organization_id = $1`,
			`DELETE FROM organization WHERE id = $1`,
		} {
			if _, err := cleanup.ExecContext(ctx, statement, orgID); err != nil {
				cleanup.Rollback()
				return
			}
		}
		cleanup.Commit()
	})
	return uuid.MustParse(id), userID, orgID
}

// TestLiveDBSessionByIDResolvesTheSession is a regression test for a mapping bug
// that broke every authenticated request in the service.
//
// SessionByID scanned into the named Session struct. go-jet resolves a named
// struct destination against the tables in the result set, Session names no
// table, and so every column went unmapped — the query returned a zero value and
// a *nil error*. Nothing failed at the point of the mistake. The visible symptom
// was the second query, one line later, rejecting `CAST(” AS uuid)` with
// "invalid input syntax for type uuid", which names neither the empty column nor
// the query that produced it.
//
// Asserting on the fields is the whole point: a destination that maps nothing
// still returns successfully, so a test that only checked the error would have
// passed against the bug.
func TestLiveDBSessionByIDResolvesTheSession(t *testing.T) {
	db := liveDB(t)
	sessionID, userID, orgID := liveSession(t, db)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(ctx, "app.session_id", sessionID.String()); err != nil {
		t.Fatal(err)
	}

	session, err := NewRepository(db).SessionByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("resolving a valid session failed: %v", err)
	}
	if session.ID != sessionID.String() {
		t.Errorf("session ID is %q, want %q", session.ID, sessionID)
	}
	if session.UserID != userID {
		t.Errorf("session UserID is %q, want %q", session.UserID, userID)
	}
	if session.OrgID != orgID {
		t.Errorf("session OrgID is %q, want %q", session.OrgID, orgID)
	}
	// From the second query, which had the same destination problem.
	if session.Email == "" || session.Name != "Live Tester" || session.Role != "administrator" {
		t.Errorf("the account half of the session did not map: %+v", session)
	}
	if session.OrganizationName != "LiveDB Session Org" {
		t.Errorf("organization name is %q", session.OrganizationName)
	}
}

// TestLiveDBUsersIncludesCurrentUser covers the custom users-page row mapping.
func TestLiveDBUsersIncludesCurrentUser(t *testing.T) {
	db := liveDB(t)
	sessionID, userID, orgID := liveSession(t, db)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(ctx, "app.session_id", sessionID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(db).SessionByID(ctx, sessionID); err != nil {
		t.Fatal(err)
	}
	users, err := NewRepository(db).Users(ctx, uuid.MustParse(orgID))
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("users = %#v, want the current user", users)
	}
	if users[0].ID != userID || users[0].Name != "Live Tester" {
		t.Errorf("current user mapped as %#v", users[0])
	}
}

// TestLiveDBSessionByIDRejectsAnExpiredSession pins that an expired row is a
// not-found rather than a session with empty fields, which is what the mapping
// bug turned every lookup into.
func TestLiveDBSessionByIDRejectsAnExpiredSession(t *testing.T) {
	db := liveDB(t)
	sessionID, _, orgID := liveSession(t, db)

	expire, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := database.WithTx(context.Background(), expire)
	if err := database.SetLocal(ctx, "app.auth_flow", "true"); err != nil {
		expire.Rollback()
		t.Fatal(err)
	}
	if _, err := expire.ExecContext(ctx,
		`UPDATE session SET expires_at = localtimestamp - interval '1 minute' WHERE organization_id = $1`, orgID); err != nil {
		expire.Rollback()
		t.Fatal(err)
	}
	if err := expire.Commit(); err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	lookup := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(lookup, "app.session_id", sessionID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(db).SessionByID(lookup, sessionID); err == nil {
		t.Error("an expired session resolved successfully")
	}
}
