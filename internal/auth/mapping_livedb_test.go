//go:build livedb

package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestLiveDBOrganizationAndUsersMapTheirColumns is the round-trip half of the
// go-jet mapping guard. internal/database/jetmapping_test.go proves the aliases
// are shaped correctly by reading the source; this proves the rows actually
// arrive, which is the part no static check can reach.
//
// It is worth having both because the failure is silent in exactly the way that
// defeats an ordinary test: the queries below returned a zero-valued struct and
// an empty slice with a nil error, so the Users page listed nobody and the
// organization settings page rendered a blank name. Nothing errored, nothing
// logged, and the SQL was correct throughout.
func TestLiveDBOrganizationAndUsersMapTheirColumns(t *testing.T) {
	db := liveDB(t)
	_, userID, orgID := liveSession(t, db)
	repo := NewRepository(db)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(ctx, "app.auth_flow", "true"); err != nil {
		t.Fatal(err)
	}

	org, err := repo.Organization(ctx, mustUUID(t, orgID))
	if err != nil {
		t.Fatal(err)
	}
	if org.ID != orgID {
		t.Errorf("Organization.ID = %q, want %q. An empty id here is the mapper "+
			"silently filling nothing, not a missing row", org.ID, orgID)
	}
	if org.Name == "" {
		t.Error("Organization.Name is empty; the settings page renders this as the org's name")
	}

	users, err := repo.Users(ctx, mustUUID(t, orgID))
	if err != nil {
		t.Fatal(err)
	}
	if len(users) == 0 {
		t.Fatal("Users returned nothing for an organization that has a user; the Users page lists nobody")
	}
	var seeded bool
	for _, u := range users {
		if u.ID == userID {
			seeded = true
			if u.Email == "" || u.Name == "" || u.Role == "" {
				t.Errorf("Users mapped a row with empty fields: %+v", u)
			}
		}
	}
	if !seeded {
		t.Errorf("Users did not return the seeded user %s", userID)
	}

	one, err := repo.User(ctx, mustUUID(t, orgID), mustUUID(t, userID))
	if err != nil {
		t.Fatal(err)
	}
	if one.ID != userID || one.Email == "" {
		t.Errorf("User(%s) mapped as %+v", userID, one)
	}
}
