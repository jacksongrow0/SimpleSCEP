//go:build livedb

// Live-database checks for pending invitations.
//
// These exist because go-jet's mapper fails silently — zero rows, nil error, correct
// SQL — whenever a scan destination and its aliases disagree, and because every one
// of these queries is new. A static check on the aliases lives in
// internal/database/jetmapping_test.go; this is the half that proves the rows arrive.
//
//	go test -tags livedb ./internal/auth/ -run LiveDBInvitation -v
package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

// invitationProbe seeds one pending invitation in a rolled-back transaction and
// returns the context, the organization, and the invitation's id.
func invitationProbe(t *testing.T, name string) (context.Context, uuid.UUID, uuid.UUID) {
	t.Helper()
	db := liveDB(t)
	_, _, orgID := liveSession(t, db)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	ctx := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(ctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}

	org := mustUUID(t, orgID)
	repo := NewRepository(db)
	if err := repo.CreateInvitation(ctx, org, "dana@acme.example", name,
		"certificate_manager", "hash-"+uuid.NewString(), time.Now().Add(invitationTTL)); err != nil {
		t.Fatal(err)
	}
	pending, err := repo.PendingInvitations(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("PendingInvitations returned %d rows, want 1; the mapping is silently empty", len(pending))
	}
	return ctx, org, mustUUID(t, pending[0].ID)
}

// TestLiveDBInvitationCarriesTheNameItWasGiven is the defect this column exists
// for. The invite dialog collected a "Full name" and the handler discarded it, so
// AcceptInvitation fell back to strings.Split(email, "@")[0] and an administrator
// who typed "Dana Whitfield" got a member listed as "dana".
func TestLiveDBInvitationCarriesTheNameItWasGiven(t *testing.T) {
	db := liveDB(t)
	ctx, org, _ := invitationProbe(t, "Dana Whitfield")
	repo := NewRepository(db)

	pending, err := repo.PendingInvitations(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	got := pending[0]
	if got.Name != "Dana Whitfield" {
		t.Errorf("Name = %q, want %q", got.Name, "Dana Whitfield")
	}
	if got.Email != "dana@acme.example" {
		t.Errorf("Email = %q", got.Email)
	}
	if got.Role != "certificate_manager" {
		t.Errorf("Role = %q", got.Role)
	}
	// Both timestamps must arrive, or the page cannot say whether the link works.
	if got.CreatedAt.IsZero() || got.ExpiresAt.IsZero() {
		t.Errorf("timestamps did not map: created=%v expires=%v", got.CreatedAt, got.ExpiresAt)
	}
	if !got.ExpiresAt.After(time.Now()) {
		t.Errorf("a freshly created invitation expires at %v, which is already past", got.ExpiresAt)
	}
}

// TestLiveDBInvitationWithNoNameStoresNull pins the distinction between "nobody
// gave a name" and "the name is empty". The accept path needs the former to reach
// its local-part fallback; an empty string would be taken as a name and render a
// member with none.
func TestLiveDBInvitationWithNoNameStoresNull(t *testing.T) {
	db := liveDB(t)
	ctx, org, _ := invitationProbe(t, "   ")
	repo := NewRepository(db)

	pending, err := repo.PendingInvitations(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if pending[0].Name != "" {
		t.Errorf("a blank name was stored as %q rather than left unset", pending[0].Name)
	}
}

// TestLiveDBInvitationCanBeRevoked is the whole point of the new routes: before
// them, a token emailed to a mistyped address worked for seven days and nothing
// could stop it.
func TestLiveDBInvitationCanBeRevoked(t *testing.T) {
	db := liveDB(t)
	ctx, org, id := invitationProbe(t, "Dana Whitfield")
	repo := NewRepository(db)

	if _, err := repo.InvitationByID(ctx, org, id); err != nil {
		t.Fatalf("the invitation could not be read back: %v", err)
	}
	if err := repo.DeleteInvitation(ctx, org, id); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	pending, err := repo.PendingInvitations(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("%d invitations remain after revoking", len(pending))
	}
	// Revoking twice must report that there was nothing to revoke rather than
	// succeeding silently — the second press comes from a stale page, and the
	// person needs to know the list they are looking at has moved on.
	if err := repo.DeleteInvitation(ctx, org, id); err == nil {
		t.Error("revoking an already-revoked invitation reported success")
	}
}

// TestLiveDBInvitationLookupIsScopedToTheOrganization: the id comes from a URL, so
// the query must not rely on row security being the only thing in the way.
func TestLiveDBInvitationLookupIsScopedToTheOrganization(t *testing.T) {
	db := liveDB(t)
	ctx, _, id := invitationProbe(t, "Dana Whitfield")
	repo := NewRepository(db)

	other := uuid.New()
	if _, err := repo.InvitationByID(ctx, other, id); err == nil {
		t.Error("an invitation was readable under a different organization id")
	}
	if err := repo.DeleteInvitation(ctx, other, id); err == nil {
		t.Error("an invitation was revocable under a different organization id")
	}
}
