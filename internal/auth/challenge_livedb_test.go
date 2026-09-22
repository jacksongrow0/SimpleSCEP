//go:build livedb

package auth

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

// liveChallenge seeds an organization, a user and an open login challenge.
func liveChallenge(t *testing.T, db *sql.DB) (challengeID uuid.UUID, userID string) {
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
	var orgID string
	if err := tx.QueryRowContext(seed, `INSERT INTO organization (name) VALUES ('LiveDB Challenge Org') RETURNING id`).Scan(&orgID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(seed,
		`INSERT INTO "user" (organization_id, email, name, role) VALUES ($1, $2, 'Live Tester', 'administrator') RETURNING id`,
		orgID, "livedb-"+uuid.NewString()+"@example.com").Scan(&userID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	var id string
	if err := tx.QueryRowContext(seed,
		`INSERT INTO login_challenge (user_id, stage, expires_at) VALUES ($1, 'enroll', localtimestamp + interval '15 minutes') RETURNING id`,
		userID).Scan(&id); err != nil {
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
			`DELETE FROM login_challenge WHERE user_id IN (SELECT id FROM "user" WHERE organization_id = $1)`,
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
	return uuid.MustParse(id), userID
}

// TestLiveDBChallengeByIDResolvesTheChallenge asserts on the fields, not just on
// the error: an unmapped destination returns a zero value and a nil error.
func TestLiveDBChallengeByIDResolvesTheChallenge(t *testing.T) {
	db := liveDB(t)
	challengeID, userID := liveChallenge(t, db)

	repo := NewRepository(db)
	var c Challenge
	err := repo.AuthFlow(context.Background(), func(ctx context.Context) error {
		var err error
		c, err = repo.ChallengeByID(ctx, challengeID)
		return err
	})
	if err != nil {
		t.Fatalf("resolving a valid challenge failed: %v", err)
	}
	t.Logf("challenge: %+v", c)
	if c.ID != challengeID {
		t.Errorf("challenge ID is %q, want %q", c.ID, challengeID)
	}
	if c.UserID.String() != userID {
		t.Errorf("challenge UserID is %q, want %q", c.UserID, userID)
	}
	if c.Stage != StageEnroll {
		t.Errorf("challenge Stage is %q, want %q", c.Stage, StageEnroll)
	}
}

// TestLiveDBSpendChallengeAttemptResolvesTheChallenge covers the RETURNING
// variant, which has the same destination.
func TestLiveDBSpendChallengeAttemptResolvesTheChallenge(t *testing.T) {
	db := liveDB(t)
	challengeID, userID := liveChallenge(t, db)

	repo := NewRepository(db)
	var c Challenge
	err := repo.AuthFlow(context.Background(), func(ctx context.Context) error {
		var err error
		c, err = repo.SpendChallengeAttempt(ctx, challengeID)
		return err
	})
	if err != nil {
		t.Fatalf("spending an attempt on a valid challenge failed: %v", err)
	}
	t.Logf("challenge: %+v", c)
	if c.ID != challengeID || c.UserID.String() != userID {
		t.Errorf("spent challenge did not map: %+v", c)
	}
	if c.Attempts != 1 {
		t.Errorf("attempts is %d, want 1", c.Attempts)
	}
}
