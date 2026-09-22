//go:build livedb

// Live-database checks for the audit trail's integrity. These cannot be
// expressed against a fake: what is under test is the row-level security policy
// itself, and specifically the absence of UPDATE and DELETE policies.
//
// Run with a database available:
//
//	go test -tags livedb ./internal/audit/ -run LiveDB -v
package audit

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/go-jet/jet/v2/postgres"
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

// liveProbe opens a transaction that is always rolled back, seeds a throwaway
// organization and user in it, and returns a context bound to that organization.
// Nothing it writes outlives the test.
func liveProbe(t *testing.T, db *sql.DB) (context.Context, string, string) {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	ctx := database.WithTx(context.Background(), tx)

	// organization and "user" are writable only under the auth-flow escape,
	// which is what signup itself uses.
	if err := database.SetLocal(ctx, "app.auth_flow", "true"); err != nil {
		t.Fatal(err)
	}
	var orgID, userID string
	var org struct{ ID string }
	if err := table.Organization.INSERT(table.Organization.Name).VALUES("audit-livedb-probe").
		RETURNING(table.Organization.ID.AS("ID")).QueryContext(ctx, tx, &org); err != nil {
		t.Fatal(err)
	}
	orgID = org.ID
	var user struct{ ID string }
	if err := table.User.INSERT(table.User.OrganizationID, table.User.Email, table.User.Name, table.User.Role).
		VALUES(orgID, "audit-probe@example.test", "Probe", "administrator").
		RETURNING(table.User.ID.AS("ID")).QueryContext(ctx, tx, &user); err != nil {
		t.Fatal(err)
	}
	userID = user.ID
	if err := database.SetLocal(ctx, "app.auth_flow", "false"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetLocal(ctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	return ctx, orgID, userID
}

// TestLiveDBAuditEventsCannotBeRewritten is the property the append-only
// policies exist for. The audit trail is the record of who touched a CA, so
// anything reaching the database inside an organization's own RLS context must
// be able to add to it and never to alter or erase it.
func TestLiveDBAuditEventsCannotBeRewritten(t *testing.T) {
	db := liveDB(t)
	ctx, orgID, userID := liveProbe(t, db)
	repo := NewRepository(db)

	err := repo.Record(ctx, Event{OrganizationID: orgID, ActorUserID: userID,
		ActorEmail: "audit-probe@example.test", Action: ActionSignedIn, Target: "probe",
		ActorIP: "198.51.100.7", ActorUserAgent: "probe/1.0", ActorSessionID: "session-1"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	tx, _ := database.Tx(ctx)
	res, err := table.AuditEvent.UPDATE(table.AuditEvent.Action).SET("tampered").
		WHERE(table.AuditEvent.OrganizationID.EQ(database.UUID(orgID))).ExecContext(ctx, tx)
	if err != nil {
		t.Fatalf("UPDATE errored rather than matching nothing: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("UPDATE altered %d audit rows; the trail must be append-only", n)
	}

	res, err = table.AuditEvent.DELETE().WHERE(table.AuditEvent.OrganizationID.EQ(database.UUID(orgID))).ExecContext(ctx, tx)
	if err != nil {
		t.Fatalf("DELETE errored rather than matching nothing: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("DELETE removed %d audit rows; the trail must be append-only", n)
	}

	var event struct{ Action, IP, Agent, Session string }
	err = postgres.SELECT(table.AuditEvent.Action.AS("Action"), table.AuditEvent.ActorIP.AS("IP"),
		table.AuditEvent.ActorUserAgent.AS("Agent"), table.AuditEvent.ActorSessionID.AS("Session")).
		FROM(table.AuditEvent).WHERE(table.AuditEvent.OrganizationID.EQ(database.UUID(orgID))).
		QueryContext(ctx, tx, &event)
	if err != nil {
		t.Fatalf("reading the event back: %v", err)
	}
	if event.Action != ActionSignedIn {
		t.Errorf("action = %q, want it unchanged", event.Action)
	}
	if event.IP != "198.51.100.7" || event.Agent != "probe/1.0" || event.Session != "session-1" {
		t.Errorf("actor context = %q/%q/%q, want it stored as written", event.IP, event.Agent, event.Session)
	}
}

// TestLiveDBRemovingAUserKeepsTheirAuditTrail covers the interaction the
// append-only policies could plausibly have broken. Referential integrity
// actions run with row security disabled, so ON DELETE SET NULL still clears
// the actor id even though no UPDATE policy exists — and actor_email, which is
// what a reader actually needs, survives the user it names.
func TestLiveDBRemovingAUserKeepsTheirAuditTrail(t *testing.T) {
	db := liveDB(t)
	ctx, orgID, userID := liveProbe(t, db)
	repo := NewRepository(db)

	err := repo.Record(ctx, Event{OrganizationID: orgID, ActorUserID: userID,
		ActorEmail: "audit-probe@example.test", Action: ActionUserRemoved, Target: "probe"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	tx, _ := database.Tx(ctx)
	if err := database.SetLocal(ctx, "app.auth_flow", "true"); err != nil {
		t.Fatal(err)
	}
	if _, err := table.User.DELETE().WHERE(table.User.ID.EQ(database.UUID(userID))).ExecContext(ctx, tx); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	if err := database.SetLocal(ctx, "app.auth_flow", "false"); err != nil {
		t.Fatal(err)
	}

	var event struct {
		Cleared bool
		Email   string
	}
	err = postgres.SELECT(table.AuditEvent.ActorUserID.IS_NULL().AS("Cleared"), table.AuditEvent.ActorEmail.AS("Email")).
		FROM(table.AuditEvent).WHERE(table.AuditEvent.OrganizationID.EQ(database.UUID(orgID))).
		QueryContext(ctx, tx, &event)
	if err != nil {
		t.Fatalf("reading the event back: %v", err)
	}
	if !event.Cleared {
		t.Error("ON DELETE SET NULL did not clear the actor id under the append-only policies")
	}
	if event.Email != "audit-probe@example.test" {
		t.Errorf("actor_email = %q, want it to outlive the user", event.Email)
	}
}

// TestLiveDBEventsRoundTripTheInstantTheyHappened is the property the
// TIMESTAMPTZ migration exists for, and it can only be checked against a real
// server: what was wrong was the interaction between the column type and the
// server's zone, which no fake reproduces.
//
// Under the old bare TIMESTAMP, now() was recorded as local wall-clock time and
// handed back to Go labelled UTC, so a row written at 20:50 in New York came
// back as 20:50 UTC — four hours late, on the page, in the CSV column named
// timestamp_utc, and in every date comparison. This asserts the round trip is
// now within a minute of when the write actually happened, which fails by whole
// hours if either column regresses to TIMESTAMP.
func TestLiveDBEventsRoundTripTheInstantTheyHappened(t *testing.T) {
	db := liveDB(t)
	ctx, orgID, userID := liveProbe(t, db)
	repo := NewRepository(db)

	before := time.Now()
	err := repo.Record(ctx, Event{OrganizationID: orgID, ActorUserID: userID,
		ActorEmail: "audit-probe@example.test", Action: ActionSignedIn, Target: "probe",
		ActorIP: "198.51.100.7", ActorUserAgent: "probe/1.0", ActorSessionID: "session-1"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	events, err := repo.Events(ctx, orgID, Filter{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	// A minute either way. The failure this catches is a whole-hour shift, and
	// the slack absorbs ordinary clock skew between the application host and the
	// database, which can put the server's now() a few milliseconds either side.
	if drift := events[0].At.Sub(before); drift < -time.Minute || drift > time.Minute {
		t.Errorf("event recorded at %s but written at %s (drift %s); the column is not carrying a zone",
			events[0].At, before, drift)
	}

	// The actor context is written by Record and has to survive the read, or the
	// page and the CSV export have no address, client, or session to show.
	if events[0].ActorIP != "198.51.100.7" || events[0].ActorUserAgent != "probe/1.0" ||
		events[0].ActorSessionID != "session-1" {
		t.Errorf("actor context read back as %q/%q/%q, want it carried through Events",
			events[0].ActorIP, events[0].ActorUserAgent, events[0].ActorSessionID)
	}
}

// TestLiveDBDateFilterSelectsTheRightDay is the other half of the zone bug. The
// filter bounds are UTC midnights, so an event has to fall inside its own UTC
// day and outside the neighbouring ones. On a non-UTC server with a bare
// TIMESTAMP column, an event within the server's offset of midnight landed on
// the wrong side of both bounds.
func TestLiveDBDateFilterSelectsTheRightDay(t *testing.T) {
	db := liveDB(t)
	ctx, orgID, userID := liveProbe(t, db)
	repo := NewRepository(db)

	if err := repo.Record(ctx, Event{OrganizationID: orgID, ActorUserID: userID,
		ActorEmail: "audit-probe@example.test", Action: ActionSignedIn, Target: "probe"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	today := time.Now().UTC().Format("2006-01-02")
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")

	for _, tc := range []struct {
		name     string
		from, to string
		want     int
	}{
		{"its own UTC day", today, today, 1},
		{"the day before", yesterday, yesterday, 0},
		{"the day after", tomorrow, tomorrow, 0},
		{"a span containing it", yesterday, tomorrow, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events, err := repo.Events(ctx, orgID, Filter{From: Day(tc.from, false), To: Day(tc.to, true)})
			if err != nil {
				t.Fatalf("Events: %v", err)
			}
			if len(events) != tc.want {
				t.Errorf("%s..%s matched %d events, want %d", tc.from, tc.to, len(events), tc.want)
			}
		})
	}
}

// TestLiveDBEveryOfferedActionIsRecordable checks the audit filter against the
// database rather than against itself. Actions is what the page's event-type
// dropdown lists, action is VARCHAR(64), and an action that overflowed it or
// that the filter could not match would be an option a reader could select and
// never get results for.
func TestLiveDBEveryOfferedActionIsRecordable(t *testing.T) {
	db := liveDB(t)
	ctx, orgID, userID := liveProbe(t, db)
	repo := NewRepository(db)

	for _, action := range Actions {
		// Derived in SQL from the signing audit's purpose column rather than
		// written to audit_event, so there is no insert to check.
		if isSigningAction(action) {
			continue
		}
		if err := repo.Record(ctx, Event{OrganizationID: orgID, ActorUserID: userID,
			ActorEmail: "audit-probe@example.test", Action: action, Target: "probe"}); err != nil {
			t.Errorf("Record(%s): %v", action, err)
			continue
		}
		events, err := repo.Events(ctx, orgID, Filter{Action: action})
		if err != nil {
			t.Errorf("Events(action=%s): %v", action, err)
			continue
		}
		if len(events) != 1 {
			t.Errorf("filtering on %s matched %d events, want 1", action, len(events))
		}
		if len(events) == 1 && ActionLabel(events[0].Action) == "Other activity" && action != ActionOther {
			t.Errorf("%s has no label, so the filter offers it as %q", action, "Other activity")
		}
	}
}

// isSigningAction reports whether the action comes from certificate_signing_audit
// via signingAction rather than from an audit_event row.
func isSigningAction(action string) bool {
	switch action {
	case ActionRootCACreated, ActionIssuingCACreated, ActionCAImported, ActionCADeleted,
		ActionCAActivated, ActionCADeactivated, ActionCARetired, ActionCARotated,
		ActionCertificateIssued, ActionCertificateRevoked, ActionOther:
		return true
	}
	return false
}
