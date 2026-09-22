//go:build livedb

// Live-database checks for the authenticator set.
//
// These queries cannot be exercised against a fake for the reason livedb_test.go
// gives: go-jet decides how to map a result set onto a destination at runtime,
// so a store that never runs the mapper cannot tell that the mapping is wrong.
// TOTPCredential and PendingTOTP are both new named destinations, which is
// exactly the shape that returns zero rows and a nil error when it is wrong.
//
// The delete rule is here rather than in a unit test for a different reason: the
// refusal to remove the last authenticator lives in the statement's EXISTS arm,
// so only the database can be asked whether it holds.
//
//	LIVEDB_URL=postgres://... go test -tags livedb ./internal/auth/ -run LiveDBTOTP -v
package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

// userContext runs against the user-scoped RLS arm, which is the context the
// settings panel's requests actually carry. The auth-flow arm would admit these
// rows too, and would therefore prove nothing about the policy the panel relies
// on.
func userContext(t *testing.T, db *sql.DB, userID string) context.Context {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	ctx := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(ctx, "app.user_id", userID); err != nil {
		t.Fatal(err)
	}
	return ctx
}

// TestLiveDBTOTPCredentialsMap is the mapping check. A destination that maps
// nothing still returns successfully, so asserting on the fields is the point:
// a test that only checked the error would pass against the bug it exists for.
func TestLiveDBTOTPCredentialsMap(t *testing.T) {
	db := liveDB(t)
	_, userID, _ := liveSession(t, db)
	repo := NewRepository(db)
	ctx := userContext(t, db, userID)

	id, err := repo.SaveTOTPCredential(ctx, uuid.MustParse(userID), "Live phone", []byte("sealed-secret"))
	if err != nil {
		t.Fatalf("saving an authenticator: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("SaveTOTPCredential returned the nil UUID; the RETURNING clause did not map")
	}

	credentials, err := repo.TOTPCredentials(ctx, uuid.MustParse(userID))
	if err != nil {
		t.Fatalf("listing authenticators: %v", err)
	}
	if len(credentials) != 1 {
		t.Fatalf("got %d authenticators, want 1", len(credentials))
	}
	got := credentials[0]
	if got.ID != id {
		t.Errorf("ID is %v, want %v", got.ID, id)
	}
	if got.Label != "Live phone" {
		t.Errorf("Label is %q, want %q", got.Label, "Live phone")
	}
	if string(got.Secret) != "sealed-secret" {
		t.Errorf("Secret is %q; the sealed column did not map", got.Secret)
	}
	if got.ConfirmedAt.IsZero() {
		t.Error("ConfirmedAt is zero; the timestamp did not map")
	}
	if got.LastUsedAt != nil {
		t.Errorf("LastUsedAt is %v on a credential that has never been used", got.LastUsedAt)
	}
}

// TestLiveDBAdvanceTOTPStepIsPerCredential pins that each authenticator carries
// its own high-water mark. A shared one would mean using the phone in your
// pocket made the next code from the key in your drawer look replayed.
func TestLiveDBAdvanceTOTPStepIsPerCredential(t *testing.T) {
	db := liveDB(t)
	_, userID, _ := liveSession(t, db)
	repo := NewRepository(db)
	ctx := userContext(t, db, userID)
	id := uuid.MustParse(userID)

	first, err := repo.SaveTOTPCredential(ctx, id, "First", []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.SaveTOTPCredential(ctx, id, "Second", []byte("b"))
	if err != nil {
		t.Fatal(err)
	}

	if advanced, err := repo.AdvanceTOTPStep(ctx, first, 5000); err != nil || !advanced {
		t.Fatalf("advancing the first credential: advanced=%v err=%v", advanced, err)
	}
	// The same step on the same credential is the replay the guard exists for.
	if advanced, err := repo.AdvanceTOTPStep(ctx, first, 5000); err != nil || advanced {
		t.Errorf("a replayed step advanced the first credential again: advanced=%v err=%v", advanced, err)
	}
	// The sibling is untouched, which is the property being pinned.
	if advanced, err := repo.AdvanceTOTPStep(ctx, second, 5000); err != nil || !advanced {
		t.Errorf("the second credential inherited the first's step: advanced=%v err=%v", advanced, err)
	}
}

// TestLiveDBDeleteTOTPCredentialKeepsTheLastOne is the floor. Mandatory
// second-factor enrolment means "at least one row here", and the delete
// statement is where that is enforced.
func TestLiveDBDeleteTOTPCredentialKeepsTheLastOne(t *testing.T) {
	db := liveDB(t)
	_, userID, _ := liveSession(t, db)
	repo := NewRepository(db)
	ctx := userContext(t, db, userID)
	id := uuid.MustParse(userID)

	first, err := repo.SaveTOTPCredential(ctx, id, "First", []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.SaveTOTPCredential(ctx, id, "Second", []byte("b"))
	if err != nil {
		t.Fatal(err)
	}

	if err := repo.DeleteTOTPCredential(ctx, id, second); err != nil {
		t.Fatalf("removing one of two authenticators: %v", err)
	}
	err = repo.DeleteTOTPCredential(ctx, id, first)
	if !errors.Is(err, ErrLastTOTPCredential) {
		t.Fatalf("removing the last authenticator returned %v, want ErrLastTOTPCredential", err)
	}
	count, err := repo.CountTOTPCredentials(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("%d authenticators remain, want 1: the account is below the floor", count)
	}
}

// TestLiveDBDeleteTOTPCredentialRefusesAnotherUsersRow states that the id in the
// URL is not enough. The RLS policy already scopes the row to app.user_id, and
// the statement's own user_id predicate is the belt to that pair of braces —
// this checks the pair, not either one alone.
func TestLiveDBDeleteTOTPCredentialRefusesAnotherUsersRow(t *testing.T) {
	db := liveDB(t)
	_, ownerID, orgID := liveSession(t, db)

	// The application is intentionally single-organization, so the second user
	// belongs to the same organization. User-level RLS is the boundary this test
	// exercises; creating a second organization would correctly violate the
	// organization_singleton index before reaching that boundary.
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := database.WithTx(context.Background(), tx)
	if err := database.SetLocal(seed, "app.auth_flow", "true"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	var otherID string
	err = tx.QueryRowContext(seed,
		`INSERT INTO "user" (organization_id, email, name, role) VALUES ($1, $2, 'Other Live Tester', 'administrator') RETURNING id`,
		orgID, "livedb-"+uuid.NewString()+"@example.com").Scan(&otherID)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	repo := NewRepository(db)

	owner := userContext(t, db, ownerID)
	kept, err := repo.SaveTOTPCredential(owner, uuid.MustParse(ownerID), "Owner", []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveTOTPCredential(owner, uuid.MustParse(ownerID), "Spare", []byte("b")); err != nil {
		t.Fatal(err)
	}

	other := userContext(t, db, otherID)
	if _, err := repo.SaveTOTPCredential(other, uuid.MustParse(otherID), "Theirs", []byte("c")); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteTOTPCredential(other, uuid.MustParse(otherID), kept); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleting another user's authenticator returned %v, want sql.ErrNoRows", err)
	}
	if count, err := repo.CountTOTPCredentials(owner, uuid.MustParse(ownerID)); err != nil || count != 2 {
		t.Errorf("the owner has %d authenticators (err %v), want 2", count, err)
	}
}

// TestLiveDBPasskeysMap is a regression test for a bug that made passkeys inert.
//
// Passkeys scanned into []Passkey, a named struct, which go-jet maps nothing
// onto — so it returned an empty slice and a nil error for an account that had
// credentials. Nothing failed at the point of the mistake: the list rendered
// "No passkeys registered", sign-in answered "no passkey is registered on this
// account", and registration excluded nothing, so the same authenticator could
// be enrolled twice. Asserting on the length and the fields is the point; a test
// that only checked the error would have passed against it.
func TestLiveDBPasskeysMap(t *testing.T) {
	db := liveDB(t)
	_, userID, _ := liveSession(t, db)
	repo := NewRepository(db)
	ctx := userContext(t, db, userID)
	id := uuid.MustParse(userID)

	credentialID := []byte("livedb-credential-" + uuid.NewString())
	stored := Passkey{
		CredentialID: credentialID, PublicKey: []byte("public-key"),
		Attestation: "none", AAGUID: []byte("aaguid"), Transports: "usb,nfc",
		SignCount: 7, BackupEli: true, BackupState: true, Label: "Live key",
	}
	if err := repo.SavePasskey(ctx, id, stored); err != nil {
		t.Fatalf("saving a passkey: %v", err)
	}

	rows, err := repo.Passkeys(ctx, id)
	if err != nil {
		t.Fatalf("listing passkeys: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d passkeys, want 1", len(rows))
	}
	got := rows[0]
	if string(got.CredentialID) != string(credentialID) {
		t.Errorf("CredentialID is %q, want %q", got.CredentialID, credentialID)
	}
	if string(got.PublicKey) != "public-key" {
		t.Errorf("PublicKey is %q; the column did not map", got.PublicKey)
	}
	if got.Label != "Live key" || got.Transports != "usb,nfc" || got.SignCount != 7 {
		t.Errorf("credential did not map: %+v", got)
	}
	if !got.BackupEli || !got.BackupState || got.CloneWarning {
		t.Errorf("flags did not map: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; the timestamp did not map")
	}
}

// TestLiveDBPendingTOTPRoundTrips covers the other new destination. An enrolment
// in progress that came back empty would present as "that registration has
// expired" the moment the user typed a correct code.
func TestLiveDBPendingTOTPRoundTrips(t *testing.T) {
	db := liveDB(t)
	sessionID, userID, _ := liveSession(t, db)
	repo := NewRepository(db)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx := database.WithTx(context.Background(), tx)
	// session_rls admits a session by its own id; app.user_id is set too because
	// that is what a real request carries.
	if err := database.SetLocal(ctx, "app.session_id", sessionID.String()); err != nil {
		t.Fatal(err)
	}
	if err := database.SetLocal(ctx, "app.user_id", userID); err != nil {
		t.Fatal(err)
	}

	sealed, label, err := repo.PendingTOTP(ctx, sessionID)
	if err != nil {
		t.Fatalf("reading an absent pending secret: %v", err)
	}
	if len(sealed) != 0 || label != "" {
		t.Errorf("a session with no enrolment reported secret=%q label=%q", sealed, label)
	}

	if err := repo.SetPendingTOTP(ctx, sessionID, []byte("parked"), "Personal phone"); err != nil {
		t.Fatalf("parking a pending secret: %v", err)
	}
	sealed, label, err = repo.PendingTOTP(ctx, sessionID)
	if err != nil {
		t.Fatalf("reading a parked pending secret: %v", err)
	}
	if string(sealed) != "parked" {
		t.Errorf("pending secret is %q, want %q", sealed, "parked")
	}
	if label != "Personal phone" {
		t.Errorf("pending label is %q, want %q", label, "Personal phone")
	}

	if err := repo.SetPendingTOTP(ctx, sessionID, nil, ""); err != nil {
		t.Fatalf("clearing a pending secret: %v", err)
	}
	if sealed, _, err = repo.PendingTOTP(ctx, sessionID); err != nil || len(sealed) != 0 {
		t.Errorf("clearing left %q behind (err %v)", sealed, err)
	}
}
