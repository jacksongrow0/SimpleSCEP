//go:build livedb

// Live-database checks for the certificate expiry alert sweep. The behaviour
// under test — that a certificate is alerted on exactly once — lives in the
// interaction between a query, an UPDATE and a transaction, which is precisely
// what a fake repository would define away.
//
// Run with a database available:
//
//	go test -tags livedb ./internal/pki/ -run LiveDB -v
package pki

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/mail"
)

func expiryLiveDB(t *testing.T) *sql.DB {
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

// recorder captures what would have been sent.
type recorder struct {
	mu       sync.Mutex
	messages []mail.Message
	err      error
}

func (r *recorder) Send(_ context.Context, msg mail.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.messages = append(r.messages, msg)
	return nil
}

func (r *recorder) sent() []mail.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]mail.Message(nil), r.messages...)
}

// expiryFixture seeds an organization with an administrator, a CA, and one
// certificate expiring in `expiresIn`.
//
// Unlike the support tests this commits, because AlertOnce opens its own
// transactions and cannot see uncommitted rows. Everything is removed again in
// a cleanup by removeFixture, which deletes the children explicitly.
func expiryFixture(t *testing.T, db *sql.DB, name string, expiresIn time.Duration) (orgID, email string) {
	t.Helper()
	// kms_key_version and (organization_id, serial) are unique, so the label is
	// made unique per run. A previous run that failed before its cleanup would
	// otherwise poison every run after it with a duplicate-key error that says
	// nothing about the test.
	label := fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	txctx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txctx, "app.auth_flow", "true"); err != nil {
		t.Fatal(err)
	}
	var org struct{ ID string }
	if err := table.Organization.INSERT(table.Organization.Name).VALUES("expiry-livedb-"+label).
		RETURNING(postgres.CAST(table.Organization.ID).AS_TEXT().AS("ID")).
		QueryContext(txctx, tx, &org); err != nil {
		t.Fatal(err)
	}
	email = "expiry-" + label + "@example.test"
	if _, err := table.User.INSERT(table.User.OrganizationID, table.User.Email, table.User.Name, table.User.Role).
		VALUES(org.ID, email, "Probe "+label, "administrator").ExecContext(txctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := database.SetLocal(txctx, "app.auth_flow", "false"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetLocal(txctx, "app.organization_id", org.ID); err != nil {
		t.Fatal(err)
	}
	var ca struct{ ID string }
	if err := table.CertificateAuthority.INSERT(
		table.CertificateAuthority.OrganizationID, table.CertificateAuthority.Name,
		table.CertificateAuthority.Type, table.CertificateAuthority.Status,
		table.CertificateAuthority.Subject, table.CertificateAuthority.Algorithm,
		table.CertificateAuthority.KmsKeyVersion, table.CertificateAuthority.CertificatePem,
		table.CertificateAuthority.ChainPem,
		table.CertificateAuthority.NotBefore, table.CertificateAuthority.NotAfter).
		// kms_key_version is UNIQUE, so it is keyed off the label to keep
		// fixtures from colliding with each other.
		VALUES(org.ID, "Probe Issuing CA", CATypeIssuing, CAStatusActive, "CN=Probe",
			"EC_P256", "probe-key-"+label, "", "",
			time.Now().Add(-time.Hour), time.Now().Add(24*365*time.Hour)).
		RETURNING(postgres.CAST(table.CertificateAuthority.ID).AS_TEXT().AS("ID")).
		QueryContext(txctx, tx, &ca); err != nil {
		t.Fatal(err)
	}
	if _, err := table.Certificate.INSERT(
		table.Certificate.OrganizationID, table.Certificate.CertificateAuthorityID,
		table.Certificate.Serial, table.Certificate.Subject, table.Certificate.Status,
		table.Certificate.CsrDigest, table.Certificate.CertificatePem, table.Certificate.ChainPem,
		table.Certificate.ExpiresAt, table.Certificate.Profile).
		VALUES(org.ID, ca.ID, "0A"+label, "CN=laptop-"+label, CertStatusIssued, "digest", "", "",
			time.Now().Add(expiresIn), CertProfileClient).
		ExecContext(txctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeFixture(t, db, org.ID) })
	return org.ID, email
}

// removeFixture deletes a seeded organization and everything hanging off it.
//
// The children are deleted explicitly, in order, rather than left to the
// organization's ON DELETE CASCADE. certificate references certificate_authority
// with no ON DELETE clause, which is RESTRICT, so cascading from the
// organization trips that constraint and the whole delete fails. It failed
// silently the first time this was written, and the leftover rows then collided
// with the next run's unique kms_key_version.
//
// The two row-level security contexts are also different: certificate and
// certificate_authority are reachable only with app.organization_id set, while
// organization and "user" are writable only under the auth-flow escape.
func removeFixture(t *testing.T, db *sql.DB, orgID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Logf("fixture cleanup could not begin: %v", err)
		return
	}
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)

	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		t.Logf("fixture cleanup could not scope to the organization: %v", err)
		return
	}
	for _, stmt := range []string{
		"DELETE FROM certificate WHERE organization_id = $1",
		"DELETE FROM certificate_authority WHERE organization_id = $1",
	} {
		if _, err := tx.ExecContext(ctx, stmt, orgID); err != nil {
			t.Logf("fixture cleanup failed on %q: %v", stmt, err)
			return
		}
	}
	if err := database.SetLocal(txctx, "app.auth_flow", "true"); err != nil {
		t.Logf("fixture cleanup could not enter the auth flow: %v", err)
		return
	}
	for _, stmt := range []string{
		`DELETE FROM "user" WHERE organization_id = $1`,
		"DELETE FROM organization WHERE id = $1",
	} {
		if _, err := tx.ExecContext(ctx, stmt, orgID); err != nil {
			t.Logf("fixture cleanup failed on %q: %v", stmt, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		t.Logf("fixture cleanup could not commit: %v", err)
	}
}

// alertsFor returns only the messages addressed to this fixture, so a shared
// development database with other organizations in it does not make the
// assertions flaky.
func alertsFor(sent []mail.Message, email string) []mail.Message {
	var out []mail.Message
	for _, msg := range sent {
		if msg.To == email {
			out = append(out, msg)
		}
	}
	return out
}

// TestLiveDBExpiryAlertSendsOnce is the property the whole feature rests on. An
// alert repeated daily for the length of the window is one the recipient
// filters, and a filtered alert is the same as no alert.
func TestLiveDBExpiryAlertSendsOnce(t *testing.T) {
	db := expiryLiveDB(t)
	orgID, email := expiryFixture(t, db, "once", 10*24*time.Hour)

	rec := &recorder{}
	if err := AlertOnce(context.Background(), db, mail.NewService(rec), "https://example.test"); err != nil {
		t.Fatalf("AlertOnce: %v", err)
	}
	first := alertsFor(rec.sent(), email)
	if len(first) != 1 {
		t.Fatalf("first sweep sent %d alerts, want 1", len(first))
	}
	if !strings.Contains(first[0].Body, "CN=laptop-once-") {
		t.Errorf("alert does not name the certificate: %q", first[0].Body)
	}
	if !strings.Contains(first[0].Subject, "expires soon") {
		t.Errorf("unexpected subject %q", first[0].Subject)
	}

	// The whole point: running again must not tell them a second time.
	if err := AlertOnce(context.Background(), db, mail.NewService(rec), "https://example.test"); err != nil {
		t.Fatalf("second AlertOnce: %v", err)
	}
	if second := alertsFor(rec.sent(), email); len(second) != 1 {
		t.Errorf("second sweep sent another alert; total %d, want 1", len(second))
	}

	// And the mark is on the row rather than in memory, so a restart does not
	// re-send either.
	if notifiedAt(t, db, orgID) == nil {
		t.Error("the certificate was not marked as notified")
	}
}

// notifiedAt reads the fixture certificate's expiry_notified_at. It fails the
// test if the row cannot be found, so a query that silently matched nothing is
// reported as the harness problem it is rather than as the absence of a mark.
func notifiedAt(t *testing.T, db *sql.DB, orgID string) *time.Time {
	t.Helper()
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
	var rows []struct {
		Serial   string
		Notified *time.Time
	}
	if err := postgres.SELECT(
		table.Certificate.Serial.AS("Serial"),
		table.Certificate.ExpiryNotifiedAt.AS("Notified")).
		FROM(table.Certificate).
		WHERE(table.Certificate.OrganizationID.EQ(database.UUID(orgID))).
		QueryContext(txctx, tx, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one fixture certificate for org %s, found %d", orgID, len(rows))
	}
	return rows[0].Notified
}

// TestLiveDBExpiryAlertRespectsWindow checks a certificate outside the window is
// left alone — the feature is a warning, not an inventory report.
func TestLiveDBExpiryAlertRespectsWindow(t *testing.T) {
	db := expiryLiveDB(t)
	// Default window is 30 days; this expires in 200.
	_, email := expiryFixture(t, db, "window", 200*24*time.Hour)

	rec := &recorder{}
	if err := AlertOnce(context.Background(), db, mail.NewService(rec), "https://example.test"); err != nil {
		t.Fatalf("AlertOnce: %v", err)
	}
	if sent := alertsFor(rec.sent(), email); len(sent) != 0 {
		t.Errorf("a certificate %d days out was alerted on: %d messages", 200, len(sent))
	}
}

// TestLiveDBExpiryAlertHonoursThePreference covers the switch actually doing
// something, which is what it did not do before.
func TestLiveDBExpiryAlertHonoursThePreference(t *testing.T) {
	db := expiryLiveDB(t)
	orgID, email := expiryFixture(t, db, "disabled", 5*24*time.Hour)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	txctx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		t.Fatal(err)
	}
	if err := NewRepository(db).SetExpiryAlerts(txctx, orgID, false, 30); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rec := &recorder{}
	if err := AlertOnce(ctx, db, mail.NewService(rec), "https://example.test"); err != nil {
		t.Fatalf("AlertOnce: %v", err)
	}
	if sent := alertsFor(rec.sent(), email); len(sent) != 0 {
		t.Errorf("alerts were sent to an organization that turned them off: %d", len(sent))
	}
}

// TestLiveDBExpiryAlertKeepsTryingAfterASendFailure pins the ordering that
// matters: the certificate is marked only once the mail is away. Marking first
// would drop the alert permanently on any provider hiccup, and a missed expiry
// is the outage this exists to prevent.
func TestLiveDBExpiryAlertKeepsTryingAfterASendFailure(t *testing.T) {
	db := expiryLiveDB(t)
	orgID, email := expiryFixture(t, db, "retry", 3*24*time.Hour)

	failing := &recorder{err: context.DeadlineExceeded}
	// AlertOnce logs and continues past a per-organization failure, so no error
	// is expected here — what matters is the state it left behind.
	if err := AlertOnce(context.Background(), db, mail.NewService(failing), "https://example.test"); err != nil {
		t.Fatalf("AlertOnce: %v", err)
	}

	if notified := notifiedAt(t, db, orgID); notified != nil {
		t.Fatal("the certificate was marked as notified even though the send failed; the alert is now lost")
	}

	// The next sweep, with a working sender, still delivers it.
	working := &recorder{}
	if err := AlertOnce(context.Background(), db, mail.NewService(working), "https://example.test"); err != nil {
		t.Fatalf("retry AlertOnce: %v", err)
	}
	if sent := alertsFor(working.sent(), email); len(sent) != 1 {
		t.Errorf("retry sent %d alerts, want 1", len(sent))
	}
}

// TestLiveDBExpiryAlertUsesConfiguredMailHeaders pins the deployment envelope.
func TestLiveDBExpiryAlertUsesConfiguredMailHeaders(t *testing.T) {
	t.Setenv("MAIL_FROM", "SimpleSCEP <pki@example.test>")
	t.Setenv("MAIL_REPLY_TO", "operators@example.test")
	db := expiryLiveDB(t)
	_, email := expiryFixture(t, db, "envelope", 10*24*time.Hour)

	rec := &recorder{}
	if err := AlertOnce(context.Background(), db, mail.NewService(rec), "https://example.test"); err != nil {
		t.Fatalf("AlertOnce: %v", err)
	}
	sent := alertsFor(rec.sent(), email)
	if len(sent) != 1 {
		t.Fatalf("sent %d alerts, want 1", len(sent))
	}
	if sent[0].From != "SimpleSCEP <pki@example.test>" {
		t.Errorf("alert From = %q", sent[0].From)
	}
	if sent[0].ReplyTo != "operators@example.test" {
		t.Errorf("alert Reply-To = %q", sent[0].ReplyTo)
	}
}

// TestLiveDBExpiryAlertHonoursTheSenderOverride covers a deployment-specific
// verified sender.
func TestLiveDBExpiryAlertHonoursTheEnvelopeOverride(t *testing.T) {
	t.Setenv("MAIL_FROM", "Alerts <alerts@staging.example>")
	db := expiryLiveDB(t)
	_, email := expiryFixture(t, db, "override", 10*24*time.Hour)

	rec := &recorder{}
	if err := AlertOnce(context.Background(), db, mail.NewService(rec), "https://example.test"); err != nil {
		t.Fatalf("AlertOnce: %v", err)
	}
	sent := alertsFor(rec.sent(), email)
	if len(sent) != 1 {
		t.Fatalf("sent %d alerts, want 1", len(sent))
	}
	if sent[0].From != "Alerts <alerts@staging.example>" {
		t.Errorf("alert From = %q, want the override", sent[0].From)
	}
}
