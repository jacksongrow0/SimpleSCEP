package pki

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/mail"
	"github.com/jacksongrow0/SimpleSCEP/internal/worker"
)

// expirySweepInterval is how often the alert sweep runs.
//
// Daily, not hourly like the CRL renewal beside it. The alert window is measured
// in weeks, so an hourly sweep would send the same set of messages a few minutes
// earlier at twenty-four times the cost, and the first sweep after a restart
// already catches anything that fell due while the process was down.
const expirySweepInterval = 24 * time.Hour

// maxAlertCertificates bounds how many certificates one message names.
//
// A fleet-wide event — a CA rotation, a mass re-enrollment — can put thousands
// into the window at once, and an email listing all of them is unreadable and
// may be rejected outright for size. The rest are still marked as notified: the
// message says how many were omitted, and the dashboard is where a list that
// long belongs.
const maxAlertCertificates = 50

// RunExpiryAlerts emails each organization's administrators about certificates
// approaching expiry.
//
// An expired device certificate is an outage that arrives on a schedule known
// weeks in advance, which makes it the one failure in this service that is
// entirely preventable by telling somebody.
func RunExpiryAlerts(ctx context.Context, db *sql.DB, sender mail.Service, appURL string) {
	worker.Run(ctx, "expiry alert sweep", expirySweepInterval, func(ctx context.Context) error {
		return AlertOnce(ctx, db, sender, appURL)
	})
}

// AlertOnce runs one sweep across every organization. Exported so it can be run
// directly in a test rather than by waiting a day for a ticker.
func AlertOnce(ctx context.Context, db *sql.DB, sender mail.Service, appURL string) error {
	orgs, err := revocationOrganizations(ctx, db)
	if err != nil {
		return err
	}
	repo := NewRepository(db)
	for _, orgID := range orgs {
		// One transaction per organization, as the CRL and ACME sweeps do: one
		// customer's failure must not roll back the work done for everybody
		// else, and each needs its own app.organization_id anyway.
		if err := alertOrganization(ctx, db, repo, sender, appURL, orgID); err != nil {
			log.Printf("expiry alert org=%s failed: %v", orgID, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

func alertOrganization(ctx context.Context, db *sql.DB, repo Repository, sender mail.Service, appURL, orgID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txctx, "app.organization_id", orgID); err != nil {
		return err
	}

	settings, err := repo.ExpiryAlertSettings(txctx, orgID)
	if err != nil {
		return err
	}
	if !settings.Enabled {
		return nil
	}
	expiring, err := repo.ExpiringCertificates(txctx, orgID, int(settings.Days))
	if err != nil {
		return err
	}
	if len(expiring) == 0 {
		return nil
	}
	recipients, err := repo.AlertRecipients(txctx, orgID)
	if err != nil {
		return err
	}
	if len(recipients) == 0 {
		// An organization with no administrator has nobody to tell. Left
		// unmarked so the alert is still waiting if one is invited later.
		log.Printf("expiry alert org=%s: %d certificates expiring and no administrator to notify", orgID, len(expiring))
		return nil
	}

	notice := alertNotice(settings, expiring, appURL)
	body, text := notice.Render()
	subject := alertSubject(expiring)
	// Marked only after every recipient has been accepted. Sending first and
	// marking second can duplicate an alert if the mark fails; the other order
	// drops it silently, and a missed expiry is the thing this exists to stop.
	// Notifications carry the operator's optional reply address.
	for _, to := range recipients {
		msg := mail.Notifications.Apply(mail.Message{To: to, Subject: subject, Body: body, Text: text})
		if err := sender.Send(txctx, msg); err != nil {
			return fmt.Errorf("sending expiry alert to %s: %w", to, err)
		}
	}

	ids := make([]string, 0, len(expiring))
	for _, cert := range expiring {
		ids = append(ids, cert.ID)
	}
	if err := repo.MarkExpiryNotified(txctx, orgID, ids); err != nil {
		return err
	}
	return tx.Commit()
}

func alertSubject(expiring []ExpiringCertificate) string {
	if len(expiring) == 1 {
		return "A certificate expires soon: " + subjectLabel(expiring[0])
	}
	return fmt.Sprintf("%d certificates expire soon", len(expiring))
}

// alertNotice is the message a set of expiring certificates becomes.
//
// It used to be a raw HTML fragment: a <p>, a <table cellpadding="6"> with the
// mail client's default styling, and no plain-text part at all. That last one is
// the real defect rather than the appearance — an HTML-only message with a table
// and a link is the shape of a newsletter, and this is the one notification whose
// arrival is the whole point of the feature. A missed expiry alert is the outage
// it exists to prevent.
//
// Rendered through mail.Notice so it carries the same chrome as everything else
// the customer receives, and so the table gets a column-aligned text equivalent
// rather than a stripped one.
func alertNotice(settings ExpiryAlertSettings, expiring []ExpiringCertificate, appURL string) mail.Notice {
	shown := expiring
	if len(shown) > maxAlertCertificates {
		shown = shown[:maxAlertCertificates]
	}

	// The issuing CA is a column only when it varies. Most organizations run one
	// issuing CA, so it was the same string in all fifty rows — a quarter of the
	// table's width spent saying one thing, on a message that has to fit a phone.
	// When it is constant it moves into the sentence above instead, which is also
	// where somebody reads it once rather than fifty times.
	sharedCA := commonCAName(shown)

	headers := []string{"Certificate", "Serial", "Issued by", "Expires"}
	if sharedCA != "" {
		headers = []string{"Certificate", "Serial", "Expires"}
	}
	rows := make([][]string, 0, len(shown))
	for _, cert := range shown {
		expires := cert.ExpiresAt.UTC().Format("2 Jan 2006")
		if sharedCA != "" {
			rows = append(rows, []string{subjectLabel(cert), cert.Serial, expires})
			continue
		}
		rows = append(rows, []string{subjectLabel(cert), cert.Serial, cert.CAName, expires})
	}

	// settings.Name is the organization, not a certificate authority. The sentence
	// here used to read "certificates issued by <organization>", which names the
	// wrong kind of thing: an organization does not issue certificates, the CAs
	// inside it do. An administrator in more than one organization needs to know
	// which account this concerns, so the name stays — as the account it is about.
	opening := fmt.Sprintf("%d certificate%s in %s expire%s within the next %d days.",
		len(expiring), plural(len(expiring)), settings.Name, verb(len(expiring)), settings.Days)
	if sharedCA != "" {
		opening = fmt.Sprintf("%d certificate%s issued by %s in %s expire%s within the next %d days.",
			len(expiring), plural(len(expiring)), sharedCA, settings.Name, verb(len(expiring)), settings.Days)
	}
	body := []string{opening}
	if len(expiring) > len(shown) {
		body = append(body, fmt.Sprintf("Only the first %d are listed below. The remaining %d are on the dashboard.",
			len(shown), len(expiring)-len(shown)))
	}

	return mail.Notice{
		Heading:   alertHeading(expiring),
		Preheader: alertPreheader(settings, expiring),
		Body:      body,
		Table: mail.Table{
			Headers: headers,
			Rows:    rows,
			// The serial is the column somebody reads aloud to a colleague or
			// pastes into a search box.
			Mono: map[int]bool{1: true},
		},
		Link: mail.Link{
			Label: "Review certificates",
			URL:   strings.TrimRight(appURL, "/") + "/certificates",
		},
		Notes: []string{
			"Renewing or re-enrolling a device replaces its certificate; this notice is sent once per certificate.",
		},
	}
}

// commonCAName returns the issuing CA when every certificate shares one, and ""
// when they do not or when there is nothing to compare.
func commonCAName(certs []ExpiringCertificate) string {
	if len(certs) == 0 {
		return ""
	}
	name := certs[0].CAName
	if strings.TrimSpace(name) == "" {
		return ""
	}
	for _, cert := range certs[1:] {
		if cert.CAName != name {
			return ""
		}
	}
	return name
}

// alertHeading restates the subject inside the message, because a mail client
// showing a threaded or forwarded copy does not always show the subject with it.
func alertHeading(expiring []ExpiringCertificate) string {
	if len(expiring) == 1 {
		return "A certificate expires soon"
	}
	return fmt.Sprintf("%d certificates expire soon", len(expiring))
}

// alertPreheader is the line an inbox shows beside the subject. The subject says
// how many; this says by when and whose, which together are enough to decide
// whether to open it now or after lunch.
func alertPreheader(settings ExpiryAlertSettings, expiring []ExpiringCertificate) string {
	soonest := expiring[0].ExpiresAt
	for _, cert := range expiring[1:] {
		if cert.ExpiresAt.Before(soonest) {
			soonest = cert.ExpiresAt
		}
	}
	return "In " + settings.Name + ". The first expires " + soonest.UTC().Format("2 Jan 2006") + "."
}

// subjectLabel is what to call a certificate in a message. A certificate with no
// subject is named by its serial rather than rendered as an empty cell.
func subjectLabel(cert ExpiringCertificate) string {
	if strings.TrimSpace(cert.Subject) != "" {
		return cert.Subject
	}
	return "serial " + cert.Serial
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func verb(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}
