package pki

import (
	"strings"
	"testing"
	"time"
)

func expiringSample() []ExpiringCertificate {
	base := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	return []ExpiringCertificate{
		{ID: "1", Subject: "vpn-gateway-03.ams.internal", Serial: "4A:1F:09:BE", CAName: "Northwind CA G2", ExpiresAt: base},
		{ID: "2", Subject: "kiosk-118", Serial: "0E:88:D1:33", CAName: "Northwind CA G2", ExpiresAt: base.AddDate(0, 0, 7)},
	}
}

// Name is the organization, not a certificate authority — the two are different
// strings and the message used to conflate them, so the fixtures keep them
// distinct on purpose.
func alertSettings() ExpiryAlertSettings {
	return ExpiryAlertSettings{Enabled: true, Days: 30, Name: "Northwind Logistics"}
}

// The alert used to be a raw HTML fragment — a <p>, a <table cellpadding="6"> at
// the mail client's default styling, and no plain-text part at all. The missing
// text part is the real defect: an HTML-only message carrying a table and a link
// is the shape of a newsletter, and this is the one notification whose arrival is
// the whole point of the feature. An expiry alert filed as spam is the outage it
// exists to prevent.
func TestTheExpiryAlertCarriesBothParts(t *testing.T) {
	body, text := alertNotice(alertSettings(), expiringSample(), "https://app.example.com").Render()
	if body == "" || text == "" {
		t.Fatalf("the alert is missing a part: html=%d bytes, text=%d bytes", len(body), len(text))
	}
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("the alert is still a bare fragment rather than a whole document")
	}
	if !strings.Contains(body, `content="only light"`) {
		t.Error("the alert does not declare a colour scheme, so clients will recolour it")
	}
	if strings.Contains(text, "<td") || strings.Contains(text, "<div") {
		t.Errorf("the text part carries markup: %q", text)
	}
}

// Every certificate has to appear in both parts with its serial and its date. A
// recipient reading the text alternative is the one most likely to be on a phone
// deciding whether this needs acting on tonight.
func TestEveryCertificateAppearsInBothParts(t *testing.T) {
	body, text := alertNotice(alertSettings(), expiringSample(), "https://app.example.com").Render()
	for _, part := range []struct{ name, content string }{{"html", body}, {"text", text}} {
		for _, want := range []string{"vpn-gateway-03.ams.internal", "4A:1F:09:BE", "4 Sep 2026", "kiosk-118", "11 Sep 2026"} {
			if !strings.Contains(part.content, want) {
				t.Errorf("the %s part is missing %q", part.name, want)
			}
		}
	}
}

// A certificate with no subject is named by its serial rather than rendered as an
// empty cell, which in a table of otherwise-identifiable rows reads as data loss.
func TestACertificateWithNoSubjectIsNamedByItsSerial(t *testing.T) {
	certs := []ExpiringCertificate{{ID: "1", Serial: "71:C2:04:AA", CAName: "CA", ExpiresAt: time.Now()}}
	_, text := alertNotice(alertSettings(), certs, "https://app.example.com").Render()
	if !strings.Contains(text, "serial 71:C2:04:AA") {
		t.Errorf("an unnamed certificate has no label: %q", text)
	}
}

// A fleet-wide event can put thousands into the window at once. The message names
// the first fifty and says how many it left out; the rest are still marked as
// notified, and the dashboard is where a list that long belongs.
func TestTheAlertCapsTheListAndSaysSo(t *testing.T) {
	certs := make([]ExpiringCertificate, 0, maxAlertCertificates+12)
	for i := 0; i < maxAlertCertificates+12; i++ {
		certs = append(certs, ExpiringCertificate{ID: "x", Subject: "device", Serial: "AA", CAName: "CA", ExpiresAt: time.Now()})
	}
	notice := alertNotice(alertSettings(), certs, "https://app.example.com")
	if len(notice.Table.Rows) != maxAlertCertificates {
		t.Errorf("the table lists %d rows, want the cap of %d", len(notice.Table.Rows), maxAlertCertificates)
	}
	_, text := notice.Render()
	if !strings.Contains(text, "remaining 12") {
		t.Errorf("the message does not say how many it omitted: %q", text)
	}
}

// A certificate subject is whatever a customer put in a CSR, so it reaches this
// template as attacker-controlled text and must arrive as text.
func TestASubjectContainingMarkupIsEscaped(t *testing.T) {
	certs := []ExpiringCertificate{{
		ID: "1", Subject: `CN=<img src=x onerror=alert(1)>`, Serial: "AA", CAName: "CA", ExpiresAt: time.Now(),
	}}
	body, _ := alertNotice(alertSettings(), certs, "https://app.example.com").Render()
	if strings.Contains(body, "<img src=x") {
		t.Error("a certificate subject reached the message as markup")
	}
}

// The preheader is what an inbox shows beside the subject. The subject says how
// many are expiring; this says whose and by when, which together are enough to
// decide whether to open it now or after lunch.
func TestThePreheaderNamesTheSoonestExpiry(t *testing.T) {
	// Deliberately out of order: the soonest is not the first in the slice.
	certs := expiringSample()
	certs[0], certs[1] = certs[1], certs[0]
	notice := alertNotice(alertSettings(), certs, "https://app.example.com")
	if !strings.Contains(notice.Preheader, "4 Sep 2026") {
		t.Errorf("the preheader does not name the soonest expiry: %q", notice.Preheader)
	}
	if !strings.Contains(notice.Preheader, "Northwind Logistics") {
		t.Errorf("the preheader does not say which account this concerns: %q", notice.Preheader)
	}
}

// settings.Name is the organization. The opening sentence used to read
// "certificates issued by <organization>", which names the wrong kind of thing:
// an organization does not issue certificates, the CAs inside it do. An
// administrator who belongs to more than one account still needs to know which
// this concerns, so the name stays — as the account it is about.
func TestTheOpeningNamesTheAccountNotAnIssuer(t *testing.T) {
	_, text := alertNotice(alertSettings(), expiringSample(), "https://app.example.com").Render()
	if strings.Contains(text, "issued by Northwind Logistics") {
		t.Error("the organization is being described as the issuer")
	}
	if !strings.Contains(text, "in Northwind Logistics") {
		t.Errorf("the message does not say which account it concerns: %q", text)
	}
}

// Most organizations run one issuing CA, so the column was the same string in
// all fifty rows — a quarter of the table's width spent saying one thing, on a
// message that has to fit a phone. When it is constant it belongs in the
// sentence above, where it is read once.
func TestTheIssuerColumnCollapsesWhenItIsConstant(t *testing.T) {
	notice := alertNotice(alertSettings(), expiringSample(), "https://app.example.com")
	if len(notice.Table.Headers) != 3 {
		t.Errorf("headers are %v; the constant issuer column should have collapsed", notice.Table.Headers)
	}
	_, text := notice.Render()
	if !strings.Contains(text, "issued by Northwind CA G2") {
		t.Errorf("the shared issuer was dropped rather than moved into the sentence: %q", text)
	}
}

// When the issuers genuinely differ the column is the only thing saying which
// certificate came from where, so it stays.
func TestTheIssuerColumnStaysWhenIssuersDiffer(t *testing.T) {
	certs := expiringSample()
	certs[1].CAName = "Northwind CA G3"
	notice := alertNotice(alertSettings(), certs, "https://app.example.com")
	if len(notice.Table.Headers) != 4 {
		t.Fatalf("headers are %v; the issuer column should have been kept", notice.Table.Headers)
	}
	_, text := notice.Render()
	for _, want := range []string{"Northwind CA G2", "Northwind CA G3"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text part is missing issuer %q", want)
		}
	}
}
