package home

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

func testSession() auth.Session {
	return auth.Session{ID: "s-1", UserID: "u-1", OrgID: "org-1", Name: "Jane Doe",
		Email: "jane@example.com", Role: "administrator",
		OrganizationName: "Acme"}
}

func render(t *testing.T, page interface {
	Render(context.Context, io.Writer) error
},
) string {
	t.Helper()
	var out strings.Builder
	if err := page.Render(context.Background(), &out); err != nil {
		t.Fatalf("render: %v", err)
	}
	return out.String()
}

func TestOverviewShowsRealCounts(t *testing.T) {
	html := render(t, Index(testSession(), OverviewData{
		IssuingCAs:       1,
		Identities:       37,
		EnabledEndpoints: 1,
		ExpiringSoon:     2,
		HasIssuingCA:     true, HasProtocol: true,
		Protocols: []string{"SCEP"},
	}))
	for _, want := range []string{">37<", ">2<", "Enabled protocols", "SCEP"} {
		if !strings.Contains(html, want) {
			t.Errorf("overview is missing %q", want)
		}
	}
	if strings.Contains(html, "2 of 4 steps") == false && strings.Contains(html, "steps complete") == false {
		t.Error("setup card does not report step progress")
	}
}

func TestUsersShowsInviteForm(t *testing.T) {
	session := testSession()
	html := render(t, Users(session, []auth.User{{
		ID: session.UserID, Name: session.Name, Email: session.Email, Role: session.Role,
	}}, nil))
	for _, want := range []string{`action="/settings/invitations"`, "Send invite"} {
		if !strings.Contains(html, want) {
			t.Errorf("users page is missing %q", want)
		}
	}
}

// TestOrganizationOnlyClaimsSupportedCompliancePosture is what this test was
// always named for, and it used to assert the opposite.
//
// It required the strings "HSM attestation" and "Audit log retention" to be
// present — the two claims on that card that were false. "FIPS 140-2 Level 3" was
// rendered deployment-wide mode text, so a deployment on software keys or
// on in-memory development keys told its customers, under the heading "Audit &
// compliance", that their CA lived in a FIPS 140-2 Level 3 module. The retention
// figure named a purge job that does not exist in this repository at all.
//
// So the assertions are inverted: the fixture is a software-key deployment, and
// the card must reflect that and claim nothing it cannot support.
func TestOrganizationOnlyClaimsSupportedCompliancePosture(t *testing.T) {
	session := testSession()
	posture := testPosture()
	html := render(t, Organization(session, auth.Organization{Name: session.OrganizationName}, posture))

	for _, want := range []string{"CA key provider", posture.KeyProtection, "CRL publication", posture.CRLRefresh, "OCSP endpoint"} {
		if !strings.Contains(html, want) {
			t.Errorf("organization compliance section is missing %q", want)
		}
	}
	// The claims that were asserted from nothing. FIPS in particular must never
	// appear on a page rendered from a fixture that is not HSM-backed.
	for _, reject := range []string{"SOC 2 Type II", "FIPS", "365 days", "US-East (Virginia)"} {
		if strings.Contains(html, reject) {
			t.Errorf("organization compliance section claims %q, which nothing here measures", reject)
		}
	}
}

// TestOrganizationOmitsTheRegionItDoesNotKnow: with no key ring configured
// pki.KeyLocation returns "", and the honest answer is to say nothing rather than
// to fall back to a plausible-looking region.
func TestOrganizationOmitsTheRegionItDoesNotKnow(t *testing.T) {
	posture := testPosture()
	posture.Region = ""
	html := render(t, Organization(testSession(), auth.Organization{Name: "Acme"}, posture))
	if strings.Contains(html, "Key region") {
		t.Error("the region row is rendered when no key ring location is known")
	}
}

// TestOrganizationShowsItsOwnCreationDate pins the other hardcoded value: the
// card's description read "Created July 8, 2026" for every organization.
func TestOrganizationShowsItsOwnCreationDate(t *testing.T) {
	created := time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC)
	html := render(t, Organization(testSession(),
		auth.Organization{Name: "Acme", CreatedAt: created}, testPosture()))
	if !strings.Contains(html, "Created March 19, 2026") {
		t.Error("the organization's own creation date is not shown")
	}
	if strings.Contains(html, "July 8, 2026") {
		t.Error("the hardcoded creation date is still rendered")
	}
	// An organization with no recorded date must not invent one.
	bare := render(t, Organization(testSession(), auth.Organization{Name: "Acme"}, testPosture()))
	if strings.Contains(bare, "Created ") {
		t.Error("a creation date is rendered for an organization that has none")
	}
}

func TestAuditRendersEventsAndFilters(t *testing.T) {
	at := time.Date(2026, 8, 5, 18, 57, 9, 0, time.UTC)
	html := render(t, Audit(testSession(), AuditData{
		Total: 2,
		Events: []audit.Event{
			{Action: audit.ActionRootCACreated, Target: "R2", Detail: "serial abc",
				ActorName: "Jackson Grow", ActorEmail: "jgrow@example.com", At: at},
			{Action: audit.ActionCertificateIssued, Target: "CN=laptop-01", At: at},
		},
		Actors: []auth.User{{ID: "u-1", Name: "Jane Doe", Email: "jane@example.com"}},
	}))
	for _, want := range []string{"Root CA created", "Certificate issued", "Jackson Grow",
		"CN=laptop-01", "2 events recorded", "/audit.csv"} {
		if !strings.Contains(html, want) {
			t.Errorf("audit page is missing %q", want)
		}
	}
	// An event with no user behind it is SimpleSCEP's own, not a blank.
	if !strings.Contains(html, "SimpleSCEP") {
		t.Error("audit page does not attribute automated events")
	}
	// Timestamps must reach the browser as instants it can localize.
	if !strings.Contains(html, `data-local="datetime"`) {
		t.Error("audit timestamps are not rendered for local-time conversion")
	}
}

func TestAuditEmptyStateDistinguishesFilters(t *testing.T) {
	unfiltered := render(t, Audit(testSession(), AuditData{}))
	if !strings.Contains(unfiltered, "Nothing recorded yet") {
		t.Error("an empty log should say nothing is recorded")
	}
	filtered := render(t, Audit(testSession(), AuditData{Total: 5, Action: audit.ActionUserRemoved}))
	if !strings.Contains(filtered, "No matching events") {
		t.Error("an empty result under filters should say so rather than claim the log is empty")
	}
	if !strings.Contains(filtered, "Clear filters") {
		t.Error("a filtered empty result should offer to clear the filters")
	}
}

func TestRevocationTimestampsAreLocalized(t *testing.T) {
	at := time.Date(2026, 8, 5, 18, 57, 9, 0, time.UTC)
	html := render(t, Revocation(testSession(), RevocationData{
		RevokedCount: "1", AffectedCAs: "1", LastPublished: &at, NextUpdate: &at,
		Points: []DistributionPoint{{CAName: "I2", Status: "Healthy", PublishedAt: &at, NextUpdate: &at}},
		Rows:   []RevocationRow{{CN: "laptop-01", Serial: "abc", CAName: "I2", Reason: "superseded", RevokedAt: &at}},
	}))
	if strings.Count(html, `data-local="datetime"`) < 5 {
		t.Error("revocation timestamps are not all rendered for local-time conversion")
	}
	if strings.Contains(html, "UTC</strong>") {
		t.Error("a distribution point timestamp is still committed to UTC in its markup")
	}
}

func TestRevocationWithoutPublicationShowsPlaceholders(t *testing.T) {
	html := render(t, Revocation(testSession(), RevocationData{
		RevokedCount: "0", AffectedCAs: "0",
		Points: []DistributionPoint{{CAName: "I2", Status: "Pending"}},
	}))
	for _, want := range []string{"Never", "Not scheduled"} {
		if !strings.Contains(html, want) {
			t.Errorf("an unpublished CRL should read %q", want)
		}
	}
}

// testPosture is a deployment on software-protection keys, deliberately not HSM.
//
// The card used to claim FIPS 140-2 Level 3 regardless of actual keys, so a fixture
// that said "HSM" would let that bug back in unnoticed. Production does run every
// CA with HSM protection and the card does say so there — but it says it because
// pki.KeyProtectionLabel read the configuration, not because the words were typed
// into the page, and this fixture is what keeps that distinction honest.
func testPosture() Posture {
	return Posture{
		KeyProtection: "Cloud KMS software · Non-exportable",
		Region:        "us-east1",
		CRLRefresh:    "Every 24h",
	}
}

// TestPendingInvitationsAreListedWithBothActions covers the section that did not
// exist: invitations were written to the database and never shown, so a mistyped
// address left a live seven-day sign-up token with no way to see or withdraw it.
func TestPendingInvitationsAreListedWithBothActions(t *testing.T) {
	session := testSession()
	expires := time.Now().Add(5 * 24 * time.Hour)
	pending := []auth.Invitation{{
		ID: "11111111-1111-1111-1111-111111111111", Email: "dana@acme.example",
		Name: "Dana Whitfield", Role: "certificate_manager",
		CreatedAt: time.Now(), ExpiresAt: expires,
	}}
	html := render(t, Users(session, nil, pending))

	for _, want := range []string{
		"Pending invitations",
		"Dana Whitfield",
		"dana@acme.example",
		"/settings/invitations/11111111-1111-1111-1111-111111111111/resend",
		"/settings/invitations/11111111-1111-1111-1111-111111111111/delete",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the pending invitations section is missing %q", want)
		}
	}
}

// TestPendingInvitationsSectionIsHiddenWhenEmpty: an empty card on the team page
// every day of the year is one nobody reads on the day it matters.
func TestPendingInvitationsSectionIsHiddenWhenEmpty(t *testing.T) {
	if html := render(t, Users(testSession(), nil, nil)); strings.Contains(html, "Pending invitations") {
		t.Error("the pending invitations section renders with nothing in it")
	}
}

// TestExpiredInvitationSaysSo. An administrator wondering why somebody never
// appeared needs to be able to tell a lapsed invitation from a live one.
func TestExpiredInvitationSaysSo(t *testing.T) {
	pending := []auth.Invitation{{
		ID: "22222222-2222-2222-2222-222222222222", Email: "old@acme.example",
		Role: "auditor", CreatedAt: time.Now().Add(-10 * 24 * time.Hour),
		ExpiresAt: time.Now().Add(-3 * 24 * time.Hour),
	}}
	html := render(t, Users(testSession(), nil, pending))
	if !strings.Contains(html, "Expired") {
		t.Error("an expired invitation is not marked as expired")
	}
	// With no name stored, the address is the only label available.
	if !strings.Contains(html, "old@acme.example") {
		t.Error("an invitation with no name does not fall back to the address")
	}
}
