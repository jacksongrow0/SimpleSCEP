package home

import (
	"strings"
	"testing"
	"time"

	c "github.com/jacksongrow0/SimpleSCEP/view/components"
)

// panelOf slices one protocol tab out of the rendered page. Both tabs render
// from a single page load — the tabs are client-side only — so an assertion
// about one of them has to be scoped or it matches the other.
//
// Unlike the version in view/pki/render_test.go this does not first truncate at
// the opening <dialog>: the SCEP panel renders its setup dialog inside itself,
// so doing that here would cut the page off before the ACME panel begins. The
// bound is the next panel marker instead.
func panelOf(t *testing.T, html, tab string) string {
	t.Helper()
	start := strings.Index(html, `data-panel="`+tab+`"`)
	if start < 0 {
		t.Fatalf("no %q panel on the page", tab)
	}
	rest := html[start:]
	if next := strings.Index(rest[1:], `data-panel="`); next >= 0 {
		return rest[:next]
	}
	return rest
}

// TestACMEPanelExplainsTheAuthorizationModel: a client skipping a challenge the
// operator expected to see is the most surprising thing about this
// implementation, so the explanation has to be on the page and not only in the
// documentation.
func TestACMEPanelExplainsTheAuthorizationModel(t *testing.T) {
	html := panelOf(t, render(t, Protocols(testSession(), ProtocolPage{
		ACME: ACMEPage{CAs: []ProtocolCA{{ID: "ca-1", Name: "Issuing CA"}}},
	})), "acme")

	for _, want := range []string{"External Account Binding", "already valid"} {
		if !strings.Contains(html, want) {
			t.Errorf("the panel does not mention %q", want)
		}
	}
}

func TestACMEPanelOffersSetupWithoutACA(t *testing.T) {
	html := panelOf(t, render(t, Protocols(testSession(), ProtocolPage{
		ACME: ACMEPage{},
	})), "acme")

	if !strings.Contains(html, "Create an active issuing CA first") {
		t.Error("an organization with no CA is not told to create one")
	}
	if strings.Contains(html, "acme-setup-dialog').showModal()") {
		t.Error("the add-endpoint button is offered with no CA to bind to")
	}
}

// TestACMEEndpointViewShowsTheDirectoryURL: the directory URL is the only thing
// an operator has to carry to a client, so it must be on the page and
// copyable.
func TestACMEEndpointViewShowsTheDirectoryURL(t *testing.T) {
	html := render(t, ACMEEndpointView(testSession(), ACMEEndpointData{
		Endpoint: ACMEEndpoint{ID: "e-1", Name: "Ingress", CAName: "Issuing CA",
			DirectoryURL: "https://pki.example.test/acme/e-1/directory",
			APIBase:      "/api/acme/endpoints/e-1", Enabled: true, ValidityDays: 90},
	}))

	if !strings.Contains(html, "https://pki.example.test/acme/e-1/directory") {
		t.Error("the directory URL is not shown")
	}
	if !strings.Contains(html, "The client must already trust") {
		t.Error("the trust prerequisite is not stated; it is what breaks a first connection")
	}
	if !strings.Contains(html, "No credentials yet") {
		t.Error("an endpoint with no credentials does not say so")
	}
}

// TestACMEDeleteDialogNamesTheSilentFailure. Every consequence of deleting is
// delayed, and for ACME the delay is invisible: clients renew unattended, so
// nobody sees an error until a certificate expires in production.
func TestACMEDeleteDialogNamesTheSilentFailure(t *testing.T) {
	html := render(t, ACMEEndpointView(testSession(), ACMEEndpointData{
		Endpoint: ACMEEndpoint{ID: "e-1", Name: "Ingress", APIBase: "/api/acme/endpoints/e-1",
			LiveCertificates: 12},
	}))

	if !strings.Contains(html, "Renewal fails silently") {
		t.Error("the delete dialog does not warn that renewal failure is silent")
	}
	if !strings.Contains(html, "12 certificates") {
		t.Error("the delete dialog does not say how many certificates depend on the endpoint")
	}
	if !strings.Contains(html, "No certificate is revoked") {
		t.Error("the delete dialog does not say what deletion leaves alone")
	}
}

func TestACMECredentialSecretShowsAllThreeParts(t *testing.T) {
	html := render(t, ACMECredentialSecret(
		"https://pki.example.test/acme/e-1/directory", "kid-value", "hmac-value", "/protocols/acme/e-1"))

	// A client needs all three; showing the key without the other two would make
	// the one moment it is readable useless.
	for _, want := range []string{"https://pki.example.test/acme/e-1/directory", "kid-value", "hmac-value"} {
		if !strings.Contains(html, want) {
			t.Errorf("the secret panel omits %q", want)
		}
	}
	if !strings.Contains(html, "Copy this now") {
		t.Error("the secret panel does not warn that the key is shown once")
	}
}

func TestACMECredentialStatus(t *testing.T) {
	past, future := timePtr(-1), timePtr(1)
	cases := []struct {
		name string
		cr   ACMECredential
		want string
	}{
		{"revoked wins", ACMECredential{Revoked: true, SingleUse: true, Used: true}, "Revoked"},
		{"expired", ACMECredential{ExpiresAt: past}, "Expired"},
		{"unexpired", ACMECredential{ExpiresAt: future}, "Active"},
		{"single use spent", ACMECredential{SingleUse: true, Used: true}, "Used"},
		{"single use unspent", ACMECredential{SingleUse: true}, "Unused"},
		{"reusable", ACMECredential{Used: true}, "Active"},
	}
	for _, tc := range cases {
		if got := tc.cr.Status(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func timePtr(hours int) *time.Time {
	t := time.Now().Add(time.Duration(hours) * time.Hour)
	return &t
}

// TestOrderLogLabelsAreNotProtocolJargon pins the order log's vocabulary. The
// log renders whatever status the server stored, and RFC 8555's names are the
// state machine's rather than the operator's: "ready" in particular reads as
// success to anyone who has not memorized §7.1.6, when it actually means the
// client has not come back to finalize yet.
func TestOrderLogLabelsAreNotProtocolJargon(t *testing.T) {
	orders := []ACMEOrder{
		{ID: "o-1", Status: "valid", Identifiers: "a.example.internal", CreatedAt: time.Now()},
		{ID: "o-2", Status: "ready", Identifiers: "b.example.internal", CreatedAt: time.Now()},
		{ID: "o-3", Status: "invalid", Identifiers: "c.example.internal", CreatedAt: time.Now(),
			Error: "the order expired before it was finalized"},
	}
	html := render(t, ACMEOrderLog(orders))

	for _, want := range []string{"Issued", "Awaiting finalize", "Failed",
		"the order expired before it was finalized"} {
		if !strings.Contains(html, want) {
			t.Errorf("the order log does not show %q: %s", want, html)
		}
	}
	// The raw status must not reach the page alongside its label. Checking the
	// pill's own text rather than the string anywhere avoids matching the
	// identifiers or the markup.
	if strings.Contains(html, ">ready<") {
		t.Errorf("the order log shows the raw protocol status: %s", html)
	}
}

// TestOrderResultCoversEveryServerStatus is the guard against a status the
// server can write but the log has no words for. Orders are created ready and
// move to valid or invalid; pending and processing are covered because they are
// RFC 8555 order states that a future change could start using.
func TestOrderResultCoversEveryServerStatus(t *testing.T) {
	cases := map[string]string{
		"ready":      "Awaiting finalize",
		"valid":      "Issued",
		"invalid":    "Failed",
		"pending":    "Awaiting validation",
		"processing": "Issuing",
	}
	for status, want := range cases {
		got := ACMEOrder{Status: status}.Result()
		if got != want {
			t.Errorf("status %q rendered as %q, want %q", status, got, want)
		}
		if got == status {
			t.Errorf("status %q fell through to the raw protocol name", status)
		}
	}
	// An unknown status is shown rather than swallowed: a blank result cell
	// would look like a rendering fault instead of a state nobody mapped.
	if got := (ACMEOrder{Status: "surprising"}).Result(); got != "surprising" {
		t.Errorf("an unmapped status rendered as %q, want it shown verbatim", got)
	}
}

// TestOrderToneFlagsOnlyRealOutcomes keeps the log from crying wolf. Every order
// is briefly "ready" between newOrder and finalize, so colouring that as a
// problem would flag successful enrollments mid-flight.
func TestOrderToneFlagsOnlyRealOutcomes(t *testing.T) {
	cases := map[string]c.Tone{
		"valid":      c.ToneSuccess,
		"invalid":    c.ToneDestructive,
		"ready":      c.ToneNeutral,
		"pending":    c.ToneNeutral,
		"processing": c.ToneNeutral,
	}
	for status, want := range cases {
		if got := (ACMEOrder{Status: status}).Tone(); got != want {
			t.Errorf("status %q got tone %q, want %q", status, got, want)
		}
	}
}

// TestIntuneConnectExplainsTheGraphPermissionFirst covers the pre-consent
// dialog. Entra's consent screen is Microsoft's page and carries no text of
// ours, so this dialog is the only place an administrator can be told why a
// certificate product wants to read applications. Connect going straight to
// Microsoft again would put them in front of "Read all applications" with
// nothing to explain it.
func TestIntuneConnectExplainsTheGraphPermissionFirst(t *testing.T) {
	html := render(t, IntuneConnectionCard(ProtocolIntune{Connected: false}))

	if !strings.Contains(html, `id="intune-consent-dialog"`) {
		t.Fatalf("no consent dialog on the card: %s", html)
	}
	dialog := html[strings.Index(html, `id="intune-consent-dialog"`):]
	// templ escapes the apostrophes in the attribute; the parser decodes them
	// again before hyperscript reads it, so the escaped form is what ships.
	if !strings.Contains(html, "getElementById(&#39;intune-consent-dialog&#39;).showModal()") {
		t.Error("Connect does not open the dialog")
	}
	// Each permission has to be named as Microsoft's consent screen spells it,
	// or an administrator cannot match the dialog to what they are approving.
	// "Proceed" is the confirm button: the dialog is a gate in front of Entra, so
	// it needs a way through as well as the Cancel beside it.
	for _, want := range []string{"SCEP challenge validation", "Read all applications",
		`View users' basic profile`, "Proceed", "Cancel"} {
		if !strings.Contains(html, want) {
			t.Errorf("the dialog does not mention %q", want)
		}
	}
	if got := strings.Count(dialog, `class="flex items-start"`); got != 3 {
		t.Errorf("permission checks are not aligned with their labels: got %d top-aligned rows, want 3", got)
	}
	// The Graph permission is the one customers push back on, so it carries the
	// attribution and the citation. Losing either leaves SimpleSCEP looking like
	// it chose to ask for this.
	if !strings.Contains(html, "Required by Microsoft") {
		t.Error("the dialog does not say who requires Read all applications")
	}
	if !strings.Contains(html, "cannot read secrets") {
		t.Error("the dialog does not bound what the permission allows")
	}
	if !strings.Contains(html, "learn.microsoft.com/en-us/intune/fundamentals/certificates/third-party-ca-scep") {
		t.Errorf("the dialog does not link Microsoft's instruction to request it: %s", html)
	}
	// The post that leaves for Microsoft must be behind the dialog rather than
	// on the card, so it cannot be reached without the explanation.
	if !strings.Contains(dialog, "/api/scep/intune/connect") {
		t.Error("the connect post is not inside the dialog")
	}
	if before := html[:strings.Index(html, `id="intune-consent-dialog"`)]; strings.Contains(before, "/api/scep/intune/connect") {
		t.Error("Connect still posts straight to Microsoft, skipping the explanation")
	}
}

// TestIntuneConsentDialogReportsFailuresWhereItAsked keeps a refusal visible.
// connectIntune answers a failure by swapping a message rather than redirecting,
// and the card's own error line sits behind the modal backdrop, so a dialog
// targeting it would report "the Intune connector is not deployed" somewhere the
// administrator cannot see.
func TestIntuneConsentDialogReportsFailuresWhereItAsked(t *testing.T) {
	html := render(t, IntuneConnectionCard(ProtocolIntune{Connected: false}))
	dialog := html[strings.Index(html, `id="intune-consent-dialog"`):]

	if !strings.Contains(dialog, `id="intune-consent-error"`) {
		t.Error("the dialog has no error line of its own")
	}
	if !strings.Contains(dialog, `hx-target="#intune-consent-error"`) {
		t.Errorf("the connect form does not report into the dialog: %s", dialog)
	}
}

// TestConnectedIntuneCardDropsTheDialog: there is no Connect button once the
// directory is connected, so rendering the dialog would leave an unreachable
// modal in the page.
func TestConnectedIntuneCardDropsTheDialog(t *testing.T) {
	html := render(t, IntuneConnectionCard(ProtocolIntune{Connected: true, TenantID: "t-1"}))
	if strings.Contains(html, "intune-consent-dialog") {
		t.Error("a connected card still renders the consent dialog")
	}
	if !strings.Contains(html, "/api/scep/intune/disconnect") {
		t.Error("a connected card offers no way to disconnect")
	}
}
