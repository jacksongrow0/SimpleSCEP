package home

import (
	"strings"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

func notificationsForm(t *testing.T, session auth.Session) string {
	t.Helper()
	html := render(t, Organization(session, auth.Organization{Name: "Acme"}, testPosture()))
	_, rest, ok := strings.Cut(html, `id="preferences-form"`)
	if !ok {
		t.Fatal("the Organization page renders no notification preferences form")
	}
	form, _, ok := strings.Cut(rest, "</form>")
	if !ok {
		t.Fatal("notification preferences form is not closed")
	}
	return form
}

// expiryAlertToggle returns the one input tag the alert switch is made of.
// Attributes render in alphabetical order, so an assertion on the whole form
// would be matching a `checked` that could belong to any field.
func expiryAlertToggle(t *testing.T, session auth.Session) string {
	t.Helper()
	_, rest, ok := strings.Cut(notificationsForm(t, session), "<input")
	if !ok {
		t.Fatal("the notification preferences form renders no input at all")
	}
	tag, _, _ := strings.Cut(rest, ">")
	return tag
}

// TestExpiryAlertSwitchPostsItsState covers the field the alert preference is
// saved through, because for a while there was not one. The toggle was a
// c.Switch, which renders a <button>: the name and the checked state were
// attributes on an element the browser never serialises, so the switch could
// not be moved and every save posted no expiry_alerts at all — which
// auth.updateNotifications reads, correctly, as off.
//
// Asserted on the rendered HTML rather than on the templ source because that is
// the whole of the bug: the template said "name" and "checked" and looked right.
func TestExpiryAlertSwitchPostsItsState(t *testing.T) {
	admin := testSession()
	admin.ExpiryAlertDays = 45

	off := expiryAlertToggle(t, admin)
	if !strings.Contains(off, `name="expiry_alerts"`) || !strings.Contains(off, `type="checkbox"`) {
		t.Errorf("the expiry alert toggle is not a checkbox the form can post: %s", off)
	}
	if strings.Contains(off, " checked") {
		t.Errorf("the toggle renders on for an organization with alerts disabled: %s", off)
	}

	admin.ExpiryAlertsEnabled = true
	if on := expiryAlertToggle(t, admin); !strings.Contains(on, " checked") {
		t.Errorf("the toggle renders off for an organization with alerts enabled: %s", on)
	}
	if window := notificationsForm(t, admin); !strings.Contains(window, `value="45"`) {
		t.Error("the warning window is not rendered from the stored value")
	}
}

// TestExpiryAlertReadsTheOrganizationNotTheShell is the reason this lives on the
// Organization page rather than in the account settings dialog. The dialog is
// part of the application shell, which each package hands its own layout.Session
// — and view/pki built one that omitted these two fields, so the switch rendered
// off on every certificate authority page whatever was stored. This page is
// passed the whole auth.Session, so there is no second copy to fall behind.
func TestExpiryAlertReadsTheOrganizationNotTheShell(t *testing.T) {
	session := testSession()
	session.ExpiryAlertsEnabled = true
	session.ExpiryAlertDays = 7
	if form := notificationsForm(t, session); !strings.Contains(form, `value="7"`) {
		t.Error("the Organization page does not read the window off the session it is given")
	}
}

// TestExpiryAlertSwitchIsAdminOnly guards the other half. The page is only
// linked in the sidebar for administrators but is not refused to anyone else, so
// a member reaching it must be shown the state without a control the server
// would reject.
func TestExpiryAlertSwitchIsAdminOnly(t *testing.T) {
	member := testSession()
	member.Role = "member"
	member.ExpiryAlertsEnabled = true

	form := notificationsForm(t, member)
	if strings.Contains(form, `name="expiry_alerts"`) || strings.Contains(form, `name="expiry_alert_days"`) {
		t.Error("a non-administrator is given a control for an organization-wide setting")
	}
	if !strings.Contains(form, "Enabled") {
		t.Error("a non-administrator is not told the current state")
	}
}

// TestAccountDialogNoLongerCarriesNotifications fails if the card is ever put
// back beside the profile form, where its heading named the person rather than
// the organization whose setting it is.
func TestAccountDialogNoLongerCarriesNotifications(t *testing.T) {
	html := render(t, Organization(testSession(), auth.Organization{Name: "Acme"}, testPosture()))
	_, dialog, ok := strings.Cut(html, `id="user-dialog"`)
	if !ok {
		t.Fatal("the shell renders no account settings dialog")
	}
	if strings.Contains(dialog, "expiry_alerts") {
		t.Error("the account settings dialog still carries the organization's alert preference")
	}
}
