package auth

import (
	"strings"
	"testing"
)

// The sign-in pages carry the toast region too.
//
// It used to be mounted on layout.App, on the reasoning that these are
// single-form cards where the message under the button is the right place for
// one. That holds for a rejected field and not for anything else on these
// pages: "If that address has an account, a sign-in link is on its way" is the
// entire outcome of the submission, not a note about the email input, and it
// was the last confirmation in the application still rendered as grey text
// beside a button.
func TestSignInPagesHostTheToastRegion(t *testing.T) {
	for _, page := range []struct {
		name string
		html string
	}{
		{"login", render(t, Login())},
		{"setup", render(t, Setup("test-token"))},
	} {
		if got := strings.Count(page.html, `id="toast-region"`); got != 1 {
			t.Errorf("%s: toast region count = %d, want one", page.name, got)
		}
		if !strings.Contains(page.html, `src="/static/toast.js"`) {
			t.Errorf("%s: has a toast region with nothing to render into it", page.name)
		}
	}
}

// The elements those confirmations used to be swapped into are gone, along with
// the hx-target that pointed at them. A form whose target no longer exists
// swaps into itself, so leaving either half behind would blank the form.
func TestTheSignInFormsNoLongerCarryAResultLine(t *testing.T) {
	for _, page := range []struct {
		name  string
		html  string
		stale string
	}{
		{"login", render(t, Login()), "login-result"},
		{"setup", render(t, Setup("test-token")), "signup-result"},
	} {
		if strings.Contains(page.html, page.stale) {
			t.Errorf("%s: still carries %q", page.name, page.stale)
		}
	}
}

// The second-factor prompt lost its inline line too, and for the same reason
// the two above did: on a card whose entire content is one field and one
// button, the outcome of the form is the outcome of the page. "That code is not
// right" now arrives as a toast, which is also the only place a passkey failure
// could ever have been reported — those ceremonies run over fetch, with nothing
// on the page for htmx to swap into.
//
// The hx-target has to go with it. A form whose target does not exist swaps
// into itself, so a leftover target pointing at a removed element would blank
// the form on the first rejected code.
func TestTheSecondFactorPromptReportsThroughToasts(t *testing.T) {
	for _, page := range []struct {
		name string
		html string
	}{
		{"verify", render(t, Verify())},
		{"enroll", render(t, Enroll("ABCD EFGH IJKL MNOP"))},
	} {
		for _, stale := range []string{"mfa-result", "recovery-result", "passkey-result", "hx-target"} {
			if strings.Contains(page.html, stale) {
				t.Errorf("%s: still carries %q", page.name, stale)
			}
		}
		if !strings.Contains(page.html, `hx-swap="none"`) {
			t.Errorf("%s: a form with no target and no hx-swap swaps over itself", page.name)
		}
	}
}

func TestTheVerifyPromptRequiresAnExplicitPasskeyClick(t *testing.T) {
	verify := render(t, Verify())
	if strings.Contains(verify, "data-passkey-auto") {
		t.Error("the passkey ceremony starts without a click")
	}
	if !strings.Contains(verify, `src="/static/mfa.js?v=`) {
		t.Error("the prompt starts a ceremony with nothing loaded to run it")
	}
	if !strings.Contains(verify, "data-passkey-signin") {
		t.Error("the explicit passkey button is missing")
	}
	if enroll := render(t, Enroll("ABCD EFGH IJKL MNOP")); strings.Contains(enroll, "data-passkey") {
		t.Error("the enrolling page offers a passkey the account cannot have yet")
	}
}

func TestSecondFactorCodeFieldsIdentifyThemselvesToPasswordManagers(t *testing.T) {
	for _, page := range []struct {
		name string
		html string
	}{
		{"verify", render(t, Verify())},
		{"enroll", render(t, Enroll("ABCD EFGH IJKL MNOP"))},
	} {
		for _, want := range []string{
			`id="totp-code"`,
			`type="text"`,
			`autocomplete="one-time-code"`,
		} {
			if !strings.Contains(page.html, want) {
				t.Errorf("%s: TOTP field does not contain %s", page.name, want)
			}
		}
	}
}
