package layout

import (
	"context"
	"strings"
	"testing"
)

// The prompt asks its methods from the server when it opens, because which of
// them a person can use is a fact about that person. It used to be a code field
// and nothing else, so someone who signs in with a passkey was still sent to
// find their authenticator app for every confirmation.
func TestStepUpDialogFetchesTheMethodsItOffers(t *testing.T) {
	var out strings.Builder
	if err := StepUpDialog().Render(context.Background(), &out); err != nil {
		t.Fatalf("render StepUpDialog: %v", err)
	}
	html := out.String()

	if !strings.Contains(html, `hx-get="/security/step-up/methods"`) {
		t.Error("the prompt does not ask which methods this person can use")
	}
	if !strings.Contains(html, `hx-trigger="stepup from:document"`) {
		t.Error("the methods are not fetched when the prompt opens")
	}
	// Hardcoding the code field here is what the fetch replaces. If it comes
	// back, a passkey holder is sent to their authenticator app again.
	if strings.Contains(html, `name="code"`) {
		t.Error("the prompt still hardcodes an authenticator code field")
	}
	// The replay pair has to survive the swap, so it lives outside the fragment.
	for _, want := range []string{`id="step-up-retarget"`, `id="step-up-method"`} {
		if !strings.Contains(html, want) {
			t.Errorf("%s is missing; the refused request could not be replayed", want)
		}
	}
}

// The dialog now makes a request of its own to load its methods. A listener
// that closed on any successful request from inside itself would shut the
// dialog the instant it opened, so the close is driven by a named event the
// step-up handler raises.
func TestTheDialogClosesOnAConfirmationNotOnAnyRequest(t *testing.T) {
	if strings.Contains(stepUpFormScript, "htmx:afterRequest") {
		t.Error("the dialog still closes on any successful request inside it, " +
			"which now includes fetching its own methods")
	}
	if !strings.Contains(stepUpFormScript, "stepupdone") {
		t.Fatal("nothing closes the dialog after a confirmation")
	}
	if !strings.Contains(stepUpFormScript, "htmx.ajax(#step-up-method.value") {
		t.Error("the refused request is no longer replayed with its own method")
	}
	// Nested access into event.detail is what this avoids: it throws at runtime
	// in hyperscript, which then silently installs none of the rest.
	if strings.Contains(stepUpFormScript, "requestConfig") {
		t.Error("the script reaches into event.detail, which fails silently when it throws")
	}
}

// The dialog script must not touch a field that is no longer there. A property
// access on a missing element throws, and hyperscript abandons the rest of the
// feature — which here would mean showModal never running and the prompt never
// appearing at all.
func TestTheDialogScriptTouchesNothingThatIsFetched(t *testing.T) {
	for _, gone := range []string{"#step-up-code"} {
		if strings.Contains(stepUpDialogScript, gone) {
			t.Errorf("stepUpDialogScript still touches %s, which now arrives with the fragment", gone)
		}
	}
	if !strings.Contains(stepUpDialogScript, "call me.showModal()") {
		t.Error("the prompt no longer opens")
	}
}
