package auth

import (
	"strings"
	"testing"
)

// The prompt renders what it is handed, in the order it is handed. Nothing in
// the template decides that a code is the answer.
func TestStepUpOffersEveryMethodInOrder(t *testing.T) {
	html := render(t, StepUpMethods(StepUpProps{
		Methods: []StepUpMethodView{
			{Kind: "passkey", Label: "Passkey", Detail: "2 registered"},
			{Kind: "totp", Label: "Authenticator app", Detail: "1 registered"},
		},
		Post: "/security/step-up", Target: "#step-up-result", Swap: "innerHTML",
		FormID: "step-up-form", ResultID: "step-up-result",
	}))

	passkey := strings.Index(html, "Confirm with a passkey")
	code := strings.Index(html, `name="code"`)
	if passkey < 0 {
		t.Fatal("a registered passkey is not offered as a way to confirm")
	}
	if code < 0 {
		t.Fatal("the authenticator code field is missing")
	}
	// A passkey is one gesture and a code is a hunt through a phone, so where
	// both are held the passkey is offered first.
	if passkey > code {
		t.Error("the code field is offered before the passkey")
	}
	if !strings.Contains(html, "2 registered") {
		t.Error("the prompt does not say what it covers")
	}
}

// Someone who holds only one method sees only that one. Rendering every kind
// and disabling the empty ones turns a question into a feature catalogue.
func TestStepUpLeavesOutMethodsTheUserDoesNotHold(t *testing.T) {
	html := render(t, StepUpMethods(StepUpProps{
		Methods: []StepUpMethodView{{Kind: "totp", Label: "Authenticator app", Detail: "1 registered"}},
		Post:    "/security/step-up", FormID: "f", ResultID: "r",
	}))
	if strings.Contains(html, "Confirm with a passkey") {
		t.Error("a passkey is offered to someone who has none registered")
	}
}

// A kind added to the catalogue before its interface exists must be invisible,
// not a broken control. This is the property that makes adding a third factor a
// data change plus one branch.
func TestAnUnknownMethodRendersNothing(t *testing.T) {
	html := render(t, StepUpMethods(StepUpProps{
		Methods: []StepUpMethodView{
			{Kind: "smartcard", Label: "Smart card", Detail: "1 registered"},
			{Kind: "totp", Label: "Authenticator app", Detail: "1 registered"},
		},
		Post: "/security/step-up", FormID: "f", ResultID: "r",
	}))
	if strings.Contains(html, "Smart card") {
		t.Error("a kind with no case in the template rendered anyway")
	}
	if !strings.Contains(html, `name="code"`) {
		t.Error("an unknown kind stopped the kinds after it from rendering")
	}
}

func TestStepUpSaysSoWhenNothingIsRegistered(t *testing.T) {
	html := render(t, StepUpMethods(StepUpProps{Post: "/x", FormID: "f", ResultID: "r"}))
	if !strings.Contains(html, "No confirmation method is registered") {
		t.Error("an empty prompt says nothing at all")
	}
}

// The prompt drawn in the account dialog carries the panel's id, so the
// unlocked panel replaces it in place. That shared id is what keeps the
// confirmation out of a second dialog.
func TestTheLockedPanelIsTheSameSwapTargetAsThePanel(t *testing.T) {
	locked := render(t, SecurityLocked(StepUpProps{
		Action: "open your security settings", Post: "/security/panel",
		Target: "#security-panel", Swap: "outerHTML",
		Methods:  []StepUpMethodView{{Kind: "totp", Label: "Authenticator app", Detail: "1 registered"}},
		FormID:   "security-unlock-form",
		ResultID: "security-unlock-result",
	}))
	if !strings.Contains(locked, `id="security-panel"`) {
		t.Fatal("the prompt does not sit where the panel goes, so it cannot replace it")
	}
	if !strings.Contains(locked, `hx-post="/security/panel"`) {
		t.Error("confirming does not go anywhere that returns the panel")
	}
	if !strings.Contains(locked, `hx-target="#security-panel"`) {
		t.Error("the answer would not land where the prompt is")
	}
	panel := render(t, SecurityPanel(SecurityProps{}))
	if !strings.Contains(panel, `id="security-panel"`) {
		t.Fatal("the panel moved; the two must share one id")
	}
}

// htmx focuses [autofocus] in content it swaps in, and this fragment is always
// swapped in. Without it a keyboard user has to go looking for the field.
func TestTheCodeFieldTakesFocus(t *testing.T) {
	html := render(t, StepUpMethods(StepUpProps{
		Methods: []StepUpMethodView{{Kind: "totp", Label: "Authenticator app", Detail: "1 registered"}},
		Post:    "/x", FormID: "f", ResultID: "r",
	}))
	if !strings.Contains(html, "autofocus") {
		t.Error("the prompt opens with focus nowhere")
	}
	if !strings.Contains(html, `autocomplete="one-time-code"`) {
		t.Error("the code field lost its one-time-code autocomplete hint")
	}
	if !strings.Contains(html, `id="totp-code"`) {
		t.Error("the code field lost the TOTP-specific identity password managers use")
	}
	if !strings.Contains(html, `type="text"`) {
		t.Error("the code field no longer declares a password-manager-compatible input type")
	}
}

func TestStepUpPasskeyRequiresAnExplicitClick(t *testing.T) {
	html := render(t, StepUpMethods(StepUpProps{
		Methods:  []StepUpMethodView{{Kind: "passkey", Label: "Passkey", Detail: "1 registered"}},
		Post:     "/security/step-up",
		FormID:   "step-up-form",
		ResultID: "step-up-result",
	}))
	if strings.Contains(html, "data-passkey-auto") {
		t.Error("the confirmation prompt starts a passkey request automatically")
	}
	if !strings.Contains(html, "data-passkey-stepup") {
		t.Fatal("nothing is left to ask for the prompt a second time")
	}
	marker := strings.Index(html, "data-passkey-stepup")
	buttonStart := strings.LastIndex(html[:marker], "<button")
	buttonEnd := strings.Index(html[marker:], "</button>")
	if buttonStart < 0 || buttonEnd < 0 {
		t.Fatal("the passkey marker is not on a button")
	}
	if strings.Contains(html[buttonStart:marker+buttonEnd], " hidden") {
		t.Error("the passkey retry button is hidden until JavaScript runs")
	}

	refused := render(t, StepUpMethods(StepUpProps{
		Methods:  []StepUpMethodView{{Kind: "passkey", Label: "Passkey", Detail: "1 registered"}},
		Post:     "/security/step-up",
		FormID:   "step-up-form",
		ResultID: "step-up-result",
		Error:    "That code is not right. Check your authenticator and try again.",
	}))
	if !strings.Contains(refused, "data-passkey-stepup") {
		t.Error("the passkey button is gone from the prompt that reports a refusal")
	}
}
