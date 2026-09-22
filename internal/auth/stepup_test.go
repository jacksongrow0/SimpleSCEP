package auth

import (
	"strings"
	"testing"
)

// Every kind the catalogue offers must have a branch in the template, or it
// would be listed by the server and silently dropped by the view — a method the
// user is told nothing about and cannot use.
//
// This is the check that keeps "add a factor" honest: the compiler will not
// catch a new catalogue entry with no interface behind it, and neither will any
// render test that only covers the kinds that exist today.
func TestEveryCatalogueKindHasAnInterface(t *testing.T) {
	rendered := map[string]bool{StepUpTOTP: true, StepUpPasskey: true}
	for _, entry := range stepUpCatalogue {
		if !rendered[entry.kind] {
			t.Errorf("stepUpCatalogue offers %q but view/auth/step_up.templ has no case for it; "+
				"it would be listed and then dropped", entry.kind)
		}
		if entry.label == "" {
			t.Errorf("%q has no label", entry.kind)
		}
		if strings.Contains(entry.kind, "-") {
			// Kinds reach the browser as data attributes and event payloads.
			t.Errorf("%q contains a hyphen", entry.kind)
		}
	}
}

// A passkey is one gesture; a code is a hunt through a phone. Where both are
// held the passkey comes first, which is the opposite of what the interface did
// before this existed.
func TestPasskeysAreOfferedBeforeCodes(t *testing.T) {
	var passkey, totp = -1, -1
	for i, entry := range stepUpCatalogue {
		switch entry.kind {
		case StepUpPasskey:
			passkey = i
		case StepUpTOTP:
			totp = i
		}
	}
	if passkey < 0 || totp < 0 {
		t.Fatalf("catalogue is missing a kind: passkey=%d totp=%d", passkey, totp)
	}
	if passkey > totp {
		t.Error("the authenticator code is offered before the passkey")
	}
}

func TestRegisteredCountReadsAsEnglish(t *testing.T) {
	if got := registeredCount(1); got != "1 registered" {
		t.Errorf("registeredCount(1) = %q", got)
	}
	if got := registeredCount(3); got != "3 registered" {
		t.Errorf("registeredCount(3) = %q", got)
	}
}
