package auth

import (
	"strings"
	"testing"
)

// The confirmation takes the form's place, so the two have to agree on the
// swap target. A mismatched id sends the fragment nowhere — htmx falls back to
// swapping over the form itself, which happens to look right until someone
// renames one of the two.
func TestTheSentConfirmationLandsWhereTheFormWas(t *testing.T) {
	login := render(t, Login())
	if !strings.Contains(login, `id="login-form"`) {
		t.Fatal("the form has no id for its answer to replace")
	}
	if !strings.Contains(login, `hx-target="#login-form"`) || !strings.Contains(login, `hx-swap="outerHTML"`) {
		t.Error("the form does not ask for its answer to replace it")
	}
	if !strings.Contains(render(t, LoginSent("you@company.com")), `id="login-form"`) {
		t.Error("the confirmation does not carry the id it replaces")
	}
}

// Asking for a link and still being shown the button that asks for one reads as
// nothing having happened. Whatever else the confirmation says, the field and
// the button are not part of it.
func TestTheSentConfirmationReplacesTheFieldAndButton(t *testing.T) {
	sent := render(t, LoginSent("you@company.com"))
	for _, gone := range []string{`name="email"`, "<form", "magic link"} {
		if strings.Contains(sent, gone) {
			t.Errorf("the confirmation still carries %q", gone)
		}
	}
	if !strings.Contains(sent, "you@company.com") {
		t.Error("the address is not echoed, so a typo cannot be spotted")
	}
}

// The same guard internal/auth's enumeration test puts on loginAccepted. Every
// branch of POST /login renders this fragment — address found, not found, rate
// limited, mail failed — so wording that only holds for a real account would be
// an account-existence oracle.
func TestTheSentConfirmationCommitsToNothing(t *testing.T) {
	sent := strings.ToLower(render(t, LoginSent("you@company.com")))
	if !strings.Contains(sent, "if <strong") {
		t.Error("the confirmation does not read as a condition")
	}
	for _, leak := range []string{"we sent", "we've sent", "we have sent", "your link is", "check the inbox for your"} {
		if strings.Contains(sent, leak) {
			t.Errorf("the confirmation claims %q, which is only true for an address that exists", leak)
		}
	}
}

// A form post can carry anything, whatever the field says. Neither an empty
// value nor an absurd one is quoted back into the sentence.
func TestTheSentConfirmationRefusesAnUnusableAddress(t *testing.T) {
	for _, email := range []string{"", strings.Repeat("a", 255) + "@example.com"} {
		if got := render(t, LoginSent(email)); !strings.Contains(got, "that address") {
			t.Errorf("LoginSent(%d chars) did not fall back to the generic phrasing", len(email))
		}
	}
}
