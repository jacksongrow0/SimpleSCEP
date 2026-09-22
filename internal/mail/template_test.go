package mail

import (
	"strings"
	"testing"
)

func testAction() Action {
	return Action{
		Heading:     "Sign in to SimpleSCEP",
		Body:        "Use the button below to sign in.",
		ButtonLabel: "Sign in",
		URL:         "https://app.example.com/auth/login?token=abc123",
		Expiry:      "15 minutes",
		Unrequested: "If you did not try to sign in, you can ignore this email.",
	}
}

// TestActionSendsBothParts is the deliverability fix. Every message used to be a
// single anchor tag as HTML with no text alternative, which is one of the
// strongest spam signals there is — and the only way into this service is a magic
// link, so a message in the spam folder is indistinguishable from login being
// broken.
func TestActionSendsBothParts(t *testing.T) {
	msg := testAction().Message("someone@example.com", "Your SimpleSCEP sign-in link")
	if msg.Body == "" {
		t.Fatal("no HTML part")
	}
	if msg.Text == "" {
		t.Fatal("no plain-text part; the message is HTML-only")
	}
	if strings.Contains(msg.Text, "<") {
		t.Errorf("the text part carries markup: %q", msg.Text)
	}
	if msg.To != "someone@example.com" || msg.Subject != "Your SimpleSCEP sign-in link" {
		t.Errorf("envelope not carried through: to=%q subject=%q", msg.To, msg.Subject)
	}
}

// TestActionSaysWhoItIsFromAndWhenItExpires covers what a bare anchor could not.
// A recipient deciding whether to trust a link needs the sender's identity, and a
// link with no stated lifetime is one people sit on and then report as broken.
func TestActionSaysWhoItIsFromAndWhenItExpires(t *testing.T) {
	body, text := testAction().Render()
	for _, part := range []struct{ name, content string }{{"HTML", body}, {"text", text}} {
		for _, want := range []string{"SimpleSCEP", "15 minutes", "did not try to sign in"} {
			if !strings.Contains(part.content, want) {
				t.Errorf("the %s part does not mention %q", part.name, want)
			}
		}
	}
}

// TestActionPrintsTheURLAsWellAsLinkingIt: a client that strips the anchor still
// has to leave the person something to copy, or the email is a dead end.
func TestActionPrintsTheURLAsWellAsLinkingIt(t *testing.T) {
	a := testAction()
	body, text := a.Render()
	if strings.Count(body, a.URL) < 2 {
		t.Error("the URL appears only once in the HTML, so a stripped anchor leaves nothing to copy")
	}
	if !strings.Contains(text, a.URL) {
		t.Error("the text part does not carry the URL")
	}
}

// TestActionEscapesItsContent. The URL carries a token from a generated value and
// the heading is ours, but nothing here should be able to inject markup — an
// unescaped template is how a link becomes a redirect somebody else chose.
func TestActionEscapesItsContent(t *testing.T) {
	a := testAction()
	a.URL = `https://app.example.com/?x="><script>alert(1)</script>`
	a.Body = `<img src=x onerror=alert(1)>`
	body, _ := a.Render()
	if strings.Contains(body, "<script>") {
		t.Error("a script tag survived into the HTML body")
	}
	if strings.Contains(body, "<img src=x") {
		t.Error("unescaped markup survived from the body text")
	}
}

// TestActionOmitsWhatItWasNotGiven: an empty expiry must not render "This link
// expires in ." — a message that reads as broken is worse than one that says less.
func TestActionOmitsWhatItWasNotGiven(t *testing.T) {
	a := testAction()
	a.Expiry, a.Unrequested = "", ""
	body, text := a.Render()
	for _, part := range []string{body, text} {
		if strings.Contains(part, "expires in") {
			t.Error("an expiry line was rendered with no expiry to state")
		}
	}
}
