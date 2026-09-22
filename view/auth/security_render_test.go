package auth

import (
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"
)

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

func panelProps() SecurityProps {
	added := time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC)
	used := added.Add(48 * time.Hour)
	return SecurityProps{
		Authenticators: []AuthenticatorView{
			{ID: "totp-1", Label: "Personal phone", AddedAt: added, LastUsedAt: &used},
			{ID: "totp-2", Label: "Backup key", AddedAt: added},
		},
		CanRemoveAuthenticator: true,
		RecoveryLeft:           7,
		RecoveryTotal:          10,
		GraceMinutes:           5,
		Passkeys: []PasskeyView{
			{ID: "pk-1", Label: "Work laptop", CreatedAt: added, LastUsedAt: &used},
		},
		PasskeysAvailable: true,
	}
}

// templCall matches an unparsed component call left in the output. templ only
// recognises `@component` where a node may begin, so writing one partway through
// a line of prose emits its own source instead of calling it — the generated code
// still compiles and the page still renders, which is why this needs a test
// rather than a compiler.
var templCall = regexp.MustCompile(`@[a-zA-Z_]+\.[A-Z][a-zA-Z]*\(`)

func TestPanelRendersItsComponentsRatherThanTheirSource(t *testing.T) {
	for name, html := range map[string]string{
		"panel":     render(t, SecurityPanel(panelProps())),
		"enrolment": render(t, SecurityPanel(withEnrolment(panelProps()))),
	} {
		if found := templCall.FindString(html); found != "" {
			t.Errorf("%s emitted %q as text; a component call has to start a line", name, found)
		}
	}
}

func withEnrolment(props SecurityProps) SecurityProps {
	props.Enrolling = true
	props.EnrollSecret = "ABCD EFGH IJKL MNOP"
	return props
}

// TestPanelDatesReadAsSentences pins the spacing around those calls. templ trims
// the whitespace around a text node on its own line, so the words next to a
// timestamp have to carry their own spaces or the line renders as "AddedMar 4".
func TestPanelDatesReadAsSentences(t *testing.T) {
	html := render(t, SecurityPanel(panelProps()))
	for _, want := range []string{"Added <time", "</time> · last used <time"} {
		if !strings.Contains(html, want) {
			t.Errorf("panel does not contain %q; the dates have lost their spacing", want)
		}
	}
	if strings.Contains(html, "Added<time") {
		t.Error("the date runs into the word before it")
	}
}

func TestPanelOffersNoWayToRegenerateRecoveryCodes(t *testing.T) {
	html := render(t, SecurityPanel(panelProps()))
	// The route is gone; this is the other half of that, so a control cannot be
	// added back without the route being noticed as missing.
	for _, gone := range []string{"/security/recovery-codes", "Generate new codes"} {
		if strings.Contains(html, gone) {
			t.Errorf("panel still offers %q; recovery codes are issued once", gone)
		}
	}
	if !strings.Contains(html, "7 of 10 left") {
		t.Error("panel does not say how many recovery codes are left")
	}
}

// TestTheLastAuthenticatorCannotBeRemovedFromThePanel is the visible half of the
// floor the repository enforces. A button that is always refused teaches people
// to ignore refusals, so it is not rendered at all.
func TestTheLastAuthenticatorCannotBeRemovedFromThePanel(t *testing.T) {
	props := panelProps()
	props.Authenticators = props.Authenticators[:1]
	props.CanRemoveAuthenticator = false

	html := render(t, SecurityPanel(props))
	if strings.Contains(html, "/security/totp/totp-1/delete") {
		t.Error("the only authenticator is offered a Remove button")
	}
	if !strings.Contains(html, "Only authenticator") {
		t.Error("nothing explains why the only authenticator cannot be removed")
	}

	// With a second registered, both become removable.
	html = render(t, SecurityPanel(panelProps()))
	for _, want := range []string{"/security/totp/totp-1/delete", "/security/totp/totp-2/delete"} {
		if !strings.Contains(html, want) {
			t.Errorf("panel does not offer %q once a spare exists", want)
		}
	}
}

// TestEveryPanelActionRetargetsThePanel keeps the fragment self-contained. These
// forms live inside a dialog; a swap that misses #security-panel replaces
// something else on the page, and the step-up retry has no target of its own at
// all.
func TestEveryPanelActionRetargetsThePanel(t *testing.T) {
	html := render(t, SecurityPanel(withEnrolment(panelProps())))
	posts := regexp.MustCompile(`hx-post="([^"]+)"`).FindAllStringSubmatch(html, -1)
	if len(posts) < 5 {
		t.Fatalf("found only %d actions in the panel; the scan is broken", len(posts))
	}
	if got := strings.Count(html, `hx-target="#security-panel"`); got < len(posts) {
		t.Errorf("%d actions but only %d target the panel", len(posts), got)
	}
}

func TestPasskeysSayWhyTheyAreUnavailable(t *testing.T) {
	props := panelProps()
	props.PasskeysAvailable = false
	html := render(t, SecurityPanel(props))
	if !strings.Contains(html, "not available on this deployment") {
		t.Error("a deployment without passkeys says nothing about it")
	}
	if strings.Contains(html, "data-passkey-register") {
		t.Error("a register button is rendered where passkeys cannot work")
	}

	// Where they are available, the button ships hidden — mfa.js reveals it — and
	// the explanation for a browser that cannot run the ceremony ships with it.
	html = render(t, SecurityPanel(panelProps()))
	if !strings.Contains(html, "data-passkey-register") {
		t.Error("no way to register a passkey")
	}
	if !strings.Contains(html, "data-passkey-unsupported") {
		t.Error("nothing explains a browser with no WebAuthn; the button would just be missing")
	}
}
