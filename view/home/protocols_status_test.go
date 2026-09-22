package home

import (
	"strings"
	"testing"

	c "github.com/jacksongrow0/SimpleSCEP/view/components"
)

// The badge on the one-time challenges row used to read "Configured" whatever
// the state, because the method stores no credentials and so is configured from
// the moment the endpoint exists. On the three rows that do store something,
// "Configured" means a credential somebody created — so on this one it claimed a
// setup step nobody had taken.
func TestOneTimeChallengesReadReadyRatherThanConfigured(t *testing.T) {
	fresh := ProtocolAuthMethod{Method: "one_time", Label: "One-time challenges",
		Configured: true, NoSetup: true}
	if got := methodStatusLabel(fresh); got != "Ready" {
		t.Errorf("an untouched one-time row reads %q, want Ready", got)
	}
	// Ready is not asking for anything, so it must not wear the colour the row
	// uses to say something is outstanding.
	if got := methodStatusTone(fresh); got != c.ToneNeutral {
		t.Errorf("Ready wears tone %q, want %q", got, c.ToneNeutral)
	}
	on := fresh
	on.Enabled = true
	if got := methodStatusLabel(on); got != "On" {
		t.Errorf("an enabled one-time row reads %q, want On", got)
	}

	html := render(t, AuthMethodRow(fresh, "/api/scep/endpoints/e-1"))
	if strings.Contains(html, ">Configured<") {
		t.Error("the one-time row still claims to have been configured")
	}
	if !strings.Contains(html, ">Ready<") {
		t.Error("the one-time row has no status badge")
	}
}

// The other three rows keep the three states they had: the word means something
// there, and a method that cannot be enabled yet has to keep asking.
func TestConfigurableMethodsKeepTheirStates(t *testing.T) {
	for _, tc := range []struct {
		name      string
		method    ProtocolAuthMethod
		wantLabel string
		wantTone  c.Tone
	}{
		{"unconfigured", ProtocolAuthMethod{Method: "static"}, "Not configured", c.ToneWarning},
		{"configured", ProtocolAuthMethod{Method: "static", Configured: true}, "Configured", c.ToneNeutral},
		{"enabled", ProtocolAuthMethod{Method: "static", Configured: true, Enabled: true}, "On", c.ToneSuccess},
	} {
		if got := methodStatusLabel(tc.method); got != tc.wantLabel {
			t.Errorf("%s reads %q, want %q", tc.name, got, tc.wantLabel)
		}
		if got := methodStatusTone(tc.method); got != tc.wantTone {
			t.Errorf("%s wears tone %q, want %q", tc.name, got, tc.wantTone)
		}
	}
}
