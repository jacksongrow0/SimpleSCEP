package auth

import (
	"strings"
	"testing"
)

func TestSetupIsForTheLocalInstance(t *testing.T) {
	html := render(t, Setup("test-token"))
	for _, want := range []string{"Set up this instance", "test-token", "Create administrator account"} {
		if !strings.Contains(html, want) {
			t.Errorf("setup page is missing %q", want)
		}
	}
	for _, stale := range []string{"accept_terms", "Terms of Service", "Privacy Policy"} {
		if strings.Contains(html, stale) {
			t.Errorf("setup page contains an external agreement %q", stale)
		}
	}
}
