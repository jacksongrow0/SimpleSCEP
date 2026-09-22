package home

import (
	"strings"
	"testing"
)

func TestSupportLinksToCommunityResources(t *testing.T) {
	html := render(t, Support(testSession(), "https://docs.example.test", "https://github.example.test/issues", "https://github.example.test/security"))
	for _, want := range []string{"https://docs.example.test", "https://github.example.test/issues", "https://github.example.test/security", "community-supported"} {
		if !strings.Contains(html, want) {
			t.Errorf("community page is missing %q", want)
		}
	}
	for _, stale := range []string{"/support/tickets", "Submit ticket", "Billing", "certificate limit"} {
		if strings.Contains(html, stale) {
			t.Errorf("community page contains hosted-service behavior %q", stale)
		}
	}
}
