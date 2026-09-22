package home

import (
	"strings"
	"testing"
)

// An unset SAN pattern now refuses every request that carries a subject
// alternative name. That is invisible from the outside — it looks exactly like a
// broken endpoint — so the tile has to say so on all three protocol pages.
func TestUnsetSANPatternIsFlaggedNotConfigured(t *testing.T) {
	html := render(t, SANPatternInfo(""))
	for _, want := range []string{"SAN pattern", "Not configured", "No SANs permitted"} {
		if !strings.Contains(html, want) {
			t.Errorf("the unset SAN tile does not say %q", want)
		}
	}
	// "Any" is what this tile used to read, and it is now the opposite of the
	// truth.
	if strings.Contains(html, ">Any<") {
		t.Error("the unset SAN tile still claims to allow any name")
	}
	// The warning tone is what marks it as something outstanding rather than a
	// setting someone chose.
	if !strings.Contains(html, "text-warning") {
		t.Error("the not-configured badge is not wearing the warning tone")
	}
}

func TestConfiguredSANPatternShowsItselfWithNoBadge(t *testing.T) {
	html := render(t, SANPatternInfo(`\.internal$`))
	if !strings.Contains(html, `\.internal$`) {
		t.Error("the configured pattern is not shown")
	}
	if strings.Contains(html, "Not configured") {
		t.Error("a configured SAN pattern is flagged as unconfigured")
	}
}

// The subject rule keeps the open default, so its tile must keep saying so —
// this is the asymmetry that makes the two rules easy to confuse.
func TestSubjectPatternKeepsTheOpenDefault(t *testing.T) {
	if got := patternLabel(""); got != "Any" {
		t.Errorf("an unset subject pattern reads %q, want Any", got)
	}
	if got := sanPatternLabel(""); got == "Any" {
		t.Error("the unset SAN pattern reads Any, which is what it no longer means")
	}
}
