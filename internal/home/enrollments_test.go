package home

import (
	"slices"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

// The graph is drawn from enrollmentMethods and from nothing else, so a profile
// missing from it is a line that never appears — with no error, no empty state
// and no gap in the legend to notice. This is the check that turns that into a
// build failure.
func TestEnrollmentMethodsCoverEveryProfile(t *testing.T) {
	plotted := make([]string, 0, len(enrollmentMethods))
	for _, method := range enrollmentMethods {
		if method.Label == "" {
			t.Errorf("enrollment method %q has no label to put in the legend", method.Profile)
		}
		if slices.Contains(plotted, method.Profile) {
			t.Errorf("profile %q is plotted twice, so its certificates are counted twice", method.Profile)
		}
		plotted = append(plotted, method.Profile)
	}
	for _, profile := range pki.EnrollmentProfiles {
		if !slices.Contains(plotted, profile) {
			t.Errorf("profile %q can issue certificates but has no line on the enrollment graph", profile)
		}
	}
	for _, profile := range plotted {
		if !slices.Contains(pki.EnrollmentProfiles, profile) {
			t.Errorf("the enrollment graph plots %q, which is not a profile anything issues", profile)
		}
	}
	// Infrastructure certificates are SimpleSCEP's own registration authority
	// certificates. Plotting them would report enrollments nobody made.
	if slices.Contains(plotted, pki.CertProfileInfrastructure) {
		t.Error("the enrollment graph plots infrastructure certificates")
	}
}
