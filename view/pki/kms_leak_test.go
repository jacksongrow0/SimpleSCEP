package pki

import (
	"strings"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

// TestCADetailsDoNotLeakKMSPaths keeps the Cloud KMS resource name off the page.
//
// It was displayed in the CA details dialog, and briefly offered as
// click-to-copy with the whole path in a data attribute and a title. The path
// names our project, location and key ring: it describes our infrastructure,
// not the customer's certificate authority, and they hold no Google Cloud
// account it means anything in.
//
// The structural defence is that pkiview.CA has no field for it and caViews
// does not copy it, so there is nothing on hand to render. This test is the
// backstop for that being undone — the field is easy to add back, and the leak
// would look like a helpful detail rather than a mistake.
func TestCADetailsDoNotLeakKMSPaths(t *testing.T) {
	session := auth.Session{Role: "administrator"}
	ca := CA{
		ID: "11111111-1111-1111-1111-111111111111", Name: "Issuing Test",
		Type: "issuing", Status: "active", Algorithm: "rsa2048",
		NotAfter: "2027-01-01", ExportPosture: "non_exportable_hsm", IssuedCount: 3,
	}
	html := render(t, CertificateAuthorities(session, []CA{ca}, true, "Google Cloud KMS", true, true))

	for _, forbidden := range []string{
		"cryptoKeyVersions", "cryptoKeys/", "keyRings", "locations/global",
		"projects/simplescep", "fake-hsm",
	} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the certificate authorities page contains %q; the KMS resource "+
				"name describes our infrastructure and must not reach the browser", forbidden)
		}
	}
	// The dialog must still be worth opening.
	for _, want := range []string{"Issuing Test", "rsa2048", "2027-01-01"} {
		if !strings.Contains(html, want) {
			t.Errorf("the CA details lost %q", want)
		}
	}
}
