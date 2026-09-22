package pki

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

func managerSession() auth.Session {
	return auth.Session{ID: "s-1", UserID: "u-1", OrgID: "org-1", Name: "Jane Doe",
		Role: "administrator", OrganizationName: "Acme"}
}

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

// panelOf returns the markup of one tab panel, so a test can assert which rows
// a tab shows rather than only that the page mentions them somewhere. The
// detail dialogs are rendered once for every row after the panels, so the
// search stops at the first of them.
func panelOf(t *testing.T, html, tab string) string {
	t.Helper()
	if dialogs := strings.Index(html, "<dialog"); dialogs >= 0 {
		html = html[:dialogs]
	}
	start := strings.Index(html, `data-panel="`+tab+`"`)
	if start < 0 {
		t.Fatalf("no %q panel on the page", tab)
	}
	rest := html[start:]
	if next := strings.Index(rest[1:], `data-panel="`); next >= 0 {
		return rest[:next]
	}
	return rest
}

// A device certificate enrolled over SCEP is a client certificate, but it is
// not a manual CSR-based issuance.
func TestClientTabShowsSCEPEnrolledDeviceCertificates(t *testing.T) {
	data := CertificatesData{
		Identities: 2,
		Rows: []CertRow{
			{ID: "1", CN: "laptop-01", CAName: "I2", Profile: "scep", EKUs: "client_auth", Status: "issued"},
			{ID: "2", CN: "vpn.example.com", CAName: "I2", Profile: "server", EKUs: "server_auth", Status: "issued"},
		},
	}
	html := render(t, Certificates(managerSession(), data))
	client := panelOf(t, html, "client")
	if !strings.Contains(client, "laptop-01") {
		t.Error("a client_auth certificate enrolled over SCEP is missing from the Client / Device tab")
	}
	if strings.Contains(client, "vpn.example.com") {
		t.Error("a server certificate should not appear under Client / Device")
	}
	server := panelOf(t, html, "server")
	if !strings.Contains(server, "vpn.example.com") {
		t.Error("a server_auth certificate is missing from the Server tab")
	}
	if !strings.Contains(client, "SCEP") {
		t.Error("a SCEP certificate should be labeled with its enrollment protocol")
	}
	if csr := panelOf(t, html, "csr"); strings.Contains(csr, "laptop-01") {
		t.Error("a SCEP-enrolled certificate should not appear under CSR-based")
	}
}

// An ACME certificate arrives through a CSR too, but its origin is the ACME
// protocol and must not be presented as a manually submitted CSR.
func TestACMECertificatesShowTheirEnrollmentProtocol(t *testing.T) {
	data := CertificatesData{
		Identities: 1,
		Rows: []CertRow{{ID: "1", CN: "api.example.com", CAName: "I2",
			Profile: "acme", EKUs: "server_auth", Status: "issued"}},
	}
	html := render(t, Certificates(managerSession(), data))
	all := panelOf(t, html, "all")
	if !strings.Contains(all, "ACME") {
		t.Error("an ACME certificate should be labeled with its enrollment protocol")
	}
	if strings.Contains(all, "CSR-based") {
		t.Error("an ACME certificate should not be labeled as CSR-based")
	}
	if !strings.Contains(panelOf(t, html, "server"), "api.example.com") {
		t.Error("an ACME server certificate should remain visible under Server")
	}
	if strings.Contains(panelOf(t, html, "csr"), "api.example.com") {
		t.Error("an ACME certificate should not appear under CSR-based")
	}
}

// The registration authority certificate is SimpleSCEP's own; it belongs in
// none of the usage tabs and must not read as one of the customer's devices.
func TestInfrastructureCertificatesStayOutOfUsageTabs(t *testing.T) {
	data := CertificatesData{
		Identities: 0,
		Rows: []CertRow{{ID: "1", CN: "SimpleSCEP RA 1234", CAName: "I2",
			Profile: "infrastructure", EKUs: "client_auth", Status: "issued"}},
	}
	html := render(t, Certificates(managerSession(), data))
	for _, tab := range []string{"client", "csr", "server"} {
		if strings.Contains(panelOf(t, html, tab), "SimpleSCEP RA 1234") {
			t.Errorf("the RA certificate should not appear on the %q tab", tab)
		}
	}
	if !strings.Contains(panelOf(t, html, "all"), "SimpleSCEP RA 1234") {
		t.Error("the RA certificate should still be visible under All")
	}
}

func TestIssuingCAActionOffered(t *testing.T) {
	cas := []CA{
		{ID: "r", Name: "Root", Type: "root", Status: "active"},
		{ID: "i", Name: "Issuer", Type: "issuing", Status: "active"},
	}
	html := render(t, CertificateAuthorities(managerSession(), cas, true, "Google Cloud KMS", true, true))
	if !strings.Contains(html, "1 issuing CAs configured") {
		t.Error("the issuing CA card does not report how many are configured")
	}
	if !strings.Contains(html, `data-dialog="ca-dialog"`) {
		t.Error("the create dialog should be offered")
	}
	for _, want := range []string{`name="protection"`, `value="hsm"`, `value="software"`} {
		if !strings.Contains(html, want) {
			t.Errorf("CA creation form missing %s", want)
		}
	}
}

func TestLocalCAFormOnlyOffersSoftwareProtection(t *testing.T) {
	cas := []CA{{ID: "r", Name: "Root", Type: "root", Status: "active"}}
	html := render(t, CertificateAuthorities(managerSession(), cas, true, "Local in-memory keys", false, false))
	if strings.Contains(html, `value="hsm"`) {
		t.Error("local provider offered HSM protection")
	}
	if !strings.Contains(html, `value="software"`) || !strings.Contains(html, "deprecated local provider") {
		t.Error("local provider did not explain its software-only deprecated posture")
	}
}

func TestIssuingCAActionRequiresARoot(t *testing.T) {
	html := render(t, CertificateAuthorities(managerSession(), nil, false, "Google Cloud KMS", true, true))
	if strings.Contains(html, `data-dialog="ca-dialog"`) {
		t.Error("the create dialog should not be offered before a root CA exists")
	}
	if !strings.Contains(html, "Create a Root CA first") {
		t.Error("the blocked action should say what to do first")
	}
}

// The root import is reachable from a button beside the Root CA, not from the
// issuing CA card — the one section of the page that cannot be about a root.
func TestRootImportEntryPointSitsWithTheRootCA(t *testing.T) {
	session := managerSession()
	html := render(t, CertificateAuthorities(session, nil, false, "Google Cloud KMS", true, true))
	for _, want := range []string{"/certificate-authorities/import?type=root", "/certificate-authorities/import?type=issuing"} {
		if !strings.Contains(html, want) {
			t.Errorf("page missing %s", want)
		}
	}
	// A root already exists, so there is nothing to import one into: only the
	// issuing entry point is offered.
	withRoot := render(t, CertificateAuthorities(session, []CA{{ID: "r-1", Name: "Acme Root", Type: "root", Status: "active"}}, true, "Google Cloud KMS", true, true))
	if strings.Contains(withRoot, "?type=root") {
		t.Error("root import offered to an organization that already has a root CA")
	}
}

func TestCertificateAuthoritiesHideImportWhenProviderDoesNotSupportIt(t *testing.T) {
	html := render(t, CertificateAuthorities(managerSession(), nil, false, "Azure Key Vault", false, true))
	for _, forbidden := range []string{"/certificate-authorities/import", "Import issuing CA", "Import existing root CA"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("page exposes unavailable import action %q", forbidden)
		}
	}
	if !strings.Contains(html, "Configure Root CA") {
		t.Error("page does not offer creation as the supported root CA path")
	}
}

// The wizard's type choice states what cannot be chosen and why, and offers no
// input for it — the dropdown it replaced offered "Root CA" to everyone and
// turned them away on submit.
func TestImportWizardOffersRootOnlyWhenItCanBeChosen(t *testing.T) {
	session := managerSession()
	html := render(t, CAImportWizard(session, nil, "Google Cloud KMS", "root", false, true))
	if !strings.Contains(html, `value="root" checked`) {
		t.Error("arriving for a root import should open on the root option")
	}

	html = render(t, CAImportWizard(session, nil, "Google Cloud KMS", "root", true, true))
	if strings.Contains(html, `value="root"`) {
		t.Error("a second root CA must not be submittable")
	}
	if !strings.Contains(html, "already has a root CA") {
		t.Error("the reason should be the existing root")
	}
}
