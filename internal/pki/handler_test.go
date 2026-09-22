package pki

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/middleware"
	pkiview "github.com/jacksongrow0/SimpleSCEP/view/pki"
)

func newTestHandler() (Handler, *memStore) {
	store := newMemStore()
	return NewHandlerWithRepository(store, NewFakeProvider()), store
}

func doForm(h Handler, session auth.Session, path string, form url.Values, htmx bool) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	req = req.WithContext(auth.WithSession(req.Context(), session))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func rootForm(name string) url.Values {
	return url.Values{
		"type":       {"root"},
		"name":       {name},
		"cn":         {name + " CA"},
		"years":      {"10"},
		"algorithm":  {AlgorithmECDSAP256SHA256},
		"protection": {ProtectionSoftware},
		"eku":        {EKUClientAuth},
	}
}

func TestCreateRootRequiresAdmin(t *testing.T) {
	h, store := newTestHandler()
	manager := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "certificate_manager"}
	if rec := doForm(h, manager, "/certificate-authorities", rootForm("Manager Root"), false); rec.Code != http.StatusForbidden {
		t.Fatalf("manager root create status = %d, want 403", rec.Code)
	}
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	if rec := doForm(h, admin, "/certificate-authorities", rootForm("Admin Root"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("admin root create status = %d, want 303 (body %q)", rec.Code, rec.Body.String())
	}
	if _, err := store.RootCA(context.Background(), testOrg); err != nil {
		t.Fatalf("root CA not created: %v", err)
	}
}

func TestCreateHTMXResponses(t *testing.T) {
	h, _ := newTestHandler()
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	rec := doForm(h, admin, "/certificate-authorities", rootForm("HX Root"), true)
	if rec.Code != http.StatusOK || rec.Header().Get("HX-Redirect") != "/certificate-authorities" {
		t.Fatalf("htmx create: status=%d HX-Redirect=%q", rec.Code, rec.Header().Get("HX-Redirect"))
	}
	// A duplicate root fails validation; htmx gets the message as a 200
	// partial for the dialog's result target instead of a dropped 400.
	rec = doForm(h, admin, "/certificate-authorities", rootForm("HX Root"), true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "root CA already exists") {
		t.Fatalf("htmx create error: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestStatusRetiredIsTerminal(t *testing.T) {
	h, store := newTestHandler()
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	if rec := doForm(h, admin, "/certificate-authorities", rootForm("Status Root"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("seed root failed: %d", rec.Code)
	}
	root, err := store.RootCA(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	if rec := doForm(h, admin, "/certificate-authorities/"+root.ID+"/status", url.Values{"status": {"retired"}}, false); rec.Code != http.StatusSeeOther {
		t.Fatalf("retire status = %d", rec.Code)
	}
	rec := doForm(h, admin, "/certificate-authorities/"+root.ID+"/status", url.Values{"status": {"active"}}, false)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "retired") {
		t.Fatalf("resurrect attempt: status=%d body=%q, want 400", rec.Code, rec.Body.String())
	}
}

func TestDownloadCA(t *testing.T) {
	h, store := newTestHandler()
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	if rec := doForm(h, admin, "/certificate-authorities", rootForm("Download Root"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("seed root failed: %d", rec.Code)
	}
	root, err := store.RootCA(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	get := func(session auth.Session) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/certificate-authorities/"+root.ID+"/download", nil)
		req = req.WithContext(auth.WithSession(req.Context(), session))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	rec := get(admin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("download: status=%d body=%q", rec.Code, rec.Body.String()[:min(80, rec.Body.Len())])
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "download-root-chain.pem") {
		t.Errorf("Content-Disposition = %q", got)
	}
	otherOrg := auth.Session{UserID: "user-9", OrgID: "org-2", Role: "auditor"}
	if rec := get(otherOrg); rec.Code != http.StatusNotFound {
		t.Errorf("cross-org download status = %d, want 404", rec.Code)
	}
}

// TestDownloadCAFormats covers the crt and cer alternatives to the default
// PEM download: crt is the same PEM text under a different extension, cer is
// binary DER of the CA certificate alone, since DER cannot hold a chain.
func TestDownloadCAFormats(t *testing.T) {
	h, store := newTestHandler()
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	if rec := doForm(h, admin, "/certificate-authorities", rootForm("Format Root"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("seed root failed: %d", rec.Code)
	}
	root, err := store.RootCA(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	get := func(format string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/certificate-authorities/"+root.ID+"/download?format="+format, nil)
		req = req.WithContext(auth.WithSession(req.Context(), admin))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	crt := get("crt")
	if crt.Code != http.StatusOK || !strings.Contains(crt.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("crt download: status=%d body=%q", crt.Code, crt.Body.String())
	}
	if got := crt.Header().Get("Content-Disposition"); !strings.Contains(got, "format-root-chain.crt") {
		t.Errorf("crt Content-Disposition = %q", got)
	}

	cer := get("cer")
	if cer.Code != http.StatusOK {
		t.Fatalf("cer download: status=%d body=%q", cer.Code, cer.Body.String())
	}
	if got := cer.Header().Get("Content-Type"); got != "application/pkix-cert" {
		t.Errorf("cer Content-Type = %q", got)
	}
	if got := cer.Header().Get("Content-Disposition"); !strings.Contains(got, "format-root.cer") || strings.Contains(got, "chain") {
		t.Errorf("cer Content-Disposition = %q, want a bare filename with no chain suffix", got)
	}
	if _, err := x509.ParseCertificate(cer.Body.Bytes()); err != nil {
		t.Errorf("cer body did not parse as DER: %v", err)
	}

	if rec := get("bogus"); rec.Code != http.StatusBadRequest {
		t.Errorf("unsupported format status = %d, want 400", rec.Code)
	}
}

func TestDownloadCAAttestationInLocalMode(t *testing.T) {
	h, store := newTestHandler()
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	if rec := doForm(h, admin, "/certificate-authorities", rootForm("Attested Root"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("seed root failed: %d", rec.Code)
	}
	root, err := store.RootCA(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	get := func(session auth.Session) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/certificate-authorities/"+root.ID+"/attestation", nil)
		req = req.WithContext(auth.WithSession(req.Context(), session))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	rec := get(admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("attestation download status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/zip" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "attested-root-attestation.zip") {
		t.Errorf("Content-Disposition = %q", got)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("read attestation zip: %v", err)
	}
	contents := make(map[string]string, len(zr.File))
	for _, file := range zr.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		if _, err := body.ReadFrom(reader); err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		contents[file.Name] = body.String()
	}
	if !strings.Contains(contents["attestation.dat"], "not a cryptographic attestation") {
		t.Errorf("example attestation = %q", contents["attestation.dat"])
	}
	if metadata := contents["metadata.json"]; !strings.Contains(metadata, `"example": true`) ||
		!strings.Contains(metadata, `"format": "EXAMPLE_NOT_HSM_ATTESTATION"`) {
		t.Errorf("metadata = %q", metadata)
	}

	otherOrg := auth.Session{UserID: "user-9", OrgID: "org-2", Role: "auditor"}
	if rec := get(otherOrg); rec.Code != http.StatusNotFound {
		t.Errorf("cross-org attestation download status = %d, want 404", rec.Code)
	}
}

func importRequest(t *testing.T, session *auth.Session) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	NewHandlerWithRepository(Repository{}, NewFakeProvider()).RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/certificate-authorities/import", nil)
	if session != nil {
		req = req.WithContext(auth.WithSession(req.Context(), *session))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestIssuingCAFormLimitedToRootEKUs renders the CA page and checks the
// issuing-CA dialog only offers the root's EKU profile (including its custom
// OID) with no free-text OID input, while the root dialog keeps the full set.
func TestIssuingCAFormLimitedToRootEKUs(t *testing.T) {
	session := auth.Session{Role: "administrator"}
	cas := []pkiview.CA{{
		ID:           "root-1",
		Name:         "Test Root",
		Type:         "root",
		Status:       "active",
		IssuanceEKUs: "server_auth,1.2.840.113635.100.4.10",
	}, {
		ID:           "issuing-1",
		Name:         "Test Issuing",
		Type:         "issuing",
		Status:       "active",
		IssuanceEKUs: "server_auth",
	}}
	var buf bytes.Buffer
	if err := pkiview.CertificateAuthorities(session, cas, true, "Google Cloud KMS · Per-CA software or HSM", true, true).Render(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if got := strings.Count(html, `/attestation`); got != len(cas) {
		t.Errorf("attestation download links = %d, want one for each of %d CAs", got, len(cas))
	}
	issuingStart := strings.Index(html, `id="ca-dialog"`)
	rootStart := strings.Index(html, `id="root-dialog"`)
	if issuingStart < 0 || rootStart < 0 || rootStart < issuingStart {
		t.Fatalf("dialog markers not found in expected order (issuing=%d root=%d)", issuingStart, rootStart)
	}
	issuing, root := html[issuingStart:rootStart], html[rootStart:]

	for _, want := range []string{`value="server_auth"`, `value="1.2.840.113635.100.4.10"`} {
		if !strings.Contains(issuing, want) {
			t.Errorf("issuing form missing %s", want)
		}
	}
	for _, reject := range []string{`value="code_signing"`, `value="client_auth"`, `name="custom_eku"`} {
		if strings.Contains(issuing, reject) {
			t.Errorf("issuing form must not offer %s", reject)
		}
	}
	for _, want := range []string{`value="client_auth"`, `value="code_signing"`, `name="custom_eku"`} {
		if !strings.Contains(root, want) {
			t.Errorf("root form missing %s", want)
		}
	}
}

func doGet(h Handler, session *auth.Session, path string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if session != nil {
		req = req.WithContext(auth.WithSession(req.Context(), *session))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// seedIssuing creates a root (client+server auth) and an issuing CA through
// the real form handlers and returns the issuing CA.
func seedIssuing(t *testing.T, h Handler, store *memStore) CertificateAuthority {
	t.Helper()
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	form := rootForm("Seed Root")
	form["eku"] = []string{EKUClientAuth, EKUServerAuth}
	if rec := doForm(h, admin, "/certificate-authorities", form, false); rec.Code != http.StatusSeeOther {
		t.Fatalf("seed root failed: %d %s", rec.Code, rec.Body.String())
	}
	root, err := store.RootCA(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	rec := doForm(h, admin, "/certificate-authorities", url.Values{
		"type":       {"issuing"},
		"name":       {"Seed Issuing"},
		"cn":         {"Seed Issuing CA"},
		"years":      {"5"},
		"algorithm":  {AlgorithmECDSAP256SHA256},
		"protection": {ProtectionSoftware},
		"parent_id":  {root.ID},
		"eku":        {EKUClientAuth, EKUServerAuth},
	}, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("seed issuing failed: %d %s", rec.Code, rec.Body.String())
	}
	cas, err := store.CAs(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	for _, ca := range cas {
		if ca.Type == CATypeIssuing {
			return ca
		}
	}
	t.Fatal("issuing CA not found")
	return CertificateAuthority{}
}

func TestCertificateRouteGating(t *testing.T) {
	h, _ := newTestHandler()
	if rec := doGet(h, nil, "/certificates"); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated page status = %d, want 401", rec.Code)
	}
	auditor := auth.Session{UserID: "user-2", OrgID: testOrg, Role: "auditor"}
	if rec := doForm(h, auditor, "/certificates/issue", url.Values{}, false); rec.Code != http.StatusForbidden {
		t.Errorf("auditor issue status = %d, want 403", rec.Code)
	}
}

func TestIssueGeneratedEndToEnd(t *testing.T) {
	h, store := newTestHandler()
	issuing := seedIssuing(t, h, store)
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	rec := doForm(h, admin, "/certificates/issue", url.Values{
		"profile":   {"server"},
		"ca_id":     {issuing.ID},
		"cn":        {"vpn.example.com"},
		"san_dns":   {"vpn.example.com, api.example.com"},
		"san_ip":    {"10.0.0.12"},
		"days":      {"90"},
		"algorithm": {LeafECP256},
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("issue status = %d body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"BEGIN PRIVATE KEY", "BEGIN CERTIFICATE", "data:application/x-pem-file", "shown only this once"} {
		if !strings.Contains(body, want) {
			t.Errorf("issue response missing %q", want)
		}
	}
	// The stored certificate row never contains the private key.
	var certID string
	for id, cert := range store.certs {
		certID = id
		if strings.Contains(cert.CertificatePEM+cert.ChainPEM, "PRIVATE KEY") {
			t.Error("private key material leaked into the stored certificate")
		}
		if cert.Profile != CertProfileServer {
			t.Errorf("stored profile = %q, want server", cert.Profile)
		}
	}
	// The page now lists the certificate and counts it.
	page := doGet(h, &admin, "/certificates")
	if page.Code != http.StatusOK {
		t.Fatalf("page status = %d", page.Code)
	}
	for _, want := range []string{"vpn.example.com", "1 certificate identity in use."} {
		if !strings.Contains(page.Body.String(), want) {
			t.Errorf("certificates page missing %q", want)
		}
	}
	// Download serves public material only, org-scoped.
	dl := doGet(h, &admin, "/certificates/"+certID+"/download")
	if dl.Code != http.StatusOK || !strings.Contains(dl.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(dl.Body.String(), "PRIVATE KEY") {
		t.Fatalf("download: status=%d", dl.Code)
	}
	if got := dl.Header().Get("Content-Disposition"); !strings.Contains(got, "vpn-example-com.pem") {
		t.Errorf("Content-Disposition = %q", got)
	}
	otherOrg := auth.Session{UserID: "user-9", OrgID: "org-2", Role: "administrator"}
	if rec := doGet(h, &otherOrg, "/certificates/"+certID+"/download"); rec.Code != http.StatusNotFound {
		t.Errorf("cross-org download status = %d, want 404", rec.Code)
	}
	// Revoke: cross-org 404s, own org redirects, double revoke 404s.
	if rec := doForm(h, otherOrg, "/certificates/"+certID+"/revoke", url.Values{"reason": {"superseded"}}, false); rec.Code != http.StatusNotFound {
		t.Errorf("cross-org revoke status = %d, want 404", rec.Code)
	}
	if rec := doForm(h, admin, "/certificates/"+certID+"/revoke", url.Values{"reason": {"superseded"}}, false); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke status = %d body=%q", rec.Code, rec.Body.String())
	}
	if rec := doForm(h, admin, "/certificates/"+certID+"/revoke", url.Values{"reason": {"superseded"}}, false); rec.Code != http.StatusNotFound {
		t.Errorf("double revoke status = %d, want 404", rec.Code)
	}
}

func TestSignCSREndToEnd(t *testing.T) {
	h, store := newTestHandler()
	issuing := seedIssuing(t, h, store)
	admin := auth.Session{UserID: "user-1", OrgID: testOrg, Role: "administrator"}
	rec := doForm(h, admin, "/certificates/csr", url.Values{
		"ca_id": {issuing.ID},
		"csr":   {testCSR(t)},
		"days":  {"30"},
		"eku":   {EKUServerAuth},
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("csr status = %d body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "BEGIN CERTIFICATE") || strings.Contains(body, "PRIVATE KEY") {
		t.Errorf("csr response should carry the certificate and never a private key")
	}
	// An EKU outside the CA profile comes back as an htmx form error.
	rec = doForm(h, admin, "/certificates/csr", url.Values{
		"ca_id": {issuing.ID},
		"csr":   {testCSR(t)},
		"eku":   {EKUTimeStamping},
	}, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not permitted by this issuing CA") {
		t.Fatalf("out-of-profile csr: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

// TestCertificatesPageDisablesUnsupportedFlows renders the page with a
// client_auth-only CA: the server flow must be a disabled tooltip button while
// the client dialog renders, and the usage copy shows real numbers.
func TestCertificatesPageDisablesUnsupportedFlows(t *testing.T) {
	session := auth.Session{Role: "administrator"}
	clientCA := pkiview.IssuerOption{ID: "ca-1", Name: "Client Issuing", EKUs: []string{"client_auth"}}
	data := pkiview.CertificatesData{
		ClientCAs: []pkiview.IssuerOption{clientCA},
		CSRCAs:    []pkiview.IssuerOption{clientCA},
	}
	var buf bytes.Buffer
	if err := pkiview.Certificates(session, data).Render(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if !strings.Contains(html, "No active issuing CA allows server certificates") {
		t.Error("missing disabled-server tooltip")
	}
	if strings.Contains(html, `id="issue-server-dialog"`) {
		t.Error("server dialog must not render without a capable CA")
	}
	if !strings.Contains(html, `id="issue-client-dialog"`) || !strings.Contains(html, `id="csr-dialog"`) {
		t.Error("client and CSR dialogs should render")
	}
	if !strings.Contains(html, "0 certificate identities in use.") {
		t.Error("missing usage copy")
	}
	// The client dialog's EKU group only offers the CA's profile, with the
	// required usage locked in.
	if !strings.Contains(html, "Client auth <span") {
		t.Error("client dialog should mark client_auth as always included")
	}
}

func TestCertPageDataOmitsInfrastructureCertificates(t *testing.T) {
	data := certPageData(auth.Session{}, nil, []Certificate{
		{ID: "ca", Profile: CertProfileInfrastructure},
		{ID: "leaf", Profile: CertProfileClient},
	}, 1)
	if len(data.Rows) != 1 || data.Rows[0].ID != "leaf" {
		t.Fatalf("certificate rows = %#v, want only the end-entity certificate", data.Rows)
	}
}

func TestImportRouteGating(t *testing.T) {
	tests := []struct {
		name    string
		session *auth.Session
		want    int
	}{
		{"unauthenticated", nil, http.StatusUnauthorized},
		{"auditor role forbidden", &auth.Session{Role: "auditor"}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := importRequest(t, tt.session)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// A root import can be opened by any certificate manager. Reaching the page
// works regardless of what is imported; the issuing import fails on the
// certificate that was not sent, which is the next check.
func TestRootImportReachableByManager(t *testing.T) {
	h, _ := newTestHandler()
	manager := auth.Session{UserID: "u-1", OrgID: "org-1", Role: "certificate_manager"}
	rec := doForm(h, manager, "/certificate-authorities/import", url.Values{"type": {"issuing"}, "name": {"Acme Issuer"}}, false)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d: %q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestRootImportWrappedKeyReachableByManager(t *testing.T) {
	h, store := newTestHandler()
	id, err := store.CreateCAImportJob(context.Background(), CAImportJob{
		OrganizationID: "org-1", CAName: "Acme Root", CAType: CATypeRoot,
		Algorithm: "EC_SIGN_P256_SHA256", State: ImportStateReadyToWrap,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := auth.Session{UserID: "u-1", OrgID: "org-1", Role: "certificate_manager"}
	rec := doForm(h, manager, "/certificate-authorities/import/"+id+"/cancel", url.Values{}, false)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d: %q", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
}

// TestPublicPKIRoutesAreRateLimited covers the one unauthenticated surface that
// can reach a KMS signing operation.
//
// SCEP, ACME and EST each limit their own endpoint; the CRL, issuer and OCSP
// distribution points had no budget at all, and their URLs are printed into
// every certificate this service issues, so the caller set is "the internet".
func TestPublicPKIRoutesAreRateLimited(t *testing.T) {
	h := Handler{limiter: middleware.NewRateLimiter(2)}
	const orgID = "11111111-1111-1111-1111-111111111111"
	const caID = "22222222-2222-2222-2222-222222222222"

	call := func() error {
		r := httptest.NewRequest("GET", "/pki/"+orgID+"/"+caID+"/crl", nil)
		r.SetPathValue("orgID", orgID)
		r.SetPathValue("caID", caID)
		return h.publicContext(r, func(context.Context) error { return nil })
	}
	for i := range 2 {
		if err := call(); err != nil {
			t.Fatalf("request %d within budget was refused: %v", i+1, err)
		}
	}
	if err := call(); !errors.Is(err, errTooManyRequests) {
		t.Errorf("the request over budget was admitted: %v", err)
	}
}

// TestPublicPKIBudgetIsPerCA keeps one CA's burst from spending another's, which
// would make a single noisy fleet a cross-tenant outage — the CRL for every other
// customer would start answering "try later".
func TestPublicPKIBudgetIsPerCA(t *testing.T) {
	h := Handler{limiter: middleware.NewRateLimiter(1)}
	const orgID = "11111111-1111-1111-1111-111111111111"

	call := func(caID string) error {
		r := httptest.NewRequest("GET", "/pki/"+orgID+"/"+caID+"/crl", nil)
		r.SetPathValue("orgID", orgID)
		r.SetPathValue("caID", caID)
		return h.publicContext(r, func(context.Context) error { return nil })
	}
	first := "22222222-2222-2222-2222-222222222222"
	second := "33333333-3333-3333-3333-333333333333"
	if err := call(first); err != nil {
		t.Fatalf("the first CA's only request was refused: %v", err)
	}
	if err := call(first); !errors.Is(err, errTooManyRequests) {
		t.Fatalf("the first CA exceeded its budget without being refused: %v", err)
	}
	if err := call(second); err != nil {
		t.Errorf("a second CA was refused because the first had spent its budget: %v", err)
	}
}
