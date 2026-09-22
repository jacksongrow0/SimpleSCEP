package pki

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	"github.com/jacksongrow0/SimpleSCEP/internal/middleware"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
	"github.com/jacksongrow0/SimpleSCEP/internal/web"
	pkiview "github.com/jacksongrow0/SimpleSCEP/view/pki"
)

type Handler struct {
	repo    Store
	service Service
	db      *sql.DB
	// limiter guards the public distribution points only. It is generous
	// because a legitimate caller is a whole device fleet behind one corporate
	// NAT, all checking revocation, and refusing them is worse than the abuse
	// this bounds: a relying party set to hard-fail treats "no answer" as
	// "revoked". The cost it exists to cap is the KMS signature behind a CRL or
	// an uncached OCSP response, and crlRetryCooldown is what actually caps that;
	// this is the backstop under it.
	limiter *middleware.RateLimiter
}

// publicPKIBudget is requests per minute per CA per client address for the CRL,
// issuer and OCSP endpoints.
const publicPKIBudget = 600

func NewHandlerWithURL(db *sql.DB, provider KeyProvider, publicURL string) Handler {
	repo := NewRepository(db)
	return Handler{repo: repo, service: NewServiceWithURL(repo, provider, publicURL), db: db,
		limiter: middleware.NewRateLimiter(publicPKIBudget)}
}

func NewHandlerWithRepository(repo Store, provider KeyProvider) Handler {
	return Handler{repo: repo, service: NewService(repo, provider),
		limiter: middleware.NewRateLimiter(publicPKIBudget)}
}

func (h Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /certificate-authorities", h.index)
	mux.HandleFunc("POST /certificate-authorities", h.create)
	mux.HandleFunc("GET /certificate-authorities/import", h.importIndex)
	mux.HandleFunc("POST /certificate-authorities/import", h.startImport)
	// The explicit /status suffix keeps this from clashing with
	// /certificate-authorities/{id}/download in ServeMux pattern matching.
	mux.HandleFunc("GET /certificate-authorities/import/{id}/status", h.importStatus)
	mux.HandleFunc("POST /certificate-authorities/import/{id}/wrapped-key", h.submitWrappedKey)
	mux.HandleFunc("POST /certificate-authorities/import/{id}/cancel", h.cancelImport)
	mux.HandleFunc("POST /certificate-authorities/{id}/status", h.status)
	mux.HandleFunc("POST /certificate-authorities/{id}/rotate", h.rotate)
	mux.HandleFunc("POST /certificate-authorities/{id}/delete", h.delete)
	mux.HandleFunc("GET /certificate-authorities/{id}/download", h.download)
	mux.HandleFunc("GET /certificate-authorities/{id}/attestation", h.downloadAttestation)
	mux.HandleFunc("GET /certificates", h.certificates)
	mux.HandleFunc("POST /certificates/issue", h.issueGenerated)
	mux.HandleFunc("POST /certificates/csr", h.signCSR)
	mux.HandleFunc("POST /certificates/{id}/revoke", h.revokeCertificate)
	mux.HandleFunc("GET /certificates/{id}/download", h.downloadCertificate)
	mux.HandleFunc("GET /revocation", h.revocationPage)
	mux.HandleFunc("POST /revocation/publish", h.publishCRLs)
	mux.HandleFunc("GET /pki/{orgID}/{caID}/issuer", h.publicIssuer)
	mux.HandleFunc("GET /pki/{orgID}/{caID}/crl", h.publicCRL)
	mux.HandleFunc("POST /pki/{orgID}/{caID}/ocsp", h.publicOCSP)
	mux.HandleFunc("GET /pki/{orgID}/{caID}/ocsp/{request...}", h.publicOCSP)
}

func (h Handler) index(w http.ResponseWriter, r *http.Request) {
	session, ok := authenticated(w, r)
	if !ok {
		return
	}
	cas, err := h.repo.CAs(r.Context(), session.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "The certificate authorities could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	pkiview.CertificateAuthorities(session, caViews(cas), hasRoot(cas), KeyProviderSummary(), h.service.provider.SupportsCAImport(), h.service.provider.SupportsHSM()).Render(r.Context(), w)
}

func subjectInput(r *http.Request) SubjectInput {
	return SubjectInput{
		CommonName:         strings.TrimSpace(r.FormValue("cn")),
		Organization:       strings.TrimSpace(r.FormValue("o")),
		OrganizationalUnit: strings.TrimSpace(r.FormValue("ou")),
		Country:            strings.ToUpper(strings.TrimSpace(r.FormValue("c"))),
		Province:           strings.TrimSpace(r.FormValue("st")),
		Locality:           strings.TrimSpace(r.FormValue("l")),
	}
}

// validityDaysFromYears converts the years form field to days; 0 lets the
// service apply its per-type default.
func validityDaysFromYears(raw string) int {
	years, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || years <= 0 {
		return 0
	}
	return years * 365
}

// ekuInput merges the EKU checkbox group with the comma-separated custom OID
// field; validation happens in the service.
func ekuInput(r *http.Request) []string {
	ekus := append([]string{}, r.Form["eku"]...)
	for t := range strings.SplitSeq(r.FormValue("custom_eku"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			ekus = append(ekus, t)
		}
	}
	return ekus
}

// pathLenValue parses the path_len form field; nil means "not provided"
// and lets the service apply its default.
func pathLenValue(raw string) *int {
	if raw == "" {
		return nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return nil
	}
	return &n
}

// caViews maps CAs to what the page is allowed to know about them.
//
// KMSKeyVersion is not copied across, and pkiview.CA has no field for it. The
// stored value is a full provider key ID, which describes deployment
// infrastructure rather than the certificate authority. It is unactionable in
// the console and tells anyone reading over an operator's shoulder where the
// keys live.
//
// It also answered nothing. The version is "1" for every CA that will ever
// exist here: both providers create a key with one version, and rotating a CA
// mints a new CA on a new key rather than a second version of this one.
//
// What a customer actually wants to know about the key — is it in an HSM, can
// it be exported — is ExportPosture, which travels below, and the attestation
// bundle behind the download button.
func caViews(cas []CertificateAuthority) []pkiview.CA {
	views := make([]pkiview.CA, 0, len(cas))
	for _, ca := range cas {
		view := pkiview.CA{
			ID:            ca.ID,
			Name:          ca.Name,
			Type:          ca.Type,
			Status:        ca.Status,
			Algorithm:     ca.Algorithm,
			Subject:       ca.Subject,
			NotBefore:     ca.NotBefore.Format("2006-01-02"),
			NotAfter:      ca.NotAfter.Format("2006-01-02"),
			ExportPosture: ca.ExportPosture,
			IssuanceEKUs:  ca.IssuanceEKUs,
			IssuedCount:   ca.IssuedCount,
		}
		// Serial and issuer live only in the certificate itself, not in a
		// column of their own — reparse rather than duplicate storage. Best
		// effort: a parse failure just leaves the dialog fields blank instead
		// of failing the whole page.
		if cert, err := parseCertificate(ca.CertificatePEM); err == nil {
			view.Serial = cert.SerialNumber.Text(16)
			view.Issuer = cert.Issuer.String()
		}
		views = append(views, view)
	}
	return views
}

func hasRoot(cas []CertificateAuthority) bool {
	for _, ca := range cas {
		if ca.Type == CATypeRoot {
			return true
		}
	}
	return false
}

func (h Handler) create(w http.ResponseWriter, r *http.Request) {
	session, ok := manager(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That form could not be read. Reload the page and try again.")
		return
	}
	caType := strings.TrimSpace(r.FormValue("type"))
	// Creating the org's trust anchor is an admin decision, same as the
	// onboarding path; managers may only create issuing CAs.
	if caType == CATypeRoot && !session.IsAdmin() {
		toast.Fail(w, r, http.StatusForbidden, "Only administrators can create a root certificate authority.")
		return
	}
	ca, err := h.service.CreateCA(r.Context(), CreateCARequest{
		OrgID:      session.OrgID,
		UserID:     session.UserID,
		Name:       strings.TrimSpace(r.FormValue("name")),
		Type:       caType,
		ParentID:   strings.TrimSpace(r.FormValue("parent_id")),
		Subject:    subjectInput(r),
		Days:       validityDaysFromYears(r.FormValue("years")),
		Algorithm:  r.FormValue("algorithm"),
		Protection: r.FormValue("protection"),
		EKUs:       ekuInput(r),
		MaxPathLen: pathLenValue(r.FormValue("path_len")),
	})
	if err != nil {
		formError(w, r, err)
		return
	}
	web.Done(w, r, "/certificate-authorities", "Certificate authority “"+ca.Name+"” created")
}

// formError reports a validation failure. htmx 2 ignores non-2xx swaps, so
// htmx requests get the message rendered into their result target with a 200;
// plain form posts get a regular 400.
func formError(w http.ResponseWriter, r *http.Request, err error) {
	if r.Header.Get("HX-Request") == "true" {
		pkiview.FormError(err.Error()).Render(r.Context(), w)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// byoca gates every Bring-Your-Own-CA route to the certificate manager role.
func (h Handler) byoca(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	return manager(w, r)
}

func (h Handler) importIndex(w http.ResponseWriter, r *http.Request) {
	if !h.importSupported(w, r) {
		return
	}
	session, ok := h.byoca(w, r)
	if !ok {
		return
	}
	jobs, err := h.repo.CAImportJobs(r.Context(), session.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "The import jobs could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	// An organization gets one root CA, so an existing one closes the root
	// import. The wizard states that constraint on the choice rather than waiting
	// for submission.
	_, rootErr := h.repo.RootCA(r.Context(), session.OrgID)
	pkiview.CAImportWizard(session, importJobViews(jobs), KeyProviderSummary(),
		strings.TrimSpace(r.URL.Query().Get("type")), rootErr == nil, h.service.provider.SupportsHSM()).Render(r.Context(), w)
}

func (h Handler) startImport(w http.ResponseWriter, r *http.Request) {
	if !h.importSupported(w, r) {
		return
	}
	session, ok := h.byoca(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseForm(); err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That form could not be read. Reload the page and try again.")
		return
	}
	caType := strings.TrimSpace(r.FormValue("type"))
	job, err := h.service.StartCAImport(r.Context(), StartCAImportRequest{
		OrgID:          session.OrgID,
		UserID:         session.UserID,
		Name:           strings.TrimSpace(r.FormValue("name")),
		Type:           caType,
		CertificatePEM: r.FormValue("certificate"),
		ChainPEM:       r.FormValue("chain"),
		Protection:     r.FormValue("protection"),
	})
	if err != nil {
		web.Fail(w, r, http.StatusBadRequest, err.Error())
		return
	}
	web.Done(w, r, "/certificate-authorities/import",
		"Import started for “"+job.CAName+"”. Wrap the key with the printed instructions, then paste it below.")
}

func (h Handler) importStatus(w http.ResponseWriter, r *http.Request) {
	if !h.importSupported(w, r) {
		return
	}
	session, ok := h.byoca(w, r)
	if !ok {
		return
	}
	job, err := h.service.SyncCAImport(r.Context(), session.OrgID, session.UserID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			web.Fail(w, r, http.StatusNotFound, "That import job no longer exists")
			return
		}
		web.Page(w, r, http.StatusInternalServerError, "That import could not be read",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	pkiview.ImportJobStatus(importJobView(job)).Render(r.Context(), w)
}

func (h Handler) submitWrappedKey(w http.ResponseWriter, r *http.Request) {
	if !h.importSupported(w, r) {
		return
	}
	session, ok := h.byoca(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseForm(); err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That form could not be read. Reload the page and try again.")
		return
	}
	job, err := h.service.SubmitWrappedKey(r.Context(), session.OrgID, session.UserID, r.PathValue("id"), r.FormValue("wrapped_key"))
	if err != nil {
		web.Fail(w, r, http.StatusBadRequest, err.Error())
		return
	}
	pkiview.ImportJobStatus(importJobView(job)).Render(r.Context(), w)
}

func (h Handler) cancelImport(w http.ResponseWriter, r *http.Request) {
	if !h.importSupported(w, r) {
		return
	}
	session, ok := h.byoca(w, r)
	if !ok {
		return
	}
	if err := h.service.CancelCAImport(r.Context(), session.OrgID, session.UserID, r.PathValue("id")); err != nil {
		web.Fail(w, r, http.StatusBadRequest, err.Error())
		return
	}
	web.Done(w, r, "/certificate-authorities/import", "Import cancelled")
}

func (h Handler) importSupported(w http.ResponseWriter, r *http.Request) bool {
	if h.service.provider.SupportsCAImport() {
		return true
	}
	web.Page(w, r, http.StatusNotFound, "CA import is unavailable",
		"This key provider does not support SimpleSCEP's wrapped-key import workflow.")
	return false
}

func importJobViews(jobs []CAImportJob) []pkiview.ImportJob {
	views := make([]pkiview.ImportJob, 0, len(jobs))
	for _, job := range jobs {
		views = append(views, importJobView(job))
	}
	return views
}

func importJobView(job CAImportJob) pkiview.ImportJob {
	view := pkiview.ImportJob{
		ID:                job.ID,
		Name:              job.CAName,
		Type:              job.CAType,
		State:             job.State,
		Algorithm:         job.Algorithm,
		WrappingMethod:    job.WrappingMethod,
		WrappingPublicKey: job.WrappingPublicKeyPEM,
		FailureReason:     job.FailureReason,
		CreatedAt:         job.CreatedAt.Format("2006-01-02 15:04"),
	}
	if job.ExpiresAt != nil {
		view.ExpiresAt = job.ExpiresAt.UTC().Format("2006-01-02 15:04 MST")
	}
	return view
}

func (h Handler) status(w http.ResponseWriter, r *http.Request) {
	session, ok := manager(w, r)
	if !ok {
		return
	}
	status := r.FormValue("status")
	if status != CAStatusActive && status != CAStatusInactive && status != CAStatusRetired {
		web.Fail(w, r, http.StatusBadRequest, "That is not a status a certificate authority can be in")
		return
	}
	ca, err := h.repo.CA(r.Context(), session.OrgID, r.PathValue("id"))
	if err != nil {
		toast.Fail(w, r, http.StatusNotFound, "That certificate authority is no longer there. Reload the page.")
		return
	}
	// Retirement is terminal; otherwise the active issuer count could be
	// dodged by retiring a CA and resurrecting it later.
	if ca.Status == CAStatusRetired {
		web.Fail(w, r, http.StatusBadRequest, "A retired certificate authority cannot change status")
		return
	}
	if status != CAStatusActive {
		scepCount, err := h.repo.EnabledSCEPEndpointCount(r.Context(), session.OrgID, ca.ID)
		if err != nil {
			toast.Fail(w, r, http.StatusInternalServerError, "That change could not be saved. Try again.")
			return
		}
		acmeCount, err := h.repo.EnabledACMEEndpointCount(r.Context(), session.OrgID, ca.ID)
		if err != nil {
			toast.Fail(w, r, http.StatusInternalServerError, "That change could not be saved. Try again.")
			return
		}
		if scepCount > 0 {
			web.Fail(w, r, http.StatusConflict,
				"Disable or rebind this CA's SCEP endpoints before changing its status")
			return
		}
		if acmeCount > 0 {
			web.Fail(w, r, http.StatusConflict,
				"Disable or rebind this CA's ACME endpoints before changing its status")
			return
		}
		estCount, err := h.repo.EnabledESTEndpointCount(r.Context(), session.OrgID, ca.ID)
		if err != nil {
			toast.Fail(w, r, http.StatusInternalServerError, "That change could not be saved. Try again.")
			return
		}
		if estCount > 0 {
			web.Fail(w, r, http.StatusConflict,
				"Disable or rebind this CA's EST endpoints before changing its status")
			return
		}
	}
	if err := h.service.SetCAStatus(r.Context(), session.OrgID, session.UserID, ca.ID, status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			toast.Fail(w, r, http.StatusNotFound, "That certificate authority is no longer there. Reload the page.")
			return
		}
		toast.Fail(w, r, http.StatusInternalServerError, "That change could not be saved. Try again.")
		return
	}
	web.Done(w, r, "/certificate-authorities", caStatusMessage(ca.Name, status))
}

func (h Handler) rotate(w http.ResponseWriter, r *http.Request) {
	session, ok := manager(w, r)
	if !ok {
		return
	}
	rotated, err := h.service.RotateIssuingCA(r.Context(), session.OrgID, session.UserID, r.PathValue("id"))
	if err != nil {
		web.Fail(w, r, http.StatusBadRequest, err.Error())
		return
	}
	web.Done(w, r, "/certificate-authorities",
		"“"+rotated.Name+"” rotated. Certificates already issued stay valid until they expire.")
}

// download serves the CA certificate plus its chain, PEM or DER depending on
// the "format" query parameter. Certificates are public material, so any
// authenticated org member may fetch them.
func (h Handler) download(w http.ResponseWriter, r *http.Request) {
	session, ok := authenticated(w, r)
	if !ok {
		return
	}
	ca, err := h.repo.CA(r.Context(), session.OrgID, r.PathValue("id"))
	if err != nil {
		toast.Fail(w, r, http.StatusNotFound, "That certificate authority is no longer there. Reload the page.")
		return
	}
	if err := WriteCertificateDownload(w, r, ca.Name, ca.CertificatePEM, ca.ChainPEM); err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That certificate format is not supported.")
		return
	}
}

// downloadAttestation serves a verification-ready bundle for an HSM key. In
// software and local modes the same endpoint returns a clearly marked example
// bundle so the UI and integrations remain exercisable without an HSM.
func (h Handler) downloadAttestation(w http.ResponseWriter, r *http.Request) {
	session, ok := authenticated(w, r)
	if !ok {
		return
	}
	ca, err := h.repo.CA(r.Context(), session.OrgID, r.PathValue("id"))
	if err != nil {
		toast.Fail(w, r, http.StatusNotFound, "That certificate authority is no longer there. Reload the page.")
		return
	}
	attestation, err := h.service.provider.Attestation(r.Context(), ca.KMSKeyVersion)
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That attestation could not be produced. Try again.")
		return
	}
	bundle, err := attestationZip(ca, attestation)
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That attestation could not be produced. Try again.")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+attestationFilename(ca.Name)+`"`)
	_, _ = w.Write(bundle)
}

// certFilename derives a safe attachment name from a leaf CN; suffix
// distinguishes the key/chain variants ("", "-key", "-chain").
func certFilename(cn, suffix string) string {
	base := pemSlug(cn)
	if base == "" {
		base = "certificate"
	}
	return base + suffix + ".pem"
}

func pemSlug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '.':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func (h Handler) delete(w http.ResponseWriter, r *http.Request) {
	session, ok := manager(w, r)
	if !ok {
		return
	}
	// Read before destroying, so the confirmation can name what is gone. The
	// route is step-up guarded and destroys a key version; one extra select is
	// cheap next to telling an administrator only that "something" was deleted.
	ca, caErr := h.repo.CA(r.Context(), session.OrgID, r.PathValue("id"))
	// The dialog disables its submit until the CA's name is typed, but a
	// disabled button is a courtesy rather than a control — the same question
	// is asked here, where a direct post cannot skip it. Checked only once the
	// CA is known to exist; a lookup miss falls straight through to the
	// "not found" branch below with the same answer either way.
	if caErr == nil && !enroll.ConfirmsEndpointName(r.FormValue("confirm_name"), ca.Name) {
		web.Fail(w, r, http.StatusBadRequest, "Type the certificate authority's name to confirm deletion")
		return
	}
	if err := h.service.DeleteCA(r.Context(), session.OrgID, session.UserID, r.PathValue("id")); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			web.Fail(w, r, http.StatusNotFound, "certificate authority not found")
			return
		}
		web.Fail(w, r, http.StatusBadRequest, err.Error())
		return
	}
	name := "Certificate authority"
	if caErr == nil {
		name = "“" + ca.Name + "”"
	}
	web.Done(w, r, "/certificate-authorities", name+" deleted and its key destroyed")
}

func (h Handler) certificates(w http.ResponseWriter, r *http.Request) {
	session, ok := authenticated(w, r)
	if !ok {
		return
	}
	cas, err := h.repo.CAs(r.Context(), session.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "The certificate authorities could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	certs, err := h.repo.Certificates(r.Context(), session.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "The certificates could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	active, err := h.repo.ActiveIdentityCount(r.Context(), session.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "The certificates could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	data := certPageData(session, cas, certs, active)
	pkiview.Certificates(session, data).Render(r.Context(), w)
}

// certPageData maps domain rows to the view model: per-flow issuer options
// (an active issuing CA is offered for a flow only when its EKU profile allows
// it) and display rows.
func certPageData(session auth.Session, cas []CertificateAuthority, certs []Certificate, active int) pkiview.CertificatesData {
	data := pkiview.CertificatesData{Identities: active}
	for _, ca := range cas {
		if ca.Type != CATypeIssuing || ca.Status != CAStatusActive {
			continue
		}
		opt := pkiview.IssuerOption{ID: ca.ID, Name: ca.Name, EKUs: splitEKUs(ca.IssuanceEKUs)}
		data.CSRCAs = append(data.CSRCAs, opt)
		if slices.Contains(opt.EKUs, EKUServerAuth) {
			data.ServerCAs = append(data.ServerCAs, opt)
		}
		if slices.Contains(opt.EKUs, EKUClientAuth) {
			data.ClientCAs = append(data.ClientCAs, opt)
		}
	}
	now := time.Now().UTC()
	for _, cert := range certs {
		if cert.Profile == CertProfileInfrastructure {
			continue
		}
		status := cert.Status
		if status == CertStatusIssued && cert.ExpiresAt.Before(now) {
			status = "expired"
		}
		data.Rows = append(data.Rows, pkiview.CertRow{
			ID:        cert.ID,
			CN:        commonNameOf(cert.Subject),
			Subject:   cert.Subject,
			CAName:    cert.CAName,
			Profile:   cert.Profile,
			Serial:    cert.Serial,
			SANs:      cert.SANs,
			EKUs:      cert.EKUs,
			Status:    status,
			IssuedAt:  cert.IssuedAt.Format("2006-01-02"),
			Expires:   cert.ExpiresAt.Format("2006-01-02"),
			Revocable: cert.Status == CertStatusIssued,
		})
	}
	return data
}

func splitEKUs(csv string) []string {
	var out []string
	for t := range strings.SplitSeq(csv, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// commonNameOf pulls the CN out of a rendered subject DN for display.
func commonNameOf(subject string) string {
	for part := range strings.SplitSeq(subject, ",") {
		if cn, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
			return cn
		}
	}
	return subject
}

// splitList splits a comma- or newline-separated form field into trimmed,
// non-empty entries.
func splitList(raw string) []string {
	var out []string
	for f := range strings.FieldsFuncSeq(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (h Handler) issueGenerated(w http.ResponseWriter, r *http.Request) {
	session, ok := manager(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseForm(); err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That form could not be read. Reload the page and try again.")
		return
	}
	days, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("days")))
	cert, keyPEM, err := h.service.IssueGenerated(r.Context(), IssueGeneratedRequest{
		OrgID:     session.OrgID,
		UserID:    session.UserID,
		CAID:      r.FormValue("ca_id"),
		Profile:   r.FormValue("profile"),
		Subject:   subjectInput(r),
		DNSNames:  splitList(r.FormValue("san_dns")),
		IPs:       splitList(r.FormValue("san_ip")),
		Emails:    splitList(r.FormValue("san_email")),
		Days:      days,
		Algorithm: r.FormValue("algorithm"),
		EKUs:      ekuInput(r),
	})
	if err != nil {
		formError(w, r, err)
		return
	}
	// The private key exists only in this one response; it is never stored.
	pkiview.GeneratedCertResult("issue-"+cert.Profile+"-dialog", commonNameOf(cert.Subject), keyPEM, cert.CertificatePEM, cert.ChainPEM).Render(r.Context(), w)
}

func (h Handler) signCSR(w http.ResponseWriter, r *http.Request) {
	session, ok := manager(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseForm(); err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That form could not be read. Reload the page and try again.")
		return
	}
	days, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("days")))
	cert, err := h.service.Issue(r.Context(), IssueRequest{
		OrgID:   session.OrgID,
		UserID:  session.UserID,
		CAID:    r.FormValue("ca_id"),
		CSRPEM:  r.FormValue("csr"),
		Days:    days,
		EKUs:    ekuInput(r),
		Purpose: "csr",
	})
	if err != nil {
		formError(w, r, err)
		return
	}
	pkiview.CSRCertResult("csr-dialog", commonNameOf(cert.Subject), cert.ID, cert.CertificatePEM, cert.ChainPEM).Render(r.Context(), w)
}

func (h Handler) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	session, ok := manager(w, r)
	if !ok {
		return
	}
	err := h.service.Revoke(r.Context(), RevokeRequest{
		OrgID:         session.OrgID,
		UserID:        session.UserID,
		CertificateID: r.PathValue("id"),
		Reason:        r.FormValue("reason"),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			web.Fail(w, r, http.StatusNotFound, "That certificate was not found, or is already revoked")
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	web.Done(w, r, "/certificates", "Certificate revoked. It will appear in the next published CRL.")
}

// downloadCertificate serves a leaf certificate plus its chain as PEM.
// Certificates are public material, so any authenticated org member may fetch
// them; the private key is never available here.
func (h Handler) downloadCertificate(w http.ResponseWriter, r *http.Request) {
	session, ok := authenticated(w, r)
	if !ok {
		return
	}
	cert, err := h.repo.Certificate(r.Context(), session.OrgID, r.PathValue("id"))
	if err != nil {
		toast.Fail(w, r, http.StatusNotFound, "That certificate is no longer there. Reload the page.")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+certFilename(commonNameOf(cert.Subject), "")+`"`)
	fmt.Fprint(w, cert.CertificatePEM+cert.ChainPEM)
}

// The gates below are where this package's refusals concentrate, and they
// answer through toast.Fail rather than http.Error.
//
// The distinction is not cosmetic. htmx does not swap a non-2xx response, so a
// bare http.Error to an hx-post produced no swap, no message and no console line:
// the button did nothing, silently, and the natural response is to press it
// again.
//
// toast.Fail keeps the real status and adds HX-Trigger, which htmx reads whatever
// the status is. A plain form post still gets the status and the text in the body,
// exactly as before.
func authenticated(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	session, ok := auth.FromContext(r.Context())
	if !ok {
		toast.Fail(w, r, http.StatusUnauthorized, "Your session has ended. Sign in again.")
		return auth.Session{}, false
	}
	return session, true
}

func manager(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	session, ok := authenticated(w, r)
	if !ok {
		return auth.Session{}, false
	}
	if !session.CanManageCertificates() {
		toast.Fail(w, r, http.StatusForbidden,
			"Only administrators and certificate managers can do that.")
		return auth.Session{}, false
	}
	return session, true
}

// caStatusMessage says what the new status means rather than naming it. "Status
// set to inactive" restates the button that was just pressed; what the
// administrator wants confirmed is whether the CA can still sign.
func caStatusMessage(name, status string) string {
	switch status {
	case CAStatusActive:
		return "“" + name + "” is active and can issue certificates"
	case CAStatusRetired:
		return "“" + name + "” is retired. This cannot be undone."
	default:
		return "“" + name + "” is inactive and will not issue new certificates"
	}
}
