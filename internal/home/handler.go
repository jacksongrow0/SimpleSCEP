package home

import (
	"database/sql"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/acme"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/est"
	"github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/jacksongrow0/SimpleSCEP/internal/scep"
	"github.com/jacksongrow0/SimpleSCEP/internal/web"
	homeview "github.com/jacksongrow0/SimpleSCEP/view/home"
)

type Handler struct {
	repo      auth.Repository
	scepRepo  scep.Repository
	acmeRepo  acme.Repository
	estRepo   est.Repository
	pkiRepo   pki.Repository
	auditRepo audit.Repository
	publicURL string
}

func RegisterRoutes(mux *http.ServeMux, db *sql.DB, publicURL string) {
	h := Handler{repo: auth.NewRepository(db),
		scepRepo: scep.NewRepository(db), acmeRepo: acme.NewRepository(db),
		estRepo: est.NewRepository(db),
		pkiRepo: pki.NewRepository(db), auditRepo: audit.NewRepository(db),
		publicURL: strings.TrimRight(publicURL, "/"),
	}
	mux.HandleFunc("GET /", h.overview)
	mux.HandleFunc("GET /protocols", h.protocols)
	// Endpoint administration lives under /protocols, not /scep, which the
	// middleware treats as unconditionally public for the device paths.
	mux.HandleFunc("GET /protocols/scep/{endpointID}", h.protocolEndpoint)
	mux.HandleFunc("GET /protocols/acme/{endpointID}", h.acmeEndpoint)
	mux.HandleFunc("GET /protocols/est/{endpointID}", h.estEndpoint)
	mux.HandleFunc("GET /users", h.users)
	mux.HandleFunc("GET /organization", h.organization)
	mux.HandleFunc("GET /audit", h.audit)
	mux.HandleFunc("GET /audit.csv", h.auditExport)
	mux.HandleFunc("GET /support", h.support)
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/organization", http.StatusSeeOther)
	})
}

func session(r *http.Request) auth.Session { s, _ := auth.FromContext(r.Context()); return s }

func (h Handler) overview(w http.ResponseWriter, r *http.Request) {
	// "GET /" is a catch-all in net/http's mux, so this handler answered every
	// path no other route claimed — and answered it with the overview dashboard
	// at 200. A typo in a URL, a stale bookmark, or a crawler probing /wp-admin
	// all came back as a perfectly successful dashboard, which makes a broken link
	// impossible to notice and a 404 impossible to report.
	if r.URL.Path != "/" {
		web.Page(w, r, http.StatusNotFound, "That page does not exist",
			"Check the address, or go back to the overview.")
		return
	}
	s := session(r)
	data, err := h.overviewData(r, s)
	if err != nil {
		log.Printf("home org=%s overview failed: %v", s.OrgID, err)
		web.Page(w, r, http.StatusInternalServerError, "The overview could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	if err := homeview.Index(s, data).Render(r.Context(), w); err != nil {
		web.Page(w, r, http.StatusInternalServerError, "That page could not be rendered",
			"Something went wrong on our side. Try again in a moment.")
	}
}

// overviewData counts what the organization actually has.
func (h Handler) overviewData(r *http.Request, s auth.Session) (homeview.OverviewData, error) {
	var data homeview.OverviewData
	cas, err := h.pkiRepo.CAs(r.Context(), s.OrgID)
	if err != nil {
		return data, err
	}
	for _, ca := range cas {
		// Retired CAs are end-of-life, matching pki.Repository.IssuingCACount.
		if ca.Type == pki.CATypeIssuing && (ca.Status == pki.CAStatusActive || ca.Status == pki.CAStatusInactive) {
			data.IssuingCAs++
		}
	}
	data.HasIssuingCA = data.IssuingCAs > 0
	if data.Identities, err = h.pkiRepo.ActiveIdentityCount(r.Context(), s.OrgID); err != nil {
		return data, err
	}
	if data.ExpiringSoon, err = h.pkiRepo.ExpiringIdentityCount(r.Context(), s.OrgID, 30); err != nil {
		return data, err
	}
	// A revoked or expired certificate no longer counts as active but the
	// organization has still issued one, so the setup step stays complete.
	certs, err := h.pkiRepo.Certificates(r.Context(), s.OrgID)
	if err != nil {
		return data, err
	}
	for _, cert := range certs {
		if cert.Profile != pki.CertProfileInfrastructure {
			data.HasCertificate = true
			break
		}
	}
	endpoints, err := h.scepRepo.EndpointSummaries(r.Context(), s.OrgID)
	if err != nil {
		return data, err
	}
	for _, e := range endpoints {
		if e.Enabled {
			data.EnabledEndpoints++
		}
	}
	if data.EnabledEndpoints > 0 {
		data.Protocols = append(data.Protocols, "SCEP")
	}
	acmeEndpoints, err := h.acmeRepo.EndpointSummaries(r.Context(), s.OrgID)
	if err != nil {
		return data, err
	}
	for _, e := range acmeEndpoints {
		if e.Enabled {
			data.EnabledEndpoints++
			// Counted once however many ACME endpoints are on, because this is a
			// list of protocols in use rather than of endpoints.
			if !slices.Contains(data.Protocols, "ACME") {
				data.Protocols = append(data.Protocols, "ACME")
			}
		}
	}
	estEndpoints, err := h.estRepo.EndpointSummaries(r.Context(), s.OrgID)
	if err != nil {
		return data, err
	}
	for _, e := range estEndpoints {
		if e.Enabled {
			data.EnabledEndpoints++
			if !slices.Contains(data.Protocols, "EST") {
				data.Protocols = append(data.Protocols, "EST")
			}
		}
	}
	data.HasProtocol = data.EnabledEndpoints > 0
	orgID, err := uuid.Parse(s.OrgID)
	if err != nil {
		return data, err
	}
	users, err := h.repo.Users(r.Context(), orgID)
	if err != nil {
		return data, err
	}
	data.HasTeam = len(users) > 1
	// Loaded last, and only for an organization that has finished setting up,
	// because that is the only case where the page has anywhere to draw it: the
	// graph takes the setup card's place rather than sitting beside it.
	if data.SetupComplete() {
		since := homeview.EnrollmentWindowStart(time.Now())
		rows, err := h.pkiRepo.EnrollmentsByProfile(r.Context(), s.OrgID, since)
		if err != nil {
			return data, err
		}
		counts := make([]homeview.EnrollmentCount, 0, len(rows))
		for _, row := range rows {
			counts = append(counts, homeview.EnrollmentCount(row))
		}
		data.Enrollments = homeview.BuildEnrollments(since, enrollmentMethods, counts)
	}
	return data, nil
}

// enrollmentMethods is every way a customer can get a certificate out of this
// product, in the order the overview's graph plots them and — because position
// in this slice is the colour slot — the order it colours them. Manual first,
// then the three automated protocols.
//
// It is the roster the graph is drawn from, so a profile added to pki and not
// added here is silently absent from the graph — no error, no gap, just a
// method nobody can see. pki.EnrollmentProfiles is the list it has to cover,
// and TestEnrollmentMethodsCoverEveryProfile holds it to that.
//
// pki.CertProfileInfrastructure is deliberately not here, and
// EnrollmentsByProfile excludes it in SQL as well: those are the registration
// authority certificates SimpleSCEP issues to itself, and nobody enrolled them.
var enrollmentMethods = []homeview.EnrollmentMethod{
	{Profile: pki.CertProfileCSR, Label: "CSR",
		Detail: "Signed from a certificate signing request uploaded to the dashboard"},
	{Profile: pki.CertProfileServer, Label: "Manual server",
		Detail: "Server certificate created in the dashboard, key generated here"},
	{Profile: pki.CertProfileClient, Label: "Manual client",
		Detail: "Client certificate created in the dashboard, key generated here"},
	{Profile: pki.CertProfileSCEP, Label: "SCEP",
		Detail: "Enrolled by a device through a SCEP endpoint"},
	{Profile: pki.CertProfileACME, Label: "ACME",
		Detail: "Issued to an ACME client through an ACME endpoint"},
	{Profile: pki.CertProfileEST, Label: "EST",
		Detail: "Enrolled through an EST endpoint"},
}
