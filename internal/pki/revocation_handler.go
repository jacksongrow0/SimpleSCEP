package pki

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
	"github.com/jacksongrow0/SimpleSCEP/internal/web"
	homeview "github.com/jacksongrow0/SimpleSCEP/view/home"
)

func (h Handler) revocationPage(w http.ResponseWriter, r *http.Request) {
	session, ok := authenticated(w, r)
	if !ok {
		return
	}
	cas, err := h.repo.CAs(r.Context(), session.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "The revocation page could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	revocations, err := h.repo.Revocations(r.Context(), session.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "The revocation page could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	data := revocationPageData(h.service, session, cas, revocations, func(caID string) (CRLPublication, error) {
		return h.repo.CRLPublication(r.Context(), session.OrgID, caID)
	})
	if err := homeview.Revocation(session, data).Render(r.Context(), w); err != nil {
		web.Page(w, r, http.StatusInternalServerError, "That page could not be rendered",
			"Something went wrong on our side. Try again in a moment.")
	}
}

// revocationPageData hands the view instants rather than formatted strings:
// publication and revocation times are rendered client-side in the viewer's own
// timezone, and a nil pointer is what the view shows its placeholder for.
func revocationPageData(service Service, session auth.Session, cas []CertificateAuthority, revocations []Revocation, publication func(string) (CRLPublication, error)) homeview.RevocationData {
	data := homeview.RevocationData{RevokedCount: strconv.Itoa(len(revocations))}
	affected := map[string]bool{}
	var latest, next time.Time
	for _, ca := range cas {
		if ca.Type != CATypeIssuing {
			continue
		}
		data.CAs = append(data.CAs, homeview.CAOption{ID: ca.ID, Name: ca.Name})
		point := homeview.DistributionPoint{CAName: ca.Name, CRLURL: service.PublicEndpoint(session.OrgID, ca.ID, "crl"), OCSPURL: service.PublicEndpoint(session.OrgID, ca.ID, "ocsp"), Status: "Pending"}
		if p, err := publication(ca.ID); err == nil {
			if p.LastError != "" {
				point.Status = "Degraded"
			} else if p.PublishedAt != nil {
				point.Status = "Healthy"
			}
			if p.PublishedAt != nil {
				point.PublishedAt = p.PublishedAt
				if p.PublishedAt.After(latest) {
					latest = *p.PublishedAt
				}
			}
			if p.NextUpdate != nil {
				point.NextUpdate = p.NextUpdate
				if next.IsZero() || p.NextUpdate.Before(next) {
					next = *p.NextUpdate
				}
			}
		}
		data.Points = append(data.Points, point)
	}
	for _, rev := range revocations {
		affected[rev.CAID] = true
		data.Rows = append(data.Rows, homeview.RevocationRow{CN: commonNameOf(rev.Subject), Serial: rev.Serial, CAID: rev.CAID, CAName: rev.CAName, Reason: rev.Reason, RevokedAt: rev.RevokedAt})
	}
	data.AffectedCAs = strconv.Itoa(len(affected))
	if !latest.IsZero() {
		data.LastPublished = &latest
	}
	if !next.IsZero() {
		data.NextUpdate = &next
	}
	return data
}

func (h Handler) publishCRLs(w http.ResponseWriter, r *http.Request) {
	session, ok := manager(w, r)
	if !ok {
		return
	}
	cas, err := h.repo.CAs(r.Context(), session.OrgID)
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError,
			"The CRLs could not be republished. The hourly worker will retry; try again if it stays failed.")
		return
	}
	// Which CA failed is the whole of what a person needs here, and it used to
	// be discarded: the loop set a bare boolean and redirected to
	// /revocation?publication=failed, a parameter no page has ever read. A
	// half-published set of revocation lists therefore looked exactly like a
	// successful one, which is the worst possible outcome for the mechanism
	// that tells relying parties a certificate is no longer trusted.
	var failed []string
	published := 0
	for _, ca := range cas {
		if ca.Type != CATypeIssuing {
			continue
		}
		if err := h.service.PublishCRL(r.Context(), session.OrgID, ca.ID); err != nil {
			log.Printf("pki org=%s ca=%s crl publish failed: %v", session.OrgID, ca.ID, err)
			failed = append(failed, ca.Name)
			continue
		}
		published++
	}
	switch {
	case len(failed) > 0:
		web.Announce(w, r, toast.Warning, "Could not publish the revocation list for "+
			strings.Join(failed, ", ")+". Those lists are still the previous version.")
	case published == 0:
		web.Announce(w, r, toast.Info, "There are no issuing certificate authorities to publish for")
	default:
		web.Announce(w, r, toast.Success, "Published "+strconv.Itoa(published)+
			" revocation list"+plural(published))
	}
	web.Redirect(w, r, "/revocation")
}
