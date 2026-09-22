package home

import (
	"log"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/jacksongrow0/SimpleSCEP/internal/web"
	homeview "github.com/jacksongrow0/SimpleSCEP/view/home"
	"github.com/jacksongrow0/SimpleSCEP/view/layout"
)

// Organization account pages: support, users and settings.

// support renders links to the public documentation and community trackers.
func (h Handler) support(w http.ResponseWriter, r *http.Request) {
	s := session(r)
	if err := homeview.Support(s, layout.DocsURL, layout.IssuesURL, layout.SecurityURL).Render(r.Context(), w); err != nil {
		web.Page(w, r, http.StatusInternalServerError, "That page could not be rendered",
			"Something went wrong on our side. Try again in a moment.")
	}
}
func (h Handler) users(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(s.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusBadRequest, "This account has no organization",
			"Sign out and back in. If it persists, check the server logs and community documentation.")
		return
	}
	users, err := h.repo.Users(r.Context(), id)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "The team could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	// A failure to read the invitations must not take the team page down with it:
	// the members are the page, and the invitations are an addition to it.
	pending, err := h.repo.PendingInvitations(r.Context(), id)
	if err != nil {
		log.Printf("home org=%s pending invitations failed: %v", s.OrgID, err)
	}
	_ = homeview.Users(s, users, pending).Render(r.Context(), w)
}
func (h Handler) organization(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(s.OrgID)
	if err != nil {
		web.Page(w, r, http.StatusBadRequest, "This account has no organization",
			"Sign out and back in. If it persists, check the server logs and community documentation.")
		return
	}
	org, err := h.repo.Organization(r.Context(), id)
	if err != nil {
		web.Page(w, r, http.StatusInternalServerError, "Your organization could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	_ = homeview.Organization(s, org, currentPosture()).Render(r.Context(), w)
}

// currentPosture reports what this deployment actually does, for the
// Organization page's compliance card.
//
// Read from the process rather than stored per organization: every tenant on one
// deployment shares the same key provider and CRL schedule. Individual CAs
// record their own software/HSM posture. The card was five hardcoded strings
// before this, two of them false — see homeview.Posture.
func currentPosture() homeview.Posture {
	return homeview.Posture{
		KeyProtection: pki.KeyProviderSummary(),
		Region:        pki.KeyLocation(),
		CRLRefresh:    "Every " + strconv.Itoa(int(pki.CRLRefreshInterval.Hours())) + "h",
	}
}
