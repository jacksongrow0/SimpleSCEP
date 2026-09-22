package home

import (
	"encoding/csv"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/web"
	homeview "github.com/jacksongrow0/SimpleSCEP/view/home"
)

// The audit trail page and its CSV export.

func (h Handler) audit(w http.ResponseWriter, r *http.Request) {
	s := session(r)
	if !s.CanViewAudit() {
		web.Page(w, r, http.StatusForbidden, "You cannot view the audit log",
			"Only administrators and auditors can read it. Ask an administrator if you need access.")
		return
	}
	data, err := h.auditPage(r, s)
	if err != nil {
		log.Printf("home org=%s audit failed: %v", s.OrgID, err)
		web.Page(w, r, http.StatusInternalServerError, "The audit log could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	if err := homeview.Audit(s, data).Render(r.Context(), w); err != nil {
		web.Page(w, r, http.StatusInternalServerError, "That page could not be rendered",
			"Something went wrong on our side. Try again in a moment.")
	}
}

// auditExport serves the same query as a CSV attachment, unpaged: it is the way
// to take more of the log than the pager will walk, so it answers with every
// matching event rather than the fifty the reader can see.
func (h Handler) auditExport(w http.ResponseWriter, r *http.Request) {
	s := session(r)
	if !s.CanViewAudit() {
		web.Page(w, r, http.StatusForbidden, "You cannot view the audit log",
			"Only administrators and auditors can read it. Ask an administrator if you need access.")
		return
	}
	data, err := h.auditExportData(r, s)
	if err != nil {
		log.Printf("home org=%s audit export failed: %v", s.OrgID, err)
		web.Page(w, r, http.StatusInternalServerError, "The audit export could not be built",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="simplescep-audit-`+
		time.Now().UTC().Format("20060102")+`.csv"`)
	out := csv.NewWriter(w)
	// The actor context columns are what makes the export a forensic record
	// rather than a prettier version of the page: they are the only place the
	// address, client, and session behind an action are readable. They are
	// empty for events with no request behind them — a device enrolling over
	// SCEP, or anything derived from the signing audit, which has no such
	// columns to carry.
	_ = out.Write([]string{"timestamp_utc", "event", "actor", "actor_email", "target", "detail",
		"actor_ip", "actor_user_agent", "actor_session_id"})
	for _, e := range data.Events {
		_ = out.Write([]string{e.At.UTC().Format(time.RFC3339), audit.ActionLabel(e.Action),
			e.Actor(), e.ActorEmail, e.Target, e.Detail,
			e.ActorIP, e.ActorUserAgent, e.ActorSessionID})
	}
	out.Flush()
}

// auditPageSize is how many events one page renders. Small enough that the page
// is a scan rather than a scroll, now that a row is one line.
const auditPageSize = 50

// maxAuditPages bounds how deep paging may go, because a page is not free at
// depth: Events reads offset+limit rows from each of the two source tables to
// return one page of them, so page 10,000 is a request to hold half a million
// rows in memory. Ten thousand events back is far past the point where scrolling
// is the right tool — the filters narrow, and the CSV export takes the rest.
const maxAuditPages = 200

// auditExportLimit bounds the CSV. The export exists to be the unpaged record,
// so this is high enough not to be reached in practice, but it is a real bound
// rather than none: an organization's whole history streamed into one response
// is a way to take the process down.
//
// It used to be absent, which was not the same as unlimited. The export asked
// for limit 0 and audit.Events read that as "no preference" and applied its own
// default of 200 — so the export silently stopped at 200 rows, which is exactly
// the failure the comment above it said would be worse than no export at all.
const auditExportLimit = 50000

// auditFilters reads the filter state out of the query string. It is shared by
// the page and the export so that the CSV covers exactly what the page shows.
func auditFilters(r *http.Request) homeview.AuditData {
	query := r.URL.Query()
	data := homeview.AuditData{
		ActorID: strings.TrimSpace(query.Get("actor")),
		Action:  strings.TrimSpace(query.Get("action")),
		From:    strings.TrimSpace(query.Get("from")),
		To:      strings.TrimSpace(query.Get("to")),
	}
	data.Filter = audit.Filter{Actor: data.ActorID, Action: data.Action,
		From: audit.Day(data.From, false), To: audit.Day(data.To, true)}
	return data
}

// auditPage reads one page of the log, along with the counts the header and the
// pager need.
//
// The count comes first because the page number cannot be validated without it.
// A request for page 900 of a 3-page log is not an error — it is a stale link, a
// bookmark, or a filter that has since narrowed — so it is clamped to the last
// page and rendered, rather than answered with an empty list that looks like a
// log with nothing in it.
func (h Handler) auditPage(r *http.Request, s auth.Session) (homeview.AuditData, error) {
	data := auditFilters(r)
	var err error
	if data.Matching, err = h.auditRepo.CountMatching(r.Context(), s.OrgID, data.Filter); err != nil {
		return data, err
	}
	data.PageSize = auditPageSize
	data.Pages = (data.Matching + auditPageSize - 1) / auditPageSize
	if data.Pages < 1 {
		data.Pages = 1
	}
	if data.Pages > maxAuditPages {
		data.Pages, data.Capped = maxAuditPages, true
	}
	data.Page = auditPageNumber(r.URL.Query().Get("page"), data.Pages)
	data.Filter.Limit, data.Filter.Offset = auditPageSize, (data.Page-1)*auditPageSize
	if data.Events, err = h.auditRepo.Events(r.Context(), s.OrgID, data.Filter); err != nil {
		return data, err
	}
	if data.Total, err = h.auditRepo.Count(r.Context(), s.OrgID); err != nil {
		return data, err
	}
	data.Actors, err = h.auditActors(r, s)
	return data, err
}

// auditPageNumber reads ?page= and keeps it inside the log. Anything that is not
// a page — a word, a negative, a number past the end — resolves to a page that
// exists rather than to an error, because none of them is the reader's mistake
// to correct.
func auditPageNumber(raw string, pages int) int {
	page, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || page < 1 {
		return 1
	}
	if page > pages {
		return pages
	}
	return page
}

// auditExportData reads every matching event for the CSV, unpaged.
func (h Handler) auditExportData(r *http.Request, s auth.Session) (homeview.AuditData, error) {
	data := auditFilters(r)
	data.Filter.Limit = auditExportLimit
	var err error
	data.Events, err = h.auditRepo.Events(r.Context(), s.OrgID, data.Filter)
	return data, err
}

func (h Handler) auditActors(r *http.Request, s auth.Session) ([]auth.User, error) {
	orgID, err := uuid.Parse(s.OrgID)
	if err != nil {
		return nil, err
	}
	return h.repo.Users(r.Context(), orgID)
}
