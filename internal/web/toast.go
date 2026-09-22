package web

import (
	"log"
	"net/http"

	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
	"github.com/jacksongrow0/SimpleSCEP/view/layout"
)

// Done confirms a mutation and sends the caller somewhere.
//
// It is the successful half of a mutating handler: the message is stored for
// the page that is about to load, then Redirect decides whether that load is an
// HX-Redirect or a 303. The mechanics are in internal/toast; this is here so
// the common case is one line at the call site rather than two.
//
// Packages that cannot import this one — internal/auth, which this package
// imports — call toast.Announce and redirect themselves.
func Done(w http.ResponseWriter, r *http.Request, location, text string) {
	toast.Announce(w, r, toast.Success, text)
	Redirect(w, r, location)
}

// Fail reports a refusal that htmx would otherwise swallow, then writes the
// status. See toast.Fail.
func Fail(w http.ResponseWriter, r *http.Request, status int, text string) {
	toast.Fail(w, r, status, text)
}

// Announce stores a message for the next page load at a chosen tone. Done is
// the success case; this is for the ones that are not, such as a publish that
// only half worked.
func Announce(w http.ResponseWriter, r *http.Request, tone toast.Tone, text string) {
	toast.Announce(w, r, tone, text)
}

// Page renders a styled error page at the given status.
//
// For a page load, not for an action: a failed GET has no control to attach a
// toast to and nothing on screen to keep, so the honest answer is a whole page
// that says what happened. Fail is the counterpart for a refused action.
//
// An htmx request gets Fail instead. htmx would not swap this page anyway, and a
// full document swapped into a fragment target would be worse than the toast.
func Page(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	if r.Header.Get("HX-Request") == "true" {
		Fail(w, r, status, message)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := layout.ErrorPage(status, heading, message).Render(r.Context(), w); err != nil {
		// The error page itself failed. There is nothing left to render into a
		// half-written response, so this is the one place bare text is right.
		log.Printf("rendering the %d page: %v", status, err)
	}
}
