package middleware

import (
	"net/http"
	"strings"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

// Flash owns the across-a-redirect half of the toast channel: it hands a
// mutating handler the key to sign a message with, and hands the shell any
// message the action that redirected here left behind, clearing it so one
// action produces one toast.
//
// It is also the single place that decides how the flash cookie is written.
// internal/toast imports nothing internal — that is what lets view/layout read
// a message without an import cycle — so it cannot ask internal/auth whether
// this deployment's cookies are Secure. This can, and does, rather than let a
// second package form its own opinion about a security default.
//
// The guard below is the whole of the difficulty. Every asset request on a page
// load carries the same cookie — /static/app.css, /static/htmx.min.js, the QR
// image on the enrolment page — and the file server sits inside the mux, which
// is inside this middleware. Clearing the cookie on whichever of those the
// browser happened to send first would race the HTML render and lose the
// message roughly at random, which is the sort of bug that reproduces once a
// week and never on demand.
func Flash(secret string, next http.Handler) http.Handler {
	config := toast.Config{Secret: secret, SecureCookie: auth.SecureCookie()}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Carried on every request, not only the ones that render: it is what
		// lets a mutating POST sign the message it leaves behind.
		r = r.WithContext(toast.WithConfig(r.Context(), config))
		if rendersPage(r) {
			if m, ok := toast.Take(w, r); ok {
				r = r.WithContext(toast.WithMessage(r.Context(), m))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rendersPage reports whether this request will produce a document with the
// application shell around it. Nothing else is a page.
//
// htmx requests are excluded even though they are GETs that accept HTML: they
// swap a fragment into a page that is already on screen and never render the
// shell, so consuming the flash there would drop it. The pending message waits
// for the next real navigation instead.
func rendersPage(r *http.Request) bool {
	if r.Method != http.MethodGet || r.Header.Get("HX-Request") == "true" {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
