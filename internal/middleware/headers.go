package middleware

import (
	"net/http"
	"strings"

	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
)

// enforcedCSP carries only the directives that are safe to enforce today.
//
// script-src is deliberately absent. Two things in the current UI would break
// under it: view/layout/base.templ renders an inline <script> (templ's
// script localTime()), and hyperscript evaluates its data-script attributes,
// which needs 'unsafe-eval'. Enforcing a script policy that has to allow both
// would buy almost nothing, so the script rules ship as report-only below until
// the inline script carries a hash and the hyperscript dependency is settled.
//
// What is here still pulls weight, and three of the four are anti-CSRF in their
// own right: form-action stops a planted form posting elsewhere, base-uri stops
// a <base> tag re-pointing relative URLs, and frame-ancestors is the modern
// X-Frame-Options.
const enforcedCSP = "base-uri 'none'; form-action 'self'" +
	"; frame-ancestors 'none'; object-src 'none'"

// reportedCSP is the policy this application is working towards. It is sent
// report-only, so a violation is written to the browser console rather than
// blocking the page. There is no report endpoint: this is here to be read
// during development, not collected.
const reportedCSP = "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'; " + enforcedCSP

// protocolPathPrefixes are the device-facing SCEP, ACME and EST operation
// URLs — never rendered by a browser, so the headers below defend nothing
// there. They cost real interoperability instead: EST's own strongSwan client
// carries a fixed-size response buffer sized for a plain PKCS#7 reply, and the
// two CSP headers alone are enough to push a response over it, corrupting the
// body it hands to the ASN.1 parser. The device gets a certificate the server
// issued correctly and a client that cannot read it.
var protocolPathPrefixes = []string{"/.well-known/est/", "/scep/", "/acme/"}

func isProtocolPath(path string) bool {
	for _, prefix := range protocolPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// SecurityHeaders sets the response headers that constrain what a browser will
// do with a page from this application. They are set before the handler runs so
// they apply to error responses too, which is where a sniffed content type or a
// framed page is most likely to matter.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProtocolPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// strict-origin-when-cross-origin keeps a magic-link token out of the
		// Referer sent to any other origin: emailed login URLs carry the token in
		// the query string, and the full URL must not leave this origin.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy", enforcedCSP)
		// Nothing on this host is meant to be found in a search result. It is a
		// signed-in dashboard: every page behind the cookie is unreachable to a
		// crawler anyway, and the handful in front of it — the sign-in form, the
		// terms — are either useless in an index or already published on the
		// marketing site under its own domain.
		//
		// The header rather than robots.txt alone, and as well as the meta tag in
		// the page head. robots.txt asks a crawler not to *fetch* a URL, which is
		// not the same as asking it not to *list* one: a URL discovered elsewhere
		// can be indexed from the link alone, and a disallowed URL is never
		// fetched, so a noindex written only in the HTML would never be read. The
		// header carries the instruction on every response, including the PDFs,
		// CRLs and JSON a meta tag cannot reach.
		h.Set("X-Robots-Tag", "noindex, nofollow")
		h.Set("Content-Security-Policy-Report-Only", reportedCSP)
		// Only over a channel already known to be TLS. Sending HSTS over plain
		// HTTP is ignored by browsers, and asserting it from a deployment whose
		// TLS status cannot be established would be a claim this code cannot back.
		if clientip.SecureChannel(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
