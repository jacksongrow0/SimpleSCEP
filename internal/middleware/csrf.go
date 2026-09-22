package middleware

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

// CSRF refuses state-changing browser requests that did not originate from this
// application's own origin.
//
// The session cookie is SameSite=Lax, which already blocks a cross-site form
// post. Two gaps remain, and this closes both: browsers that do not default to
// Lax, and same-site sibling origins — a subdomain of the cookie's domain is
// "same-site" to Lax but is not this application. The targets on the other side
// of those gaps include POST /certificate-authorities/{id}/delete, which
// schedules destruction of a CA's KMS key version.
//
// Enrollment traffic is exempt via deviceClient(): SCEP, ACME, EST and the Jamf
// webhook are not browsers, send neither Origin nor Sec-Fetch-Site, and would
// otherwise be refused — which would stop every device in every customer fleet
// from enrolling. That exemption is checked before anything else, and before
// the session, so a device request carrying a stray cookie still passes.
//
// The exemption is deviceClient() and not public(), which is a narrower set.
// public() also admits the browser pages that create a session — /login,
// /setup and the /auth/ flow — and those are browser form posts that complete
// an authentication. Exempting them would make POST /login and the second-factor
// submission usable as login-CSRF primitives: an attacker could sign a victim
// into an account the attacker controls, or complete their own second factor in
// the victim's browser. They send browser headers, so they are checked.
func CSRF(appURL string, next http.Handler) http.Handler {
	expected, err := url.Parse(appURL)
	if err != nil || expected.Host == "" {
		// Unreachable in a configured deployment: APP_URL is validated at startup
		// before this is constructed. Refusing to build a permissive middleware is
		// still the right failure, so say so loudly.
		log.Fatalf("CSRF middleware requires a valid APP_URL, got %q", appURL)
	}
	origin := expected.Scheme + "://" + expected.Host

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) || deviceClient(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r, origin) {
			// htmx will not swap a 403, so this refusal used to be entirely
			// silent: the button did nothing and said nothing. The trigger
			// header is read before htmx decides whether to swap, which is the
			// only way a non-2xx reaches the screen.
			toast.Fail(w, r, http.StatusForbidden,
				"That request was refused because it did not come from this site. Reload the page and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// safeMethod reports whether the method is one that must not change state.
// OPTIONS is included so a preflight is answered rather than refused.
func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// sameOrigin decides whether a state-changing request came from this
// application, preferring the header that says so most directly.
func sameOrigin(r *http.Request, origin string) bool {
	// Sec-Fetch-Site is the browser's own answer and cannot be set by script.
	// "same-site" is refused along with "cross-site": it covers sibling
	// subdomains, which is precisely what SameSite=Lax does not protect against.
	// "none" is a user-initiated navigation with no initiator — a typed URL or a
	// bookmark — which is not an attacker-driven request.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	// Older browsers: Origin is sent on every state-changing request.
	if got := r.Header.Get("Origin"); got != "" {
		return strings.EqualFold(got, origin)
	}
	// Last resort. Referer carries a full URL, so compare only scheme and host.
	if ref := r.Header.Get("Referer"); ref != "" {
		parsed, err := url.Parse(ref)
		if err != nil {
			return false
		}
		return strings.EqualFold(parsed.Scheme+"://"+parsed.Host, origin)
	}
	// No evidence at all. Every browser sends at least one of the above on a
	// state-changing request, so this is refused rather than assumed friendly.
	return false
}
