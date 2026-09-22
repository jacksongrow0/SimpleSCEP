package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testAppURL = "https://pki.example.com"

func csrfHandler() http.Handler {
	return CSRF(testAppURL, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

func serve(t *testing.T, r *http.Request) int {
	t.Helper()
	w := httptest.NewRecorder()
	csrfHandler().ServeHTTP(w, r)
	return w.Code
}

func TestCSRFDecision(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		site    string
		origin  string
		referer string
		want    int
	}{
		// Safe methods never change state, so they are never refused.
		{name: "GET needs nothing", method: "GET", path: "/certificate-authorities", want: http.StatusNoContent},
		{name: "HEAD needs nothing", method: "HEAD", path: "/certificate-authorities", want: http.StatusNoContent},
		{name: "OPTIONS preflight", method: "OPTIONS", path: "/api/est/endpoints", want: http.StatusNoContent},

		// Sec-Fetch-Site is the browser's own answer and wins when present.
		{name: "same-origin post", method: "POST", path: "/certificate-authorities/x/delete",
			site: "same-origin", want: http.StatusNoContent},
		{name: "typed url or bookmark", method: "POST", path: "/logout", site: "none", want: http.StatusNoContent},
		{name: "cross-site post refused", method: "POST", path: "/certificate-authorities/x/delete",
			site: "cross-site", want: http.StatusForbidden},
		// The gap SameSite=Lax leaves open: a sibling subdomain is "same-site".
		{name: "same-site sibling refused", method: "POST", path: "/certificate-authorities/x/delete",
			site: "same-site", want: http.StatusForbidden},
		// A cross-site request does not get to override the browser's own answer
		// by also sending a matching Origin.
		{name: "site header beats a forged origin", method: "POST", path: "/certificate-authorities/x/delete",
			site: "cross-site", origin: testAppURL, want: http.StatusForbidden},

		// Older browsers send Origin but not Sec-Fetch-Site.
		{name: "matching origin", method: "POST", path: "/certificates/issue",
			origin: testAppURL, want: http.StatusNoContent},
		{name: "foreign origin", method: "POST", path: "/certificates/issue",
			origin: "https://evil.example", want: http.StatusForbidden},
		{name: "sibling origin", method: "POST", path: "/certificates/issue",
			origin: "https://other.example.com", want: http.StatusForbidden},
		{name: "scheme downgrade", method: "POST", path: "/certificates/issue",
			origin: "http://pki.example.com", want: http.StatusForbidden},

		// Referer is the last resort; only scheme and host are compared.
		{name: "matching referer", method: "POST", path: "/certificates/issue",
			referer: testAppURL + "/certificate-authorities", want: http.StatusNoContent},
		{name: "foreign referer", method: "POST", path: "/certificates/issue",
			referer: "https://evil.example/page", want: http.StatusForbidden},

		// No evidence at all from a browser path is refused.
		{name: "bare post refused", method: "POST", path: "/certificate-authorities/x/delete",
			want: http.StatusForbidden},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		if tc.site != "" {
			r.Header.Set("Sec-Fetch-Site", tc.site)
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.referer != "" {
			r.Header.Set("Referer", tc.referer)
		}
		if got := serve(t, r); got != tc.want {
			t.Errorf("%s: %s %s = %d, want %d", tc.name, tc.method, tc.path, got, tc.want)
		}
	}
}

// TestCSRFExemptsEveryEnrollmentPath is the test standing between this
// middleware and a global enrollment outage. SCEP, ACME, EST and the Jamf
// webhook are not browsers: they send no Origin and no Sec-Fetch-Site, so if
// any of them stopped being exempt, every device in every customer fleet would
// be refused with a 403 that no client reports usefully.
func TestCSRFExemptsEveryEnrollmentPath(t *testing.T) {
	const id = "22222222-2222-2222-2222-222222222222"
	for _, path := range []string{
		"/scep/" + id,
		"/scep/" + id + "/pkiclient.exe",
		"/acme/" + id + "/new-account",
		"/acme/" + id + "/new-order",
		"/acme/" + id + "/revoke-cert",
		"/.well-known/est/" + id + "/simpleenroll",
		"/.well-known/est/" + id + "/simplereenroll",
		"/integrations/jamf/scep-challenge/" + id,
		"/pki/" + id + "/" + id + "/ocsp",
	} {
		r := httptest.NewRequest("POST", path, nil)
		if got := serve(t, r); got != http.StatusNoContent {
			t.Errorf("POST %s = %d, want %d: enrollment clients send no browser headers",
				path, got, http.StatusNoContent)
		}
	}
}

// TestCSRFAllowsOCSPOverPOST pins the one exempt path that is neither an
// enrollment nor a webhook.
//
// RFC 6960 lets a client send an OCSP request as a base64 GET or as a DER POST
// body, and the choice is not the client's preference: OpenSSL, Windows
// CryptoAPI and NSS all switch to POST once the request outgrows the GET length
// limit, and several use POST unconditionally. None of them sends a browser
// header, so without the exemption the origin check refuses the request — and a
// relying party configured to hard-fail reads that 403 as "revocation status
// unavailable" and rejects the whole chain, which is indistinguishable from this
// service having revoked the certificate.
//
// The body is here because the GET form of this route already passed as a safe
// method: a test with no body would pass even if the POST route were refused.
func TestCSRFAllowsOCSPOverPOST(t *testing.T) {
	const id = "22222222-2222-2222-2222-222222222222"
	path := "/pki/" + id + "/" + id + "/ocsp"
	r := httptest.NewRequest("POST", path, bytes.NewReader([]byte{0x30, 0x03, 0x02, 0x01, 0x00}))
	r.Header.Set("Content-Type", "application/ocsp-request")
	if got := serve(t, r); got != http.StatusNoContent {
		t.Errorf("POST %s = %d, want %d: an OCSP responder client sends no browser headers",
			path, got, http.StatusNoContent)
	}
}

// TestCSRFProtectsAdministration is the other half: the paths that destroy CA
// key material or issue certificates must not be exempt.
func TestCSRFProtectsAdministration(t *testing.T) {
	const id = "22222222-2222-2222-2222-222222222222"
	for _, path := range []string{
		"/certificate-authorities",
		"/certificate-authorities/" + id + "/delete",
		"/certificate-authorities/" + id + "/rotate",
		"/certificate-authorities/" + id + "/status",
		"/certificates/issue",
		"/certificates/csr",
		"/certificates/" + id + "/revoke",
		"/api/scep/endpoints",
		"/api/acme/endpoints",
		"/api/est/endpoints",
		"/settings/invitations",
		"/settings/users/" + id + "/role",
		"/logout",
	} {
		r := httptest.NewRequest("POST", path, nil)
		if got := serve(t, r); got != http.StatusForbidden {
			t.Errorf("POST %s = %d, want %d: this path changes state and must be origin-checked",
				path, got, http.StatusForbidden)
		}
	}
}

// TestCSRFExemptionMatchesDeviceClient keeps the exemption tied to the one
// predicate that describes it. A machine caller must skip both the session and
// the origin check, or it would be refused at a different layer than the one
// that exempted it.
func TestCSRFExemptionMatchesDeviceClient(t *testing.T) {
	const id = "22222222-2222-2222-2222-222222222222"
	for _, path := range []string{
		"/scep/" + id,
		"/acme/" + id + "/new-order",
		"/.well-known/est/" + id + "/simpleenroll",
		"/integrations/jamf/scep-challenge/" + id,
		"/certificate-authorities/" + id + "/delete",
		"/api/est/endpoints",
		"/login",
		"/setup",
		"/auth/2fa/totp",
	} {
		r := httptest.NewRequest("POST", path, nil)
		exempt := serve(t, r) == http.StatusNoContent
		if exempt != deviceClient(r) {
			t.Errorf("%s: CSRF exempt = %v but deviceClient() = %v; the two disagree",
				path, exempt, deviceClient(r))
		}
	}
}

// TestCSRFProtectsSessionCreatingPosts is the regression guard for a hole that
// existed while CSRF shared one predicate with the session allowlist: /login and
// /setup are listed there, so they were exempt from the origin check, and a
// cross-site POST could sign a victim's browser into an account the attacker
// controls. The second-factor submissions inherit the same reasoning and are
// pinned here before they are written.
func TestCSRFProtectsSessionCreatingPosts(t *testing.T) {
	for _, path := range []string{
		"/login",
		"/setup",
		"/logout",
		"/auth/2fa/totp",
		"/auth/2fa/recovery",
		"/auth/2fa/passkey/finish",
		"/security/step-up",
	} {
		r := httptest.NewRequest("POST", path, nil)
		if got := serve(t, r); got != http.StatusForbidden {
			t.Errorf("POST %s = %d, want %d: this path completes an authentication and must be origin-checked",
				path, got, http.StatusForbidden)
		}
		// The same paths must still be reachable from our own origin.
		r = httptest.NewRequest("POST", path, nil)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		if got := serve(t, r); got != http.StatusNoContent {
			t.Errorf("POST %s from our own origin = %d, want %d", path, got, http.StatusNoContent)
		}
	}
}
