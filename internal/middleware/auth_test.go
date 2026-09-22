package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestPublicPKIPaths(t *testing.T) {
	if !public(httptest.NewRequest("GET", "/pki/org/ca/crl", nil)) {
		t.Fatal("public PKI endpoint requires authentication")
	}
	if public(httptest.NewRequest("GET", "/revocation", nil)) {
		t.Fatal("revocation dashboard must remain authenticated")
	}
}

// TestPublicEnrollmentPaths guards the failure that would otherwise only appear
// against a real client: a device or ACME path answered with a 303 to the login
// page, which the client reports as an unparseable response rather than as an
// authentication problem.
func TestPublicEnrollmentPaths(t *testing.T) {
	const id = "22222222-2222-2222-2222-222222222222"
	for _, path := range []string{
		"/scep/" + id,
		"/acme/" + id + "/directory",
		"/acme/" + id + "/new-order",
		"/.well-known/est/" + id + "/cacerts",
		"/.well-known/est/" + id + "/simpleenroll",
		"/.well-known/est/" + id + "/simplereenroll",
		"/.well-known/est/" + id + "/csrattrs",
	} {
		if !public(httptest.NewRequest("GET", path, nil)) {
			t.Errorf("%s requires authentication; enrollment clients have no session", path)
		}
	}
	// Administration lives under /protocols precisely so it stays behind the
	// session, even though it administers the public paths above.
	for _, path := range []string{"/protocols/acme/" + id, "/protocols/est/" + id} {
		if public(httptest.NewRequest("GET", path, nil)) {
			t.Errorf("%s must remain authenticated", path)
		}
	}
	// The API surface is not exempt either: only the client prefix is.
	if public(httptest.NewRequest("POST", "/api/est/endpoints", nil)) {
		t.Error("EST administration API must remain authenticated")
	}
}

// TestHealthCheckIsPublic pins the liveness probe as session-exempt.
//
// The platform polls it with no cookie. Behind the session it would be answered
// with a 303 to /login, which is a 3xx rather than a 5xx — so a probe that
// treats any non-error as healthy would report a service with an unreachable
// database as up, which is the one thing the probe exists to catch.
func TestHealthCheckIsPublic(t *testing.T) {
	r := httptest.NewRequest("GET", "/healthz", nil)
	if !public(r) {
		t.Error("/healthz must be reachable without a session")
	}
	// Not a device client: it is neither origin-exempt nor in need of being so,
	// because GET is already outside the CSRF check.
	if deviceClient(r) {
		t.Error("/healthz is not an enrollment client")
	}
}

// TestPublicCoversTheWholeAuthFlow pins the invariant the /auth/ prefix rests
// on. Every step between clicking a magic link and holding a session must be
// reachable without the cookie it exists to mint, so the whole prefix is public.
func TestPublicCoversTheWholeAuthFlow(t *testing.T) {
	for _, path := range []string{
		"/login",
		"/setup",
		"/auth/email",
		"/auth/invite",
		"/auth/2fa",
		"/auth/2fa/qr.png",
		"/auth/2fa/totp",
		"/auth/2fa/recovery",
		"/auth/2fa/passkey/begin",
		"/auth/2fa/passkey/finish",
	} {
		if !public(httptest.NewRequest("POST", path, nil)) {
			t.Errorf("%s requires a session, but it is part of the flow that creates one", path)
		}
	}
}

// TestSecurityPagesRequireASession is the other half of that invariant, and the
// reason post-session security management lives under /security/ rather than
// under /auth/. Managing a second factor is something an authenticated user
// does; if any of it were reachable without a session, an attacker holding only
// a magic link could enroll their own authenticator.
func TestSecurityPagesRequireASession(t *testing.T) {
	const id = "22222222-2222-2222-2222-222222222222"
	for _, path := range []string{
		"/security",
		"/security/step-up",
		"/security/recovery-codes",
		"/security/totp/begin",
		"/security/passkeys/begin",
		"/security/passkeys/" + id + "/delete",
	} {
		if public(httptest.NewRequest("POST", path, nil)) {
			t.Errorf("%s must remain authenticated", path)
		}
	}
}

// TestDeviceClientIsNarrowerThanPublic states the relationship the two
// predicates have to keep: every machine caller may skip the session, but the
// browser pages that create a session may not skip the origin check. Collapsing
// the two back into one function is what put POST /login outside CSRF.
func TestDeviceClientIsNarrowerThanPublic(t *testing.T) {
	const id = "22222222-2222-2222-2222-222222222222"
	machine := []string{
		"/scep/" + id,
		"/acme/" + id + "/new-order",
		"/.well-known/est/" + id + "/simpleenroll",
		"/integrations/jamf/scep-challenge/" + id,
	}
	for _, path := range machine {
		r := httptest.NewRequest("POST", path, nil)
		if !deviceClient(r) {
			t.Errorf("%s is an enrollment client and must be exempt from the origin check", path)
		}
		if !public(r) {
			t.Errorf("%s is exempt from the origin check but not from the session; the two must agree", path)
		}
	}
	// Browsers: session-exempt, never origin-exempt.
	for _, path := range []string{"/login", "/setup", "/auth/email", "/auth/2fa/totp", "/static/app.css"} {
		r := httptest.NewRequest("POST", path, nil)
		if deviceClient(r) {
			t.Errorf("%s is reached by a browser and must stay inside the origin check", path)
		}
		if !public(r) {
			t.Errorf("%s must be reachable without a session", path)
		}
	}
}

// The sign-in page renders the wordmark, and nobody looking at the sign-in page
// has a session yet: an /assets/ path behind the cookie is a login form with a
// broken image on it. robots.txt is here for the same shape of reason — a
// crawler has no cookie either, and a redirect to /login is not an answer to
// what it asked.
func TestTheBrandAndRobotsFileNeedNoSession(t *testing.T) {
	for _, path := range []string{
		"/assets/logos/horizontal-dark.svg",
		"/assets/favicon.svg",
		"/assets/site.webmanifest",
		"/robots.txt",
		"/favicon.ico",
	} {
		if !public(httptest.NewRequest("GET", path, nil)) {
			t.Errorf("%s requires a session, so it is missing from the page that has none", path)
		}
	}
}
