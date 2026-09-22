package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

// TestAHalfSessionReachesNothing is the design thesis of mandatory two-factor,
// stated as a test.
//
// The whole scheme rests on one property: an "auth" cookie means both factors
// are complete, and nothing else does. A browser that has redeemed a magic link
// holds an "mfa" cookie naming a login_challenge, and that cookie must be worth
// exactly nothing to every authenticated route — not because a check refuses it,
// but because the session lookup has nothing to find.
//
// If someone later reintroduces a half-authenticated session — an
// mfa_satisfied_at column, a "pending" session row, a bypass for one endpoint —
// this is the test that fails.
func TestAHalfSessionReachesNothing(t *testing.T) {
	const secret = "test-secret-at-least-32-characters-long"
	// A well-formed, correctly signed challenge cookie. It names a real-looking
	// challenge and carries a valid HMAC, so nothing about its shape is what
	// gets it refused.
	challenge := "5f775cd5-96ce-46b1-8348-563097f0db83"
	cookie := &http.Cookie{
		Name:  auth.ChallengeCookieName,
		Value: challenge + "." + auth.Sign(challenge, secret),
	}

	// Auth is given a nil database on purpose: if the challenge cookie were ever
	// treated as a session, the handler would try to open a transaction and this
	// would panic rather than quietly pass. Reaching the redirect proves the
	// cookie was never mistaken for one.
	reached := false
	handler := Auth(nil, auth.Repository{}, secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range []string{
		"/",
		"/certificate-authorities",
		"/certificates",
		"/organization",
		"/users",
		"/audit",
		"/security",
	} {
		reached = false
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		if reached {
			t.Errorf("%s was served to a browser holding only a second-factor challenge; "+
				"an mfa cookie must never authenticate anything", path)
		}
		if w.Code != http.StatusSeeOther {
			t.Errorf("%s = %d, want %d to /login", path, w.Code, http.StatusSeeOther)
		}
		if location := w.Header().Get("Location"); location != "/login" {
			t.Errorf("%s redirected to %q, want /login", path, location)
		}
	}
}

// TestTheChallengeCookieIsNotTheSessionCookie states the separation the above
// depends on. One cookie name, used for both, is the shape of the bug this
// design exists to make impossible.
func TestTheChallengeCookieIsNotTheSessionCookie(t *testing.T) {
	if auth.ChallengeCookieName == auth.CookieName {
		t.Fatalf("the challenge and session cookies share the name %q; a half-finished "+
			"login would then be indistinguishable from a complete one", auth.CookieName)
	}
}

// TestTheSecondFactorFlowIsReachableWithoutASession is the other half: the pages
// that complete a login cannot require the cookie they exist to mint. Together
// with TestAHalfSessionReachesNothing this fixes both ends — /auth/ is reachable
// and buys nothing, /security/ is not reachable at all.
func TestTheSecondFactorFlowIsReachableWithoutASession(t *testing.T) {
	const secret = "test-secret-at-least-32-characters-long"
	reached := false
	handler := Auth(nil, auth.Repository{}, secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range []string{
		"/login", "/setup", "/auth/email", "/auth/invite",
		"/auth/2fa", "/auth/2fa/qr.png", "/auth/2fa/totp", "/auth/2fa/recovery",
	} {
		reached = false
		r := httptest.NewRequest("GET", path, nil)
		handler.ServeHTTP(httptest.NewRecorder(), r)
		if !reached {
			t.Errorf("%s was refused without a session, but it is part of the flow that creates one", path)
		}
	}
}
