package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecondFactorRoutesAreRegistered is the cheap insurance this repo already
// buys for its enrollment protocols: a route that silently falls through to
// home's catch-all "GET /" answers a second-factor request with a dashboard
// page, and nothing else would notice.
//
// It needs no database — RegisterRoutes only stores the handles it is given — so
// it asserts on the pattern the mux resolves rather than on any response.
func TestSecondFactorRoutesAreRegistered(t *testing.T) {
	mux := http.NewServeMux()
	Handler{}.RegisterRoutes(mux)

	const id = "22222222-2222-2222-2222-222222222222"
	cases := []struct{ method, path, want string }{
		{"GET", "/auth/2fa", "GET /auth/2fa"},
		{"GET", "/auth/recovery-codes", "GET /auth/recovery-codes"},
		{"GET", "/auth/2fa/qr.png", "GET /auth/2fa/qr.png"},
		{"POST", "/auth/2fa/enroll", "POST /auth/2fa/enroll"},
		{"POST", "/auth/2fa/totp", "POST /auth/2fa/totp"},
		{"POST", "/auth/2fa/recovery", "POST /auth/2fa/recovery"},
		{"POST", "/auth/2fa/passkey/begin", "POST /auth/2fa/passkey/begin"},
		{"POST", "/auth/2fa/passkey/finish", "POST /auth/2fa/passkey/finish"},
		{"GET", "/security/panel", "GET /security/panel"},
		{"POST", "/security/step-up", "POST /security/step-up"},
		{"POST", "/security/totp/begin", "POST /security/totp/begin"},
		{"POST", "/security/totp/cancel", "POST /security/totp/cancel"},
		{"POST", "/security/totp/confirm", "POST /security/totp/confirm"},
		{"GET", "/security/totp/qr.png", "GET /security/totp/qr.png"},
		{"POST", "/security/totp/" + id + "/delete", "POST /security/totp/{id}/delete"},
		{"POST", "/security/passkeys/begin", "POST /security/passkeys/begin"},
		{"POST", "/security/passkeys/finish", "POST /security/passkeys/finish"},
		{"POST", "/security/passkeys/" + id + "/delete", "POST /security/passkeys/{id}/delete"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		if _, pattern := mux.Handler(r); pattern != tc.want {
			t.Errorf("%s %s resolved to %q, want %q", tc.method, tc.path, pattern, tc.want)
		}
	}
}

// TestQRIsItsOwnRouteNotAQueryParameter pins a small decision with a real
// consequence. The enrolment QR carries the shared secret, and it is served from
// a path with no parameters so there is nothing a caller can vary to be shown
// somebody else's. If it ever grew a ?user= or ?secret=, this is where that
// would be noticed.
func TestQRIsItsOwnRouteNotAQueryParameter(t *testing.T) {
	mux := http.NewServeMux()
	Handler{}.RegisterRoutes(mux)

	// Both of them: one serves an enrolment authorised by a challenge cookie, the
	// other one authorised by a session, and neither takes a parameter.
	for _, want := range []string{"GET /auth/2fa/qr.png", "GET /security/totp/qr.png"} {
		path := strings.TrimPrefix(want, "GET ") + "?user=someone-else"
		r := httptest.NewRequest("GET", path, nil)
		if _, pattern := mux.Handler(r); pattern != want {
			t.Errorf("%s resolved to %q", path, pattern)
		}
	}
	// The handlers read a cookie and nothing from the query string. This is a
	// statement of intent as much as a check: the parameter above is ignored, and
	// it must stay ignored.
}

