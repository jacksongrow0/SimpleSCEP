package est

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testEndpointID = "22222222-2222-2222-2222-222222222222"

// TestPublicRoutesAreRegistered is cheap insurance against the failure that
// otherwise only appears against a real client: a route that falls through to
// home's catch-all "GET /" and answers an EST request with an HTML page.
//
// It needs no database — RegisterRoutes only stores the handles it is given —
// so it asserts on the pattern the mux resolves rather than on any response.
func TestPublicRoutesAreRegistered(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, nil, nil, testURL)

	cases := []struct{ method, path, want string }{
		{"GET", "/.well-known/est/" + testEndpointID + "/cacerts",
			"GET /.well-known/est/{endpointID}/cacerts"},
		{"GET", "/.well-known/est/" + testEndpointID + "/csrattrs",
			"GET /.well-known/est/{endpointID}/csrattrs"},
		{"POST", "/.well-known/est/" + testEndpointID + "/simpleenroll",
			"POST /.well-known/est/{endpointID}/simpleenroll"},
		{"POST", "/.well-known/est/" + testEndpointID + "/simplereenroll",
			"POST /.well-known/est/{endpointID}/simplereenroll"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		if _, pattern := mux.Handler(r); pattern != tc.want {
			t.Errorf("%s %s resolved to %q, want %q", tc.method, tc.path, pattern, tc.want)
		}
	}
}

func TestAdminRoutesAreRegistered(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, nil, nil, testURL)

	cases := []struct{ path, want string }{
		{"/api/est/endpoints", "POST /api/est/endpoints"},
		{"/api/est/endpoints/" + testEndpointID + "/delete", "POST /api/est/endpoints/{endpointID}/delete"},
		{"/api/est/endpoints/" + testEndpointID + "/enabled", "POST /api/est/endpoints/{endpointID}/enabled"},
		{"/api/est/endpoints/" + testEndpointID + "/policy", "POST /api/est/endpoints/{endpointID}/policy"},
		{"/api/est/endpoints/" + testEndpointID + "/credentials", "POST /api/est/endpoints/{endpointID}/credentials"},
		{"/api/est/endpoints/" + testEndpointID + "/credentials/x/revoke",
			"POST /api/est/endpoints/{endpointID}/credentials/{credentialID}/revoke"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", tc.path, nil)
		if _, pattern := mux.Handler(r); pattern != tc.want {
			t.Errorf("POST %s resolved to %q, want %q", tc.path, pattern, tc.want)
		}
	}
}

// TestEndpointURLAgreesWithRoutes checks the URL an administrator is shown
// against the mux. That string is copied by hand into a device's configuration,
// so a mismatch is a dead endpoint that no other test would catch.
func TestEndpointURLAgreesWithRoutes(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, nil, nil, testURL)

	svc, _ := newTestService(newFakeStore())
	base := svc.EndpointURL(testEndpointID)

	for _, op := range []string{OpCACerts, OpCSRAttrs, OpSimpleEnroll, OpSimpleReenrol} {
		method := "GET"
		if op == OpSimpleEnroll || op == OpSimpleReenrol {
			method = "POST"
		}
		r := httptest.NewRequest(method, base+"/"+op, nil)
		if _, pattern := mux.Handler(r); pattern == "" {
			t.Errorf("%s hangs off %s, which no route serves", op, base)
		}
	}
}

// TestClientPathsAreUnderWellKnown pins the prefix middleware.public exempts.
// Moving these paths without moving that list would answer every enrollment with
// a redirect to the login page.
func TestClientPathsAreUnderWellKnown(t *testing.T) {
	svc, _ := newTestService(newFakeStore())
	base := svc.EndpointURL(testEndpointID)
	const want = testURL + "/.well-known/est/" + testEndpointID
	if base != want {
		t.Errorf("endpoint URL = %q, want %q", base, want)
	}
}
