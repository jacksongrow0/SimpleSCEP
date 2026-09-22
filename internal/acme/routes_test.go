package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPublicRoutesAreRegistered is cheap insurance against the failure that
// otherwise only appears against a real client: a route that falls through to
// home's catch-all "GET /" and answers an ACME request with an HTML page.
//
// It needs no database — RegisterRoutes only stores the handles it is given —
// so it asserts on the pattern the mux resolves rather than on any response.
func TestPublicRoutesAreRegistered(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, nil, nil, "https://pki.example.test")

	const id = "22222222-2222-2222-2222-222222222222"
	cases := []struct{ method, path, want string }{
		{"GET", "/acme/" + id + "/directory", "GET /acme/{endpointID}/directory"},
		{"HEAD", "/acme/" + id + "/new-nonce", "HEAD /acme/{endpointID}/new-nonce"},
		{"GET", "/acme/" + id + "/new-nonce", "GET /acme/{endpointID}/new-nonce"},
		{"POST", "/acme/" + id + "/new-account", "POST /acme/{endpointID}/new-account"},
		{"POST", "/acme/" + id + "/accounts/abc", "POST /acme/{endpointID}/accounts/{accountID}"},
		{"POST", "/acme/" + id + "/key-change", "POST /acme/{endpointID}/key-change"},
		{"POST", "/acme/" + id + "/new-order", "POST /acme/{endpointID}/new-order"},
		{"POST", "/acme/" + id + "/orders/abc", "POST /acme/{endpointID}/orders/{orderID}"},
		{"POST", "/acme/" + id + "/orders/abc/finalize", "POST /acme/{endpointID}/orders/{orderID}/finalize"},
		{"POST", "/acme/" + id + "/authorizations/abc", "POST /acme/{endpointID}/authorizations/{authzID}"},
		{"POST", "/acme/" + id + "/challenges/abc", "POST /acme/{endpointID}/challenges/{challengeID}"},
		{"POST", "/acme/" + id + "/certificates/abc", "POST /acme/{endpointID}/certificates/{orderID}"},
		{"POST", "/acme/" + id + "/revoke-cert", "POST /acme/{endpointID}/revoke-cert"},
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
	RegisterRoutes(mux, nil, nil, "https://pki.example.test")

	const id = "22222222-2222-2222-2222-222222222222"
	cases := []struct{ path, want string }{
		{"/api/acme/endpoints", "POST /api/acme/endpoints"},
		{"/api/acme/endpoints/" + id + "/delete", "POST /api/acme/endpoints/{endpointID}/delete"},
		{"/api/acme/endpoints/" + id + "/enabled", "POST /api/acme/endpoints/{endpointID}/enabled"},
		{"/api/acme/endpoints/" + id + "/policy", "POST /api/acme/endpoints/{endpointID}/policy"},
		{"/api/acme/endpoints/" + id + "/credentials", "POST /api/acme/endpoints/{endpointID}/credentials"},
		{"/api/acme/endpoints/" + id + "/credentials/x/revoke",
			"POST /api/acme/endpoints/{endpointID}/credentials/{credentialID}/revoke"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", tc.path, nil)
		if _, pattern := mux.Handler(r); pattern != tc.want {
			t.Errorf("POST %s resolved to %q, want %q", tc.path, pattern, tc.want)
		}
	}
}

// TestDirectoryURLsAgreeWithRoutes checks the directory against the mux. A
// client only ever learns its URLs from the directory, so a typo there is a
// dead endpoint that no other test would catch.
func TestDirectoryURLsAgreeWithRoutes(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, nil, nil, "https://pki.example.test")

	repo := newFakeStore()
	svc, _ := newTestService(repo)
	directory := svc.Directory(endpointOf(t, repo))

	for _, key := range []string{"newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"} {
		url, ok := directory[key].(string)
		if !ok {
			t.Fatalf("directory is missing %s", key)
		}
		method := "POST"
		if key == "newNonce" {
			method = "GET"
		}
		// The directory carries absolute URLs; the mux matches on the path.
		r := httptest.NewRequest(method, url, nil)
		if _, pattern := mux.Handler(r); pattern == "" {
			t.Errorf("directory %s points at %s, which no route serves", key, url)
		}
	}
	// ARI is deliberately absent: a client that does not find it falls back to
	// its own renewal timer, which is correct until RFC 9773 is implemented.
	if _, ok := directory["renewalInfo"]; ok {
		t.Error("the directory advertises renewalInfo, which is not implemented")
	}
	meta, ok := directory["meta"].(map[string]any)
	if !ok || meta["externalAccountRequired"] != true {
		t.Error("the directory does not tell clients that external account binding is required")
	}
}
