package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
)

func headerFor(t *testing.T, r *http.Request) http.Header {
	t.Helper()
	w := httptest.NewRecorder()
	SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	return w.Result().Header
}

func TestSecurityHeadersAreAlwaysSet(t *testing.T) {
	got := headerFor(t, httptest.NewRequest("GET", "/certificate-authorities", nil))
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": enforcedCSP,
	}
	for name, value := range want {
		if got.Get(name) != value {
			t.Errorf("%s = %q, want %q", name, got.Get(name), value)
		}
	}
	if got.Get("Content-Security-Policy-Report-Only") == "" {
		t.Error("the report-only policy was not sent")
	}
}

// TestSecurityHeadersSetOnErrorResponses covers why the headers are written
// before the handler runs: an error page is exactly where a sniffed content
// type or a framed response would matter most.
func TestSecurityHeadersSetOnErrorResponses(t *testing.T) {
	w := httptest.NewRecorder()
	SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	})).ServeHTTP(w, httptest.NewRequest("POST", "/certificates/issue", nil))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if w.Result().Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("an error response went out without the security headers")
	}
}

// TestHSTSOnlyOverASecureChannel keeps the header honest: asserting HSTS from a
// deployment whose TLS status cannot be established would be a claim this code
// has no evidence for.
func TestHSTSOnlyOverASecureChannel(t *testing.T) {
	if err := clientip.ConfigureTrustedProxies("10.0.0.0/8"); err != nil {
		t.Fatalf("ConfigureTrustedProxies: %v", err)
	}

	plain := httptest.NewRequest("GET", "/login", nil)
	plain.RemoteAddr = "10.0.0.5:8080"
	if got := headerFor(t, plain).Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS sent over a plaintext channel: %q", got)
	}

	// An untrusted peer claiming https must not earn the header either.
	spoofed := httptest.NewRequest("GET", "/login", nil)
	spoofed.RemoteAddr = "203.0.113.9:44321"
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	if got := headerFor(t, spoofed).Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS sent on an untrusted peer's say-so: %q", got)
	}

	forwarded := httptest.NewRequest("GET", "/login", nil)
	forwarded.RemoteAddr = "10.0.0.5:8080"
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	if headerFor(t, forwarded).Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing on a request the ingress forwarded as https")
	}

	direct := httptest.NewRequest("GET", "/login", nil)
	direct.TLS = &tls.ConnectionState{}
	if headerFor(t, direct).Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing on a direct TLS connection")
	}
}

// The dashboard is not meant to be findable. The header carries that on every
// response — including the CRLs, the QR image and the JSON, none of which can
// hold the meta tag view/layout/base.templ renders.
func TestNothingIsOfferedToASearchEngine(t *testing.T) {
	for _, path := range []string{"/login", "/", "/pki/org/ca/crl", "/security/totp/qr.png"} {
		got := headerFor(t, httptest.NewRequest("GET", path, nil)).Get("X-Robots-Tag")
		if got != "noindex, nofollow" {
			t.Errorf("%s: X-Robots-Tag = %q, want noindex", path, got)
		}
	}
}

// TestProtocolPathsSkipBrowserHeaders guards the interoperability fix: a
// minimal EST client (strongSwan's pki --est) carries a fixed-size response
// buffer sized for a plain PKCS#7 reply, and the browser-oriented headers
// below — the two CSP headers especially — are large enough on their own to
// overflow it, corrupting the certificate the server issued correctly.
func TestProtocolPathsSkipBrowserHeaders(t *testing.T) {
	for _, path := range []string{
		"/.well-known/est/e1/simpleenroll",
		"/scep/e1",
		"/scep/e1/pkiclient.exe",
		"/acme/e1/directory",
	} {
		got := headerFor(t, httptest.NewRequest("GET", path, nil))
		for _, name := range []string{
			"Content-Security-Policy", "Content-Security-Policy-Report-Only",
			"X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "X-Robots-Tag",
		} {
			if v := got.Get(name); v != "" {
				t.Errorf("%s: %s = %q, want unset on a device-facing protocol path", path, name, v)
			}
		}
	}

	// The dashboard and its JSON/API routes are untouched.
	if headerFor(t, httptest.NewRequest("GET", "/api/est/endpoints", nil)).Get("Content-Security-Policy") == "" {
		t.Error("/api/est/endpoints lost its security headers; only the device-facing operations should")
	}
}
