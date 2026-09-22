package est

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
)

// trustTestProxy believes the address httptest.NewRequest gives every request,
// standing in for the ingress. Without it the forwarded header is ignored by
// design, which is what TestSecureChannelIgnoresAnUntrustedProxy covers in the
// middleware package.
func trustTestProxy(t *testing.T) {
	t.Helper()
	if err := clientip.ConfigureTrustedProxies("192.0.2.1"); err != nil {
		t.Fatalf("ConfigureTrustedProxies: %v", err)
	}
}

// TestSecureChannel covers the deployments this service actually runs in. Every
// one of them terminates TLS ahead of the process, so the header is the only
// evidence available and getting its parsing wrong either leaks passwords or
// refuses every enrollment.
func TestSecureChannel(t *testing.T) {
	trustTestProxy(t)
	cases := []struct {
		name  string
		proto string
		tls   bool
		want  bool
	}{
		{name: "direct TLS", tls: true, want: true},
		{name: "managed ingress", proto: "https", want: true},
		{name: "cloudflare in front of the ingress", proto: "https, https", want: true},
		{name: "mixed chain keeps the client's scheme", proto: "https, http", want: true},
		{name: "case insensitive", proto: "HTTPS", want: true},
		{name: "whitespace", proto: "  https ", want: true},
		// The cases that must refuse: a plain-HTTP hop anywhere in front of us,
		// or no proxy at all.
		{name: "plaintext hop", proto: "http", want: false},
		{name: "no header at all", want: false},
		{name: "client downgraded first entry", proto: "http, https", want: false},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", "/.well-known/est/x/simpleenroll", nil)
		if tc.proto != "" {
			r.Header.Set("X-Forwarded-Proto", tc.proto)
		}
		if tc.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if got := secureChannel(r); got != tc.want {
			t.Errorf("%s: secureChannel() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestSecureChannelIgnoresTheRequestURLScheme guards a plausible mistake: an
// https URL in the request line says nothing about the connection the request
// actually arrived on.
func TestSecureChannelIgnoresTheRequestURLScheme(t *testing.T) {
	trustTestProxy(t)
	r := httptest.NewRequest("POST", "https://pki.example.test/.well-known/est/x/simpleenroll", nil)
	r.TLS = nil
	if secureChannel(r) {
		t.Error("an https request URL was mistaken for an https connection")
	}
}
