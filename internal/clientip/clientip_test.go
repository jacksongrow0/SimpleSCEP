package clientip

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

// trustProxies points the package at a proxy set for one test and restores the
// previous configuration afterwards, so tests cannot leak trust into each other
// through the package-level list.
func trustProxies(t *testing.T, spec string) {
	t.Helper()
	previous := trustedProxies
	t.Cleanup(func() { trustedProxies = previous })
	if err := ConfigureTrustedProxies(spec); err != nil {
		t.Fatalf("ConfigureTrustedProxies(%q): %v", spec, err)
	}
}

// TestClientIPPrefersTheOriginalCaller covers the reason this helper exists: in
// production every request arrives from the same proxy address, so keying a rate
// limiter on RemoteAddr would put a whole fleet in one bucket.
func TestClientIPPrefersTheOriginalCaller(t *testing.T) {
	cases := []struct {
		name   string
		cf     string
		xff    string
		remote string
		want   string
	}{
		{name: "direct", remote: "203.0.113.7:54321", want: "203.0.113.7"},
		{name: "cloudflare", cf: "198.51.100.4", xff: "198.51.100.4, 172.16.0.1",
			remote: "10.0.0.5:8080", want: "198.51.100.4"},
		// The header is read from the right. An appending ingress leaves whatever
		// the caller sent in front of the entry it wrote itself, so the rightmost
		// untrusted entry is the peer a proxy actually saw and everything left of
		// it is the caller talking about itself.
		{name: "forwarded single", xff: "198.51.100.4", remote: "10.0.0.5:8080", want: "198.51.100.4"},
		{name: "trusted hops skipped", xff: "198.51.100.4, 203.0.113.9, 10.0.0.2",
			remote: "10.0.0.5:8080", want: "198.51.100.4"},
		{name: "whitespace", xff: "  198.51.100.4 , 10.0.0.2 ", remote: "10.0.0.5:8080", want: "198.51.100.4"},
		// The entry before the rightmost was written by a hop we cannot account
		// for, so it is a claim rather than evidence and does not win.
		{name: "untrusted hop wins", xff: "198.51.100.4, 172.16.0.1, 10.0.0.2",
			remote: "10.0.0.5:8080", want: "172.16.0.1"},
		{name: "port-qualified entry", xff: "198.51.100.4, [2001:db8::1]:443, 10.0.0.2",
			remote: "10.0.0.5:8080", want: "2001:db8::1"},
		// Nothing left of an unparseable entry can be attributed to a hop either.
		{name: "malformed stops the walk", xff: "198.51.100.4, nonsense, 10.0.0.2",
			remote: "10.0.0.5:8080", want: "10.0.0.5"},
		{name: "only trusted hops", xff: "10.0.0.2, 203.0.113.9", remote: "10.0.0.5:8080", want: "10.0.0.5"},
		{name: "empty header ignored", xff: "", remote: "10.0.0.5:8080", want: "10.0.0.5"},
		{name: "blank chain ignored", xff: " , ", remote: "10.0.0.5:8080", want: "10.0.0.5"},
		// RemoteAddr is not always host:port — a unix socket has no port to split.
		{name: "portless remote", remote: "@", want: "@"},
	}
	trustProxies(t, "10.0.0.0/8,203.0.113.0/24")
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.cf != "" {
			r.Header.Set("CF-Connecting-IP", tc.cf)
		}
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := ClientIP(r); got != tc.want {
			t.Errorf("%s: ClientIP() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestClientIPDistinguishesCallersBehindOneProxy is the property the limiter
// depends on: two devices behind the same ingress must not share a bucket.
func TestClientIPDistinguishesCallersBehindOneProxy(t *testing.T) {
	trustProxies(t, "10.0.0.0/8")
	first := httptest.NewRequest("GET", "/", nil)
	first.RemoteAddr = "10.0.0.5:8080"
	first.Header.Set("CF-Connecting-IP", "198.51.100.4")

	second := httptest.NewRequest("GET", "/", nil)
	second.RemoteAddr = "10.0.0.5:8080"
	second.Header.Set("CF-Connecting-IP", "198.51.100.9")

	if ClientIP(first) == ClientIP(second) {
		t.Error("two devices behind one proxy share a rate-limit bucket")
	}
}

// TestClientIPIgnoresForwardedHeadersFromAnUntrustedPeer is the whole point of
// the allowlist. ClientIP is the key every rate limiter is built on, so a caller
// that can reach the port directly must not be able to mint a fresh bucket per
// request by rotating a header.
func TestClientIPIgnoresForwardedHeadersFromAnUntrustedPeer(t *testing.T) {
	trustProxies(t, "10.0.0.0/8")
	for _, header := range []string{"CF-Connecting-IP", "X-Forwarded-For"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.9:44321"
		r.Header.Set(header, "198.51.100.4")
		if got := ClientIP(r); got != "203.0.113.9" {
			t.Errorf("%s from an untrusted peer was believed: ClientIP() = %q, want the peer address", header, got)
		}
	}
}

// TestClientIPTrustsNobodyWhenConfiguredNone covers the deployment that faces
// the internet with no proxy: every header is a client's word for it.
func TestClientIPTrustsNobodyWhenConfiguredNone(t *testing.T) {
	trustProxies(t, "none")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:8080"
	r.Header.Set("X-Forwarded-For", "198.51.100.4")
	if got := ClientIP(r); got != "10.0.0.5" {
		t.Errorf("ClientIP() = %q, want the peer address when no proxy is trusted", got)
	}
}

func TestConfigureTrustedProxiesRefusesUnusableInput(t *testing.T) {
	previous := trustedProxies
	t.Cleanup(func() { trustedProxies = previous })
	// An empty value is refused rather than defaulted: silently trusting nobody
	// would put a whole fleet in one bucket and make EST refuse every enrollment.
	for _, spec := range []string{"", "   ", "not-an-ip", "10.0.0.0/33", "10.0.0.0/8,bogus", ","} {
		if err := ConfigureTrustedProxies(spec); err == nil {
			t.Errorf("ConfigureTrustedProxies(%q) accepted; want an error", spec)
		}
	}
}

func TestConfigureTrustedProxiesAcceptsBareAddressesAndBlocks(t *testing.T) {
	trustProxies(t, "10.0.0.5, 172.16.0.0/12, ::1")
	cases := map[string]bool{
		"10.0.0.5:1":     true,
		"10.0.0.6:1":     false,
		"172.16.4.9:1":   true,
		"[::1]:1":        true,
		"192.0.2.1:1":    false,
		"not-an-address": false,
	}
	for remote, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if got := trustedPeer(r); got != want {
			t.Errorf("trustedPeer(%q) = %v, want %v", remote, got, want)
		}
	}
}

// TestSecureChannelIgnoresAnUntrustedProxy guards the check that enforces "an
// EST Basic password only travels over TLS". A caller that can reach the port
// directly must not be able to assert its own plaintext hop was secure.
func TestSecureChannelIgnoresAnUntrustedProxy(t *testing.T) {
	trustProxies(t, "10.0.0.0/8")

	spoofed := httptest.NewRequest("POST", "/.well-known/est/x/simpleenroll", nil)
	spoofed.RemoteAddr = "203.0.113.9:44321"
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	if SecureChannel(spoofed) {
		t.Error("X-Forwarded-Proto from an untrusted peer was believed")
	}

	forwarded := httptest.NewRequest("POST", "/.well-known/est/x/simpleenroll", nil)
	forwarded.RemoteAddr = "10.0.0.5:8080"
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	if !SecureChannel(forwarded) {
		t.Error("X-Forwarded-Proto from the configured ingress was ignored")
	}

	// A real TLS connection needs no header and no trusted peer.
	direct := httptest.NewRequest("POST", "/.well-known/est/x/simpleenroll", nil)
	direct.RemoteAddr = "203.0.113.9:44321"
	direct.TLS = &tls.ConnectionState{}
	if !SecureChannel(direct) {
		t.Error("a direct TLS connection was not treated as secure")
	}
}

// TestClientIPIgnoresACallerSpoofingItsOwnAddress is the property the rate
// limiters and the audit log rest on.
//
// A managed ingress may append to a client-supplied X-Forwarded-For rather than
// replace it, so a caller can put any address it likes in front of the entry
// the ingress writes. Reading the header from the left handed that caller its own
// rate-limit key and its own actor address in the audit trail; reading from the
// right discards it.
func TestClientIPIgnoresACallerSpoofingItsOwnAddress(t *testing.T) {
	trustProxies(t, "10.0.0.0/8")
	const realCaller = "198.51.100.7"

	spoofed := httptest.NewRequest("GET", "/", nil)
	spoofed.RemoteAddr = "10.0.0.5:8080"
	// What the ingress produces from a caller that sent "X-Forwarded-For: 1.2.3.4".
	spoofed.Header.Set("X-Forwarded-For", "1.2.3.4, "+realCaller)

	if got := ClientIP(spoofed); got != realCaller {
		t.Errorf("a spoofed leading entry was believed: ClientIP() = %q, want %q", got, realCaller)
	}

	// And rotating the forged value must not mint a fresh rate-limit key.
	other := httptest.NewRequest("GET", "/", nil)
	other.RemoteAddr = "10.0.0.5:8080"
	other.Header.Set("X-Forwarded-For", "5.6.7.8, "+realCaller)
	if got := ClientIP(other); got != ClientIP(spoofed) {
		t.Errorf("rotating the forged entry changed the key: %q vs %q", got, ClientIP(spoofed))
	}
}
