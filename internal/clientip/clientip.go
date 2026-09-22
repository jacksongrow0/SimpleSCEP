package clientip

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// trustedProxies holds the networks whose forwarded headers are believed. It is
// written once at startup by ConfigureTrustedProxies and only read afterwards.
//
// Nothing else in this package may append to it: an empty list means no peer is
// trusted, which is the safe reading, and a request that arrives before startup
// finishes must not be luckier than one that arrives after.
var trustedProxies []*net.IPNet

// ConfigureTrustedProxies parses TRUSTED_PROXY_CIDRS into the set of peers whose
// CF-Connecting-IP, X-Forwarded-For and X-Forwarded-Proto headers are believed.
//
// Accepts comma-separated CIDR blocks or bare addresses, or the literal "none"
// for a deployment that genuinely faces the internet with no proxy in front. It
// is deliberately fatal for the caller on error rather than defaulting: the
// alternative is a deployment that silently ignores every forwarded header,
// which puts an entire fleet into one rate-limit bucket and makes EST refuse
// every enrollment. A loud failure at startup beats that.
func ConfigureTrustedProxies(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return errors.New(`TRUSTED_PROXY_CIDRS is required: list the networks the ingress connects from, or "none" if this service is reached directly`)
	}
	if strings.EqualFold(spec, "none") {
		trustedProxies = nil
		return nil
	}
	var nets []*net.IPNet
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// A bare address is accepted as a single-host network, because naming one
		// ingress address is the common case and writing /32 for it is a trap.
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return fmt.Errorf("TRUSTED_PROXY_CIDRS: %q is not an IP address or CIDR block", entry)
			}
			bits := 8 * net.IPv6len
			if ip.To4() != nil {
				bits = 8 * net.IPv4len
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, block, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("TRUSTED_PROXY_CIDRS: %q is not a CIDR block: %w", entry, err)
		}
		nets = append(nets, block)
	}
	if len(nets) == 0 {
		return errors.New(`TRUSTED_PROXY_CIDRS listed no usable entries; give CIDR blocks or "none"`)
	}
	trustedProxies = nets
	// Logged rather than left silent, because both ways of getting this wrong are
	// invisible at startup and expensive later. Too narrow — the common case, since
	// the peer is the ingress and not an address anyone thinks to look up — and
	// trustedPeer is false for every request: EST refuses every credential as
	// arriving over plaintext, HSTS is never sent, and every rate limiter collapses
	// into one bucket shared by the whole internet. Too wide and any caller can
	// name its own address. Neither reports itself; this line is what makes the
	// resolved value something a deploy log can be read for.
	log.Printf("trusting forwarded headers from %d proxy network(s): %s",
		len(nets), spec)
	return nil
}

// trustedPeer reports whether the immediate peer is one of the configured
// proxies. Only the peer address counts — it is the one part of a request no
// client can forge, because the TCP connection came from it.
func trustedPeer(r *http.Request) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return trustedIP(ip)
}

// trustedIP reports whether ip names one of the proxies in front of this
// service. Shared by trustedPeer, which asks it about the connecting peer, and
// forwardedFor, which asks it about each hop a forwarded header names.
func trustedIP(ip net.IP) bool {
	for _, block := range trustedProxies {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP identifies the caller behind the proxies that terminate TLS in front
// of this service.
//
// r.RemoteAddr alone is useless in production: it is the address of the last
// proxy hop, which is the same for every device in an organization's fleet. Rate
// limiting on it turns a per-caller budget into one bucket shared by everyone,
// so a fleet re-enrolling after an outage locks itself out while a single abuser
// is barely constrained.
//
// The forwarded headers are read only when the peer is a configured proxy. From
// anyone else they are ignored entirely: they are trivially forged, and this
// value is the key the rate limiters are built on, so believing them from an
// arbitrary caller would let one rotate the header per request and turn the
// limiter into decoration.
func ClientIP(r *http.Request) string {
	if trustedPeer(r) {
		// Cloudflare's own header is preferred where present: it carries the
		// original client and, unlike X-Forwarded-For, Cloudflare overwrites
		// rather than appends, so a value forged by the client cannot survive it.
		//
		// That holds only while every request reaches this service *through*
		// Cloudflare. A deployment that also answers on its origin hostname lets
		// a caller set this header itself and have the trusted ingress forward it
		// unchanged. The
		// origin has to be closed to anything but the CDN for this line to mean
		// what it says.
		if ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}
		if ip := forwardedFor(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// forwardedFor picks the caller out of an X-Forwarded-For chain, reading it from
// the right.
//
// The leftmost entry is the obvious choice and the wrong one. A proxy that
// *appends* — as many managed ingress products do, and as RFC 7239 assumes
// generally — leaves whatever the client sent sitting in front of the entry it
// added itself. So a caller sending `X-Forwarded-For: 198.51.100.7` arrives as
// `198.51.100.7, <real client>`, and taking the left-hand value hands the caller
// a rate-limit key and an audit-log actor address of its own choosing.
//
// Reading from the right instead: skip the entries that name our own proxies,
// because those are the hops we put there, and return the first one that does
// not. That entry was written by a trusted proxy about the peer it actually saw,
// which is the furthest left this can go and still be evidence rather than a
// claim.
//
// A malformed entry stops the walk rather than being skipped. Everything to the
// left of something unparseable was copied by a hop we cannot account for, so
// none of it is evidence either.
//
// Returns "" when the header is empty, unparseable, or names only trusted
// proxies — the caller then falls back to the peer address, which is always
// true even when it is not useful.
func forwardedFor(header string) string {
	entries := strings.Split(header, ",")
	for i := len(entries) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(entries[i])
		if entry == "" {
			continue
		}
		// Some proxies write [2001:db8::1]:443 rather than a bare address.
		if host, _, err := net.SplitHostPort(entry); err == nil {
			entry = host
		}
		ip := net.ParseIP(strings.Trim(entry, "[]"))
		if ip == nil {
			return ""
		}
		if trustedIP(ip) {
			continue
		}
		return ip.String()
	}
	return ""
}

// SecureChannel reports whether the request reached us over a confidential
// channel. RFC 7030 §3.2.3 permits HTTP Basic only over server-authenticated
// TLS, and an EST password is the one thing in that protocol worth stealing.
//
// TLS terminates at an ingress in every deployment of this service, so r.TLS is
// nil in production and the forwarded header is the only evidence there is.
// Believing it from an untrusted peer would let a client assert its own
// plaintext connection was secure simply by saying so, which is precisely the
// refusal this exists to make.
func SecureChannel(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !trustedPeer(r) {
		return false
	}
	// Chained proxies append, so the leftmost value is the original client's: a
	// client that reached the first hop over plaintext must not be rescued by a
	// later hop's https.
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}
