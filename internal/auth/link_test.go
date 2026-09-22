package auth

import (
	"strings"
	"testing"
)

// A magic link is a bearer credential delivered by mail. Building it from the
// request's Host header let an attacker send a victim a working-looking login
// link on a domain they controlled, in a mail the victim had asked for and that
// arrived from the real sender. These tests pin the link to APP_URL so that
// cannot come back.
func TestLinkIsBuiltFromAppURL(t *testing.T) {
	h := Handler{appURL: "https://app.simplescep.com"}

	got, err := h.link("/auth/email", "tok en+/=")
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if want := "https://app.simplescep.com/auth/email?token=tok+en%2B%2F%3D"; got != want {
		t.Errorf("link = %q, want %q", got, want)
	}
}

func TestLinkKeepsTheConfiguredHostAndScheme(t *testing.T) {
	// APP_URL carrying a port and a path prefix must survive intact, and the
	// scheme must never be downgraded to match how the request arrived.
	h := Handler{appURL: "https://pki.example.com:8443"}

	got, err := h.link("/auth/invite", "abc")
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if !strings.HasPrefix(got, "https://pki.example.com:8443/auth/invite?") {
		t.Errorf("link = %q, want the configured host, port and scheme", got)
	}
}

func TestLinkRefusesAnUnusableAppURL(t *testing.T) {
	// Every caller abandons the send when this errors, so a misconfigured
	// deployment mails nothing rather than mailing a half-built link.
	for _, appURL := range []string{"", "app.simplescep.com", "ftp://app.simplescep.com", "https://", "://nope"} {
		h := Handler{appURL: appURL}
		if got, err := h.link("/auth/email", "abc"); err == nil {
			t.Errorf("APP_URL %q accepted, produced %q; want an error", appURL, got)
		}
	}
}
