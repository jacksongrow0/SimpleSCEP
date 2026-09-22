package auth

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

func TestWebAuthnPrefersDiscoverableCredentials(t *testing.T) {
	wa, err := NewWebAuthn("https://pki.example.com")
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	options, _, err := wa.BeginRegistration(webAuthnUser{
		id:    uuid.New(),
		email: "person@example.com",
	})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	selection := options.Response.AuthenticatorSelection
	if got := selection.ResidentKey; got != protocol.ResidentKeyRequirementPreferred {
		t.Errorf("resident key requirement = %q, want %q", got, protocol.ResidentKeyRequirementPreferred)
	}
	if got := selection.AuthenticatorAttachment; got != "" {
		t.Errorf("authenticator attachment = %q, want no restriction", got)
	}
}
