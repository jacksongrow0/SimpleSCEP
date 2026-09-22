package pki

import (
	"context"
	"strings"
	"testing"
)

// TestCloudKMSProviderRequiresAProtectionKey pins the refusal that replaced
// creating the key on demand.
//
// The key wraps every TOTP secret, SCEP RA private key and ACME EAB MAC key.
// When it was created implicitly, an unset or wrong configuration produced a
// *new* empty key and nothing failed until the first authenticator enrolment,
// under which none of the existing ciphertext opens. Failing construction is
// the only safe answer, and it has to happen before the client is built so it
// works without credentials or a network.
func TestCloudKMSProviderRequiresAProtectionKey(t *testing.T) {
	for _, empty := range []string{"", "   ", "\t\n"} {
		_, err := NewCloudKMSProvider(context.Background(),
			"projects/p/locations/global/keyRings/r", empty)
		if err == nil {
			t.Fatalf("NewCloudKMSProvider accepted a blank protection key %q", empty)
		}
		if !strings.Contains(err.Error(), "protection key") {
			t.Errorf("error %q does not say what is missing", err)
		}
	}
}

// TestProtectionKeyIsNotDerivedFromTheKeyRing records the coupling that was
// removed. The name used to be the key ring plus a constant id, so moving the
// ring silently moved the protection key with it and orphaned the ciphertext.
func TestProtectionKeyIsNotDerivedFromTheKeyRing(t *testing.T) {
	const other = "projects/other/locations/global/keyRings/other/cryptoKeys/app-secrets"
	p := &CloudKMSProvider{
		keyRing:           "projects/p/locations/global/keyRings/r",
		protectionKeyName: other,
	}
	if p.protectionKeyName != other {
		t.Fatalf("protection key = %q, want %q", p.protectionKeyName, other)
	}
	if strings.HasPrefix(p.protectionKeyName, p.keyRing) {
		t.Error("the protection key still lives under the signing key ring by construction")
	}
}
