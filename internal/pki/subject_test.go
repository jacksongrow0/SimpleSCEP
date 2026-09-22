package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestBuildSubject(t *testing.T) {
	name, err := BuildSubject(SubjectInput{
		CommonName:         "Acme Root CA",
		Organization:       "Acme Inc",
		OrganizationalUnit: "IT",
		Country:            "us",
		Province:           "California",
		Locality:           "San Francisco",
	})
	if err != nil {
		t.Fatal(err)
	}
	if name.CommonName != "Acme Root CA" {
		t.Errorf("CommonName = %q", name.CommonName)
	}
	if len(name.Organization) != 1 || name.Organization[0] != "Acme Inc" {
		t.Errorf("Organization = %v", name.Organization)
	}
	if len(name.Country) != 1 || name.Country[0] != "US" {
		t.Errorf("Country = %v, want normalized [US]", name.Country)
	}
	if !strings.Contains(name.String(), "CN=Acme Root CA") {
		t.Errorf("DN string = %q", name.String())
	}
}

func TestBuildSubjectRejects(t *testing.T) {
	cases := []struct {
		name string
		in   SubjectInput
	}{
		{"missing CN", SubjectInput{Organization: "Acme"}},
		{"bad country", SubjectInput{CommonName: "x", Country: "USA"}},
		{"numeric country", SubjectInput{CommonName: "x", Country: "1A"}},
		{"control chars", SubjectInput{CommonName: "x\x00y"}},
		{"too long", SubjectInput{CommonName: strings.Repeat("a", 129)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildSubject(tc.in); err == nil {
				t.Fatalf("expected error for %+v", tc.in)
			}
		})
	}
}

func TestValidateEKUs(t *testing.T) {
	out, err := ValidateEKUs([]string{"server_auth", "client_auth", "server_auth"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0] != "server_auth" || out[1] != "client_auth" {
		t.Errorf("got %v, want deduped order-stable [server_auth client_auth]", out)
	}
	if out, err = ValidateEKUs(nil); err != nil || len(out) != 1 || out[0] != EKUClientAuth {
		t.Errorf("empty input: got %v, %v; want default [client_auth]", out, err)
	}
	if _, err = ValidateEKUs([]string{"any_extended_key_usage"}); err == nil {
		t.Error("expected error for unsupported EKU")
	}
	for _, token := range []string{
		EKUIPSECEndSystem, EKUIPSECTunnel, EKUIPSECUser, EKUTimeStamping,
		EKUOCSPSigning, EKUSmartcardLogon, EKUMacAddress,
	} {
		if _, err := ValidateEKUs([]string{token}); err != nil {
			t.Errorf("%s rejected: %v", token, err)
		}
	}
}

func TestValidateEKUsCustomOIDs(t *testing.T) {
	out, err := ValidateEKUs([]string{"1.3.6.1.4.1.311.20.2.2", " 1.2.840.113635.100.4.10 "})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0] != "1.3.6.1.4.1.311.20.2.2" || out[1] != "1.2.840.113635.100.4.10" {
		t.Errorf("got %v", out)
	}
	for _, bad := range []string{"3.2.1", "1", "1.a.2", "1.-2.3", "not an oid"} {
		if _, err := ValidateEKUs([]string{bad}); err == nil {
			t.Errorf("expected rejection for %q", bad)
		}
	}
}

func TestEKUsWithinParent(t *testing.T) {
	if err := ekusWithinParent([]string{"client_auth"}, "client_auth,server_auth"); err != nil {
		t.Errorf("subset rejected: %v", err)
	}
	if err := ekusWithinParent([]string{"time_stamping"}, "client_auth"); err == nil {
		t.Error("expected rejection outside parent profile")
	}
	if err := ekusWithinParent([]string{"anything"}, ""); err == nil {
		t.Error("empty parent profile should permit nothing")
	}
}

func TestValidateAlgorithm(t *testing.T) {
	if alg, err := ValidateAlgorithm(""); err != nil || alg != AlgorithmECDSAP256SHA256 {
		t.Errorf("empty: got %q, %v", alg, err)
	}
	for _, alg := range []string{AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384, AlgorithmRSA3072SHA256, AlgorithmRSA4096SHA256} {
		if _, err := ValidateAlgorithm(alg); err != nil {
			t.Errorf("%s rejected: %v", alg, err)
		}
	}
	if _, err := ValidateAlgorithm("RSA_SIGN_PKCS1_2048_SHA256"); err == nil {
		t.Error("expected error for RSA-2048")
	}
}

func TestValidityDays(t *testing.T) {
	if d, err := validityDays(CATypeRoot, 0); err != nil || d != DefaultRootDays {
		t.Errorf("root default: %d, %v", d, err)
	}
	if d, err := validityDays(CATypeIssuing, 0); err != nil || d != DefaultIssuingDays {
		t.Errorf("issuing default: %d, %v", d, err)
	}
	if _, err := validityDays(CATypeRoot, MaxValidityDays+1); err == nil {
		t.Error("expected error above max")
	}
	if _, err := validityDays(CATypeRoot, -1); err == nil {
		t.Error("expected error for negative days")
	}
}

func TestRejectPrivateKeyMaterial(t *testing.T) {
	pemKey := "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
	if err := rejectPrivateKeyMaterial("harmless", pemKey); err == nil {
		t.Error("expected private key to be rejected")
	}
	pkcs8 := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	if err := rejectPrivateKeyMaterial(pkcs8); err == nil {
		t.Error("expected PKCS#8 key to be rejected")
	}
	if err := rejectPrivateKeyMaterial("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"); err != nil {
		t.Errorf("certificate should pass: %v", err)
	}
}

func TestValidateLeafAlgorithm(t *testing.T) {
	if a, err := ValidateLeafAlgorithm(""); err != nil || a != LeafECP256 {
		t.Errorf("default: %q, %v", a, err)
	}
	for _, a := range []string{LeafRSA2048, LeafRSA3072, LeafRSA4096, LeafECP256, LeafECP384} {
		if got, err := ValidateLeafAlgorithm(a); err != nil || got != a {
			t.Errorf("%s: %q, %v", a, got, err)
		}
	}
	if _, err := ValidateLeafAlgorithm(AlgorithmECDSAP256SHA256); err == nil {
		t.Error("KMS algorithm tokens must be rejected for leaf keys")
	}
}

func TestLeafValidityDays(t *testing.T) {
	if d, err := leafValidityDays(0); err != nil || d != 365 {
		t.Errorf("default: %d, %v", d, err)
	}
	if d, err := leafValidityDays(MaxLeafValidityDays); err != nil || d != MaxLeafValidityDays {
		t.Errorf("max: %d, %v", d, err)
	}
	for _, bad := range []int{-1, MaxLeafValidityDays + 1} {
		if _, err := leafValidityDays(bad); err == nil {
			t.Errorf("expected error for %d days", bad)
		}
	}
}

func TestEKUSelection(t *testing.T) {
	profile := "server_auth,client_auth,code_signing"
	// Empty request with no required usage applies the full profile.
	if got, err := ekuSelection(nil, profile, ""); err != nil || strings.Join(got, ",") != profile {
		t.Errorf("full profile: %v, %v", got, err)
	}
	// A subset passes through.
	if got, err := ekuSelection([]string{"code_signing"}, profile, ""); err != nil || strings.Join(got, ",") != "code_signing" {
		t.Errorf("subset: %v, %v", got, err)
	}
	// The required usage is auto-included and deduplicated.
	if got, err := ekuSelection([]string{"code_signing", "server_auth"}, profile, "server_auth"); err != nil || strings.Join(got, ",") != "server_auth,code_signing" {
		t.Errorf("required: %v, %v", got, err)
	}
	// Empty request with a required usage yields just that usage.
	if got, err := ekuSelection(nil, profile, "server_auth"); err != nil || strings.Join(got, ",") != "server_auth" {
		t.Errorf("required only: %v, %v", got, err)
	}
	// Anything outside the CA profile fails closed — including the required
	// usage itself.
	if _, err := ekuSelection([]string{"time_stamping"}, profile, ""); err == nil {
		t.Error("expected out-of-profile rejection")
	}
	if _, err := ekuSelection(nil, "client_auth", "server_auth"); err == nil {
		t.Error("expected rejection when the CA profile lacks the required usage")
	}
	if _, err := ekuSelection([]string{"bogus"}, profile, ""); err == nil {
		t.Error("expected unknown token rejection")
	}
}

func TestGenerateLeafKeyRoundTrip(t *testing.T) {
	for _, a := range []string{LeafECP256, LeafECP384, LeafRSA2048} {
		key, keyPEM, err := GenerateLeafKey(a)
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		block, _ := pem.Decode([]byte(keyPEM))
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Fatalf("%s: bad PEM", a)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		if !publicKeysEqual(parsed.(crypto.Signer).Public(), key.Public()) {
			t.Errorf("%s: PEM does not round-trip to the same key", a)
		}
	}
}

// Key usage follows the purpose, not just the key type: a code-signing
// certificate has no key to establish, while S/MIME does — and an EC key
// establishes by agreement where an RSA key establishes by transport.
func TestLeafKeyUsageFollowsEKUAndKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		pub  crypto.PublicKey
		ekus []string
		want x509.KeyUsage
	}{
		"rsa client auth transports a key": {rsaKey.Public(), []string{EKUClientAuth},
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		"rsa code signing establishes nothing": {rsaKey.Public(), []string{EKUCodeSigning},
			x509.KeyUsageDigitalSignature},
		"rsa smime transports a key": {rsaKey.Public(), []string{EKUEmailProtection},
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		"ec smime agrees a key": {ecKey.Public(), []string{EKUEmailProtection},
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement},
		"ec client auth signs only": {ecKey.Public(), []string{EKUClientAuth},
			x509.KeyUsageDigitalSignature},
		"ec code signing signs only": {ecKey.Public(), []string{EKUCodeSigning},
			x509.KeyUsageDigitalSignature},
		"mixed takes the union": {rsaKey.Public(), []string{EKUCodeSigning, EKUClientAuth},
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		// A purpose this code cannot reason about keeps the old bits rather
		// than silently breaking a deployment that relied on them.
		"custom oid keeps encipherment": {rsaKey.Public(), []string{"1.3.6.1.4.1.99999.1"},
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		"custom oid on ec keeps agreement": {ecKey.Public(), []string{"1.3.6.1.4.1.99999.1"},
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement},
	} {
		t.Run(name, func(t *testing.T) {
			if got := leafKeyUsage(tc.pub, tc.ekus); got != tc.want {
				t.Fatalf("leafKeyUsage = %b, want %b", got, tc.want)
			}
		})
	}
}
