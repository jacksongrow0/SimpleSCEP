package est

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

// TestReenrollRefusesAnotherCredentialsSubject is the binding that stands in for
// the mutual-TLS proof RFC 7030 assumes.
//
// Before it, re-enrollment asked only whether the endpoint had ever issued this
// subject. Any holder of any live credential on the endpoint could therefore
// renew any subject it had issued, with a key of their own choosing — a weaker
// check than the /simpleenroll path it is meant to be narrower than.
func TestReenrollRefusesAnotherCredentialsSubject(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	e := repo.seedEndpoint()

	owner, _ := mustCredential(t, svc, e, CredentialSpec{Username: "owner"})
	intruder, _ := mustCredential(t, svc, e, CredentialSpec{Username: "intruder"})

	csr := testCSR(t, csrOptions{})
	subject := appPKI.RenderSubject(csr.RawSubject, csr.Subject)
	// The owner enrolled this subject and is inside the renewal window.
	repo.seedRenewable(e, owner, subject, time.Now().AddDate(0, 0, 10), "")

	_, _, err := svc.Reenroll(context.Background(), e, intruder, csr)
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("another credential renewed a subject it never enrolled: status = %d, want 403", statusOf(err))
	}
	if issuer.issued != 0 {
		t.Errorf("issued %d certificates, want 0", issuer.issued)
	}
	// The refusal must not distinguish "never enrolled" from "enrolled by
	// somebody else", or one credential holder learns what another has enrolled.
	if !strings.Contains(err.Error(), "no live certificate") {
		t.Errorf("error = %q, want the same answer as a subject that was never enrolled", err)
	}
}

// TestReenrollAcceptsARotatedCredentialWithTheSameUsername covers the second arm
// of the credential test. Revoking a credential and minting a replacement is
// routine; if that orphaned every renewal the credential had enrolled, rotating
// a secret would brick a fleet at its next renewal.
func TestReenrollAcceptsARotatedCredentialWithTheSameUsername(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	e := repo.seedEndpoint()

	old, _ := mustCredential(t, svc, e, CredentialSpec{Username: "gateway"})
	csr := testCSR(t, csrOptions{})
	subject := appPKI.RenderSubject(csr.RawSubject, csr.Subject)
	repo.seedRenewable(e, old, subject, time.Now().AddDate(0, 0, 10), "")

	// The operator rotates the secret: same username, new credential row.
	if err := svc.RevokeCredential(context.Background(), e.OrganizationID, e.ID, old.ID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	replacement, _ := mustCredential(t, svc, e, CredentialSpec{Username: "gateway"})

	if _, _, err := svc.Reenroll(context.Background(), e, replacement, csr); err != nil {
		t.Fatalf("a rotated credential could not renew what it enrolled: %v", err)
	}
	if issuer.issued != 1 {
		t.Errorf("issued %d certificates, want 1", issuer.issued)
	}
}

// TestReenrollKeyContinuity covers the opt-in hardening. With it on, the CSR
// must carry the same public key as the certificate being renewed — and since
// parseCSR has already verified the CSR's self-signature, that is a real proof
// the caller holds the key the live certificate was issued for.
func TestReenrollKeyContinuity(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	e := repo.seedEndpoint()
	e.ReenrollRequiresSameKey = true
	cred, _ := mustCredential(t, svc, e, CredentialSpec{Username: "gateway"})

	csr := testCSR(t, csrOptions{})
	subject := appPKI.RenderSubject(csr.RawSubject, csr.Subject)

	// A certificate for a different key: renewal must be refused.
	repo.seedRenewable(e, cred, subject, time.Now().AddDate(0, 0, 10), certificateForNewKey(t))
	_, _, err := svc.Reenroll(context.Background(), e, cred, csr)
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("a different key was accepted: status = %d, want 403", statusOf(err))
	}
	if !strings.Contains(err.Error(), "reuse the key") {
		t.Errorf("error = %q, want it to explain the key must be reused", err)
	}

	// The same key: accepted.
	repo.seedRenewable(e, cred, subject, time.Now().AddDate(0, 0, 10), certificateForKey(t, csr.PublicKey))
	if _, _, err := svc.Reenroll(context.Background(), e, cred, csr); err != nil {
		t.Fatalf("the certificate's own key was refused: %v", err)
	}
	if issuer.issued != 1 {
		t.Errorf("issued %d certificates, want 1", issuer.issued)
	}
}

// TestReenrollAllowsAKeyChangeByDefault pins the default. Rotating a key at
// renewal is normal EST behaviour, so continuity is opt-in rather than assumed.
func TestReenrollAllowsAKeyChangeByDefault(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{Username: "gateway"})

	csr := testCSR(t, csrOptions{})
	subject := appPKI.RenderSubject(csr.RawSubject, csr.Subject)
	repo.seedRenewable(e, cred, subject, time.Now().AddDate(0, 0, 10), certificateForNewKey(t))

	if _, _, err := svc.Reenroll(context.Background(), e, cred, csr); err != nil {
		t.Fatalf("a key rotation at renewal was refused by default: %v", err)
	}
}

// TestIdentifierPinCoversOtherNameSANs closes a gap the pin had: it read only
// DNSNames, IPAddresses and the CN, while pki copies the requested SAN DER into
// the issued certificate untouched. A credential pinned to one team's names
// could therefore still obtain a certificate carrying a userPrincipalName
// naming somebody else.
func TestIdentifierPinCoversOtherNameSANs(t *testing.T) {
	csr := upnCSR(t, "jacksongnav", "jacksongnav@l07n.onmicrosoft.com")
	cred := Credential{IdentifierPin: "jacksongnav"}

	err := checkIdentifierPin(cred, csr)
	if err == nil {
		t.Fatal("a UPN otherName outside the pin was accepted")
	}
	if !strings.Contains(err.Error(), "jacksongnav@l07n.onmicrosoft.com") {
		t.Errorf("error = %q, want it to name the refused UPN", err)
	}

	// Pinning the UPN itself alongside the CN admits the same request.
	permitted := Credential{IdentifierPin: "jacksongnav,jacksongnav@l07n.onmicrosoft.com"}
	if err := checkIdentifierPin(permitted, csr); err != nil {
		t.Errorf("a request wholly inside the pin was refused: %v", err)
	}
}

// upnCSR builds the request shape Intune sends: a userPrincipalName carried as
// an otherName SAN, which Go's x509 does not model and which pki copies into the
// issued certificate verbatim.
func upnCSR(t *testing.T, cn, upn string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := asn1.MarshalWithParams(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: mustMarshalAll(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: mustMarshalAll(t, asn1.RawValue{Class: asn1.ClassUniversal,
				Tag: asn1.TagUTF8String, Bytes: []byte(upn)}),
		}),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	sans, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal,
		Tag: asn1.TagSequence, IsCompound: true, Bytes: inner})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sans}},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func mustMarshalAll(t *testing.T, values ...any) []byte {
	t.Helper()
	var out []byte
	for _, v := range values {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
	}
	return out
}

// certificateForNewKey returns a certificate for a freshly generated key.
func certificateForNewKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return certificateForKey(t, key.Public())
}

// certificateForKey returns a self-signed certificate carrying pub, which is all
// samePublicKey reads.
func certificateForKey(t *testing.T, pub any) string {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "live"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
