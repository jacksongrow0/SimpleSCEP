package scep

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/smallstep/pkcs7"
	protocol "github.com/smallstep/scep"
)

func TestCryptoPolicy(t *testing.T) {
	if pkcs7.ContentEncryptionAlgorithm != pkcs7.EncryptionAlgorithmAES128CBC {
		t.Fatal("SCEP responses must use AES-128-CBC")
	}
	sha1, _ := asn1.Marshal(algorithmOIDs["sha1"])
	md5, _ := asn1.Marshal(algorithmOIDs["md5"])
	if err := cryptoPolicy([]byte("modern"), false); err != nil {
		t.Fatal(err)
	}
	if err := cryptoPolicy(sha1, false); err == nil {
		t.Fatal("SHA-1 must require legacy mode")
	}
	if err := cryptoPolicy(sha1, true); err != nil {
		t.Fatal("legacy mode should permit SHA-1")
	}
	if err := cryptoPolicy(md5, true); err == nil {
		t.Fatal("MD5 must always be rejected")
	}
}

func TestNamePolicyIncludesURISAN(t *testing.T) {
	u, _ := url.Parse("ID:JAMF:GUID:device-1")
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-1"}, URIs: []*url.URL{u}}
	e := Endpoint{SubjectPattern: `CN=device-[0-9]+`, SANPattern: `(?i)^id:JAMF:GUID:`}
	if err := validateNames(e, csr); err != nil {
		t.Fatal(err)
	}
	e.SANPattern = `^DNS:`
	if validateNames(e, csr) == nil {
		t.Fatal("mismatched SAN policy accepted")
	}
}

// testEndpoint is the endpoint the authorization tests enroll against. An
// organization may run several; these tests only need one.
var testEndpoint = Endpoint{ID: "endpoint-1", OrganizationID: "org-1", CAID: "ca-1", Name: "Corporate Wi-Fi",
	RenewalWindowDays: 30}

// testIntuneApp stands in for the deployed multi-tenant Entra application.
var testIntuneApp = IntuneApp{ClientID: "app-id", ClientSecret: "app-secret"}

func authorizeWith(t *testing.T, f *fakeStore, intune IntuneValidator, password string) (string, error) {
	t.Helper()
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-1"}}
	return Service{repo: f, intune: intune}.authorize(context.Background(), testEndpoint, pkiMessage(password), csr,
		[]string{appPKI.EKUClientAuth})
}

// pkiMessage builds the decrypted request shape authorize sees, where the
// challenge password lives on the embedded CSRReqMessage.
func pkiMessage(password string) *protocol.PKIMessage {
	msg := &protocol.PKIMessage{TransactionID: "tx-1",
		CSRReqMessage: &protocol.CSRReqMessage{ChallengePassword: password}}
	msg.MessageType = protocol.PKCSReq
	return msg
}

// seedChallenge stores a one-time challenge the way CreateChallenge does.
func seedChallenge(t *testing.T, f *fakeStore, secret string, c Challenge) {
	t.Helper()
	hash, err := enroll.HashSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	c.ID, c.SecretHash = uuid.NewString(), hash
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = time.Now().Add(15 * time.Minute)
	}
	lookup := sha256.Sum256([]byte(secret))
	if err := f.CreateChallenge(context.Background(), c, lookup[:]); err != nil {
		t.Fatal(err)
	}
}

// A single endpoint serves every enrollment source, so the presented password
// alone has to select the method that applies.
func TestAuthorizeResolvesMethodByChallengePassword(t *testing.T) {
	f := newFakeStore()
	f.enable(AuthOneTime, AuthMethod{})
	staticHash, err := enroll.HashSecret("shared-secret")
	if err != nil {
		t.Fatal(err)
	}
	f.enable(AuthStatic, AuthMethod{SecretHash: staticHash})
	seedChallenge(t, f, "one-time-secret", Challenge{})

	got, err := authorizeWith(t, f, nil, "one-time-secret")
	if err != nil || got != AuthOneTime {
		t.Fatalf("one-time challenge: got %q, %v", got, err)
	}
	if len(f.usedIDs) != 1 {
		t.Fatalf("one-time challenge should be consumed exactly once, got %d", len(f.usedIDs))
	}
	got, err = authorizeWith(t, f, nil, "shared-secret")
	if err != nil || got != AuthStatic {
		t.Fatalf("shared secret: got %q, %v", got, err)
	}
	if len(f.usedIDs) != 1 {
		t.Fatal("shared secret enrollment must not consume a one-time challenge")
	}
}

// An Intune-issued password matches no local record, so it must fall through to
// Intune rather than being rejected outright.
func TestAuthorizeFallsThroughToIntune(t *testing.T) {
	f := newFakeStore()
	f.enable(AuthOneTime, AuthMethod{})
	keys := appPKI.NewFakeProvider()
	f.enable(AuthIntune, AuthMethod{IntuneConnected: true})
	f.tenant = "tenant"
	seedChallenge(t, f, "one-time-secret", Challenge{})
	intune := &stubIntune{}

	got, err := Service{repo: f, intune: intune, keys: keys, intuneApp: testIntuneApp}.authorize(context.Background(), testEndpoint,
		pkiMessage("intune-issued-blob"), &x509.CertificateRequest{}, []string{appPKI.EKUClientAuth})
	if err != nil || got != AuthIntune {
		t.Fatalf("intune: got %q, %v", got, err)
	}
	if intune.calls != 1 {
		t.Fatalf("Intune should be called once, got %d", intune.calls)
	}
	if len(f.usedIDs) != 0 {
		t.Fatal("a password Intune validated must not consume a one-time challenge")
	}
}

// A bad password with every method on must be rejected without side effects.
func TestAuthorizeRejectsUnknownPasswordWithoutConsumingState(t *testing.T) {
	f := newFakeStore()
	f.enable(AuthOneTime, AuthMethod{})
	staticHash, err := enroll.HashSecret("shared-secret")
	if err != nil {
		t.Fatal(err)
	}
	f.enable(AuthStatic, AuthMethod{SecretHash: staticHash})
	f.enable(AuthJamf, AuthMethod{Username: "jamf", PasswordHash: staticHash})
	seedChallenge(t, f, "one-time-secret", Challenge{})

	if _, err := authorizeWith(t, f, nil, "not-a-real-password"); err == nil {
		t.Fatal("unknown password accepted")
	}
	if len(f.usedIDs) != 0 {
		t.Fatal("a rejected enrollment must not consume a one-time challenge")
	}
}

func TestAuthorizeRejectsWhenNoMethodIsEnabled(t *testing.T) {
	f := newFakeStore()
	if err := f.SeedAuthMethods(context.Background(), testEndpoint); err != nil {
		t.Fatal(err)
	}
	_, err := authorizeWith(t, f, nil, "anything")
	if err == nil || !strings.Contains(err.Error(), "no enrollment authentication method") {
		t.Fatalf("expected a no-method-enabled error, got %v", err)
	}
}

func TestAuthorizeRejectsExpiredAndUsedChallenges(t *testing.T) {
	used := time.Now().Add(-time.Minute)
	for name, challenge := range map[string]Challenge{
		"expired": {ExpiresAt: time.Now().Add(-time.Minute)},
		"used":    {UsedAt: &used},
	} {
		f := newFakeStore()
		f.enable(AuthOneTime, AuthMethod{})
		seedChallenge(t, f, "one-time-secret", challenge)
		if _, err := authorizeWith(t, f, nil, "one-time-secret"); err == nil {
			t.Fatalf("%s challenge accepted", name)
		}
	}
}

// The challenge can pin the CSR it authorizes, so a swapped subject is refused.
func TestAuthorizeEnforcesChallengeSubjectBinding(t *testing.T) {
	f := newFakeStore()
	f.enable(AuthOneTime, AuthMethod{})
	seedChallenge(t, f, "one-time-secret", Challenge{ExpectedSubject: "CN=laptop-01"})
	if _, err := authorizeWith(t, f, nil, "one-time-secret"); err == nil {
		t.Fatal("challenge bound to a different subject was accepted")
	}
	if len(f.usedIDs) != 0 {
		t.Fatal("a subject mismatch must not consume the challenge")
	}
}

// A challenge pinned to S/MIME must not authorize a client-auth enrollment, and
// a mismatch must not burn the challenge.
func TestAuthorizeEnforcesChallengeEKUBinding(t *testing.T) {
	f := newFakeStore()
	f.enable(AuthOneTime, AuthMethod{})
	seedChallenge(t, f, "one-time-secret", Challenge{ExpectedEKUs: appPKI.EKUEmailProtection})
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-1"}}
	svc := Service{repo: f}
	if _, err := svc.authorize(context.Background(), testEndpoint, pkiMessage("one-time-secret"), csr,
		[]string{appPKI.EKUClientAuth}); err == nil {
		t.Fatal("a challenge pinned to S/MIME authorized a client-auth enrollment")
	}
	if len(f.usedIDs) != 0 {
		t.Fatal("a usage mismatch must not consume the challenge")
	}
	got, err := svc.authorize(context.Background(), testEndpoint, pkiMessage("one-time-secret"), csr,
		[]string{appPKI.EKUEmailProtection})
	if err != nil || got != AuthOneTime {
		t.Fatalf("matching usages: got %q, %v", got, err)
	}
}

// The Entra directory belongs to the organization, so an endpoint whose own
// intune row was never seeded still reports the method configured. Synthesized
// rows carry no connection of their own, which is exactly where this can break.
func TestAuthMethodsCarriesOrganizationIntuneConnection(t *testing.T) {
	f := newFakeStore()
	f.tenant = "tenant-1"
	methods, err := Service{repo: f}.AuthMethods(context.Background(), testEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range methods {
		if m.Method != AuthIntune {
			continue
		}
		if !m.Configured() {
			t.Fatal("an unseeded intune method must report configured when the organization is connected")
		}
		return
	}
	t.Fatal("intune method was not rendered")
}

// Disconnecting is organization-wide, so every endpoint that was enrolling
// through the directory must stop; leaving one on would advertise a method that
// can no longer authorize anything.
func TestDisconnectIntuneTurnsTheMethodOff(t *testing.T) {
	f := newFakeStore()
	ctx := context.Background()
	svc := Service{repo: f}
	if err := svc.ConnectIntune(ctx, testEndpoint.OrganizationID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if connected, _ := f.IntuneConnected(ctx, testEndpoint.OrganizationID); !connected {
		t.Fatal("connect did not record the tenant")
	}
	if err := svc.DisconnectIntune(ctx, testEndpoint.OrganizationID); err != nil {
		t.Fatal(err)
	}
	if connected, _ := f.IntuneConnected(ctx, testEndpoint.OrganizationID); connected {
		t.Fatal("disconnect left the tenant connected")
	}
	if m := f.methods[AuthIntune]; m.Enabled || m.Configured() {
		t.Fatalf("disconnect left the method usable: enabled=%t configured=%t", m.Enabled, m.Configured())
	}
}

// A tenant that is not a directory ID is Microsoft misbehaving or a tampered
// callback; either way it must never be stored.
func TestConnectIntuneRejectsNonUUIDTenant(t *testing.T) {
	f := newFakeStore()
	if err := (Service{repo: f}).ConnectIntune(context.Background(), "org-1", "not-a-directory"); err == nil {
		t.Fatal("a non-UUID tenant was accepted")
	}
	if f.tenant != "" {
		t.Fatal("a rejected tenant must not be stored")
	}
}

func TestSetMethodEnabledRequiresConfiguration(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		method  string
		stored  AuthMethod
		intune  IntuneValidator
		wantErr string
	}{
		"static without a secret": {method: AuthStatic, wantErr: "the shared secret"},
		"intune without a connected tenant": {method: AuthIntune, intune: &stubIntune{},
			wantErr: "Microsoft Intune"},
		"jamf without one-time challenges": {method: AuthJamf,
			stored:  AuthMethod{Username: "jamf", PasswordHash: "hash"},
			intune:  &stubIntune{},
			wantErr: "one-time challenges"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeStore()
			if err := f.SeedAuthMethods(ctx, testEndpoint); err != nil {
				t.Fatal(err)
			}
			tc.stored.Method = tc.method
			f.methods[tc.method] = tc.stored
			err := Service{repo: f, intune: tc.intune}.SetMethodEnabled(ctx, testEndpoint, tc.method, true)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want an error containing %q, got %v", tc.wantErr, err)
			}
			if f.methods[tc.method].Enabled {
				t.Fatal("method was enabled despite the precondition failing")
			}
		})
	}
}

// Jamf enrolls with one-time challenges, so that method cannot be pulled out
// from under it.
func TestSetMethodEnabledKeepsJamfDependency(t *testing.T) {
	ctx := context.Background()
	f := newFakeStore()
	if err := f.SeedAuthMethods(ctx, testEndpoint); err != nil {
		t.Fatal(err)
	}
	f.enable(AuthOneTime, AuthMethod{})
	f.enable(AuthJamf, AuthMethod{Username: "jamf", PasswordHash: "hash"})
	s := Service{repo: f}
	if err := s.SetMethodEnabled(ctx, testEndpoint, AuthOneTime, false); err == nil {
		t.Fatal("disabling one-time challenges under an active Jamf connection was allowed")
	}
	if err := s.SetMethodEnabled(ctx, testEndpoint, AuthJamf, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMethodEnabled(ctx, testEndpoint, AuthOneTime, false); err != nil {
		t.Fatal(err)
	}
}

func TestSetMethodEnabledRejectsUnknownMethod(t *testing.T) {
	if err := (Service{repo: newFakeStore()}).SetMethodEnabled(context.Background(), testEndpoint, "ldap", true); err == nil {
		t.Fatal("unknown method accepted")
	}
}

// createEndpoint drives the service with a fake issuer so RA issuance is
// exercised without a KMS.
func createEndpoint(t *testing.T, f *fakeStore, name string) (Endpoint, error) {
	t.Helper()
	svc := Service{repo: f, keys: appPKI.NewFakeProvider(), pki: &fakeIssuer{}}
	return svc.CreateEndpoint(context.Background(), CreateEndpointRequest{OrgID: "org-1", UserID: "user-1",
		CAID: "ca-1", Name: name})
}

func TestCreateEndpointRequiresIssuingCA(t *testing.T) {
	f := newFakeStore()
	svc := Service{repo: f, keys: appPKI.NewFakeProvider(), pki: &fakeIssuer{}}
	_, err := svc.CreateEndpoint(context.Background(),
		CreateEndpointRequest{OrgID: "org-1", UserID: "user-1", CAID: "  ", Name: "Wi-Fi"})
	if err == nil {
		t.Fatal("endpoint created without an issuing CA")
	}
	if f.createdRAs != 0 {
		t.Fatal("a rejected request must not mint an RA keypair")
	}
}

func TestCreateEndpointValidatesName(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":             "",
		"whitespace only":   "   ",
		"too long":          strings.Repeat("a", 65),
		"control character": "Wi-Fi\x00",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeStore()
			if _, err := createEndpoint(t, f, raw); err == nil {
				t.Fatalf("name %q was accepted", raw)
			}
			if f.createdRAs != 0 {
				t.Fatal("a rejected name must not mint an RA keypair")
			}
		})
	}
	// A name at the boundary, and one needing trimming, are both fine.
	f := newFakeStore()
	e, err := createEndpoint(t, f, "  Corporate Wi-Fi  ")
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "Corporate Wi-Fi" {
		t.Fatalf("name = %q, want it trimmed", e.Name)
	}
}

func TestCreateEndpointRejectsDuplicateName(t *testing.T) {
	f := newFakeStore()
	if _, err := createEndpoint(t, f, "Corporate Wi-Fi"); err != nil {
		t.Fatal(err)
	}
	// Names collide case-insensitively, matching the unique index.
	if _, err := createEndpoint(t, f, "corporate wi-fi"); err == nil {
		t.Fatal("a case-different duplicate name was accepted")
	}
	if f.createdRAs != 1 {
		t.Fatal("a duplicate name must be caught before the RA keypair is minted")
	}
}

// An endpoint is deletable whether or not it has issued. The consequences are
// real but they are the administrator's to accept, so they are surfaced by the
// delete dialog and gated on typing the name rather than refused outright.
func TestDeleteEndpointSucceedsRegardlessOfIssuance(t *testing.T) {
	ctx := context.Background()
	svc := Service{repo: nil}
	for name, issued := range map[string]bool{"never issued": false, "has issued": true} {
		t.Run(name, func(t *testing.T) {
			f := newFakeStore()
			svc.repo = f
			e, err := createEndpoint(t, f, "Corporate Wi-Fi")
			if err != nil {
				t.Fatal(err)
			}
			if issued {
				f.issuedBy["cert-1"] = e.ID
			}
			if err := svc.DeleteEndpoint(ctx, "org-1", e.ID); err != nil {
				t.Fatalf("delete failed: %v", err)
			}
			if _, err := f.EndpointByID(ctx, "org-1", e.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("the endpoint survived deletion, got %v", err)
			}
		})
	}
}

// The count behind the dialog's warning has to reflect what the endpoint
// actually issued, or the number an administrator is shown is meaningless.
func TestLiveCertificateCountIsPerEndpoint(t *testing.T) {
	f := newFakeStore()
	mine, err := createEndpoint(t, f, "Mine")
	if err != nil {
		t.Fatal(err)
	}
	other, err := createEndpoint(t, f, "Other")
	if err != nil {
		t.Fatal(err)
	}
	f.issuedBy["cert-1"] = mine.ID
	f.issuedBy["cert-2"] = mine.ID
	f.issuedBy["cert-3"] = other.ID
	ctx := context.Background()
	if n, _ := f.LiveCertificateCount(ctx, mine.ID); n != 2 {
		t.Fatalf("count for the endpoint = %d, want 2", n)
	}
	if n, _ := f.LiveCertificateCount(ctx, other.ID); n != 1 {
		t.Fatalf("count for the sibling = %d, want 1", n)
	}
}

func TestAuthMethodConfigured(t *testing.T) {
	for name, tc := range map[string]struct {
		method AuthMethod
		want   bool
	}{
		"one-time needs nothing": {AuthMethod{Method: AuthOneTime}, true},
		"static needs a secret":  {AuthMethod{Method: AuthStatic}, false},
		"static with a secret":   {AuthMethod{Method: AuthStatic, SecretHash: "h"}, true},
		"intune needs a tenant":  {AuthMethod{Method: AuthIntune}, false},
		"intune with a tenant":   {AuthMethod{Method: AuthIntune, IntuneConnected: true}, true},
		"jamf needs both":        {AuthMethod{Method: AuthJamf, Username: "u"}, false},
		"jamf complete":          {AuthMethod{Method: AuthJamf, Username: "u", PasswordHash: "h"}, true},
		"unknown is never":       {AuthMethod{Method: "ldap"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.method.Configured(); got != tc.want {
				t.Fatalf("Configured() = %t, want %t", got, tc.want)
			}
		})
	}
}

// selfSigned mints a certificate over its own fresh key, the way a SCEP client
// wraps a request.
func selfSigned(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// Windows signs a PKCSReq with a throwaway "CN=SCEP Protocol Certificate"
// keypair that is not the key in the CSR, contrary to RFC 8894 3.2.1. Rejecting
// that shape refuses every Intune enrollment, so PKIOperation deliberately does
// not compare the two keys. What must keep holding is that the PKCS#10
// self-signature still proves possession of the key being certified.
func TestWindowsPKCSReqSignsWithASeparateKey(t *testing.T) {
	raCert, raKey := selfSigned(t, "SimpleSCEP RA")
	signerCert, signerKey := selfSigned(t, "SCEP Protocol Certificate")

	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "jacksongnav"}}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	request, err := protocol.NewCSRRequest(csr, &protocol.PKIMessage{
		MessageType: protocol.PKCSReq, Recipients: []*x509.Certificate{raCert},
		SignerCert: signerCert, SignerKey: signerKey})
	if err != nil {
		t.Fatal(err)
	}

	// Exactly what PKIOperation does before it decides.
	msg, err := protocol.ParsePKIMessage(request.Raw)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := pkcs7.Parse(request.Raw)
	if err != nil {
		t.Fatal(err)
	}
	msg.SignerCert = outer.GetOnlySigner()
	if err := msg.DecryptPKIEnvelope(raCert, raKey); err != nil {
		t.Fatal(err)
	}

	if msg.SignerCert == nil {
		t.Fatal("a request with no readable signer must still be rejected")
	}
	if msg.SignerCert.Subject.CommonName != "SCEP Protocol Certificate" {
		t.Fatalf("signer subject = %q", msg.SignerCert.Subject.CommonName)
	}
	signerDER, _ := x509.MarshalPKIXPublicKey(msg.SignerCert.PublicKey)
	csrDERKey, _ := x509.MarshalPKIXPublicKey(msg.CSR.PublicKey)
	if bytes.Equal(signerDER, csrDERKey) {
		t.Fatal("this test is meant to cover a signer key that differs from the CSR key")
	}
	// The property the relaxed check relies on.
	if err := msg.CSR.CheckSignature(); err != nil {
		t.Fatalf("CSR self-signature must still prove possession: %v", err)
	}
}

// oidEmailAddress is the emailAddress RDN. pkix.Name has no field for it, which
// is the whole point of the test below.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// parsedCSR round-trips a request through DER, which is what a device actually
// sends. The round trip matters: on the way back, every RDN pkix.Name does not
// model lands in Subject.Names and nothing else, so Subject.String() stops
// rendering it while RawSubject still carries it.
func parsedCSR(t *testing.T, tmpl *x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
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

// TestSubjectPolicyReadsTheDERThatGetsIssued covers a subject smuggled past the
// policy in an RDN Go does not model.
//
// The check used to be run against csr.Subject.String(), which renders only the
// attributes pkix.Name has fields for. pki issues template.RawSubject — the
// request's DER, untouched — so an emailAddress RDN was invisible to the policy
// and present in the certificate. A relying party doing S/MIME or subject-based
// identity mapping then sees a name the endpoint never agreed to.
func TestSubjectPolicyReadsTheDERThatGetsIssued(t *testing.T) {
	csr := parsedCSR(t, &x509.CertificateRequest{Subject: pkix.Name{
		CommonName: "device-7",
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidEmailAddress, Value: "ceo@corp.example.com"}},
	}})

	// The premise. If Go ever starts rendering this, the test below stops testing
	// anything and should be rewritten rather than deleted.
	if strings.Contains(csr.Subject.String(), "ceo@corp.example.com") {
		t.Skip("pkix.Name.String now renders emailAddress; this smuggling route is closed")
	}
	if !strings.Contains(appPKI.RenderSubject(csr.RawSubject, csr.Subject), "ceo@corp.example.com") {
		t.Fatal("RenderSubject does not read the RDN out of the DER; the test cannot detect the bypass")
	}

	e := Endpoint{SubjectPattern: `^CN=device-\d+$`}
	if err := validateNames(e, csr); err == nil {
		t.Error("a subject carrying an unpoliced emailAddress RDN was accepted")
	}
	// The same policy still accepts the subject it was written for.
	plain := parsedCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-7"}})
	if err := validateNames(e, plain); err != nil {
		t.Errorf("the conforming subject was refused: %v", err)
	}
}

// TestRenewalIsBoundToTheCertificateItRenews is the escalation path.
//
// authorize proves the signer certificate is live, unexpired, issued by this
// endpoint and inside its renewal window, and no challenge password is asked for
// on that path. So without this binding, a key lifted from one enrolled device
// was a credential for any identity the CA vouches for — and the endpoint policy
// is no backstop, because a new endpoint's default subject pattern is ".+".
func TestRenewalIsBoundToTheCertificateItRenews(t *testing.T) {
	held := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "laptop-01"},
		DNSNames: []string{"laptop-01.corp.example.com"},
	}

	same := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "laptop-01"},
		DNSNames: []string{"laptop-01.corp.example.com"},
	}
	if err := sameNames(held, same); err != nil {
		t.Fatalf("renewing the same identity was refused: %v", err)
	}

	elevated := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ceo@corp.example.com"}}
	if err := sameNames(held, elevated); err == nil {
		t.Error("a renewal naming a different subject was accepted")
	}

	extraSAN := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "laptop-01"},
		DNSNames: []string{"laptop-01.corp.example.com", "vpn.corp.example.com"},
	}
	if err := sameNames(held, extraSAN); err == nil {
		t.Error("a renewal claiming a subject alternative name the certificate does not hold was accepted")
	}

	// Dropping a name gives up authority rather than acquiring it, so it is
	// allowed: a device that stops claiming a name is not the case this guards.
	fewer := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "laptop-01"}}
	if err := sameNames(held, fewer); err != nil {
		t.Errorf("a renewal dropping a subject alternative name was refused: %v", err)
	}
}

// upnSAN builds the subjectAltName extension Intune sends: a userPrincipalName
// carried as an otherName, which Go's x509 does not model and which pki copies
// into the issued certificate verbatim.
func upnSAN(t *testing.T, upn string) pkix.Extension {
	t.Helper()
	marshal := func(vals ...any) []byte {
		var out []byte
		for _, v := range vals {
			b, err := asn1.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, b...)
		}
		return out
	}
	inner := marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: marshal(asn1.RawValue{Class: asn1.ClassUniversal,
				Tag: asn1.TagUTF8String, Bytes: []byte(upn)}),
		}),
	})
	return pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: marshal(asn1.RawValue{Class: asn1.ClassUniversal,
			Tag: asn1.TagSequence, IsCompound: true, Bytes: inner}),
	}
}

// TestRenewalComparesOtherNames pins the form that matters most in practice.
// Intune populates a userPrincipalName otherName from {{UserPrincipalName}}, and
// it is the name an attacker would want to change: x509 does not parse it, so a
// comparison reading only DNSNames would be blind to it moving.
func TestRenewalComparesOtherNames(t *testing.T) {
	held := &x509.Certificate{
		Subject:    pkix.Name{CommonName: "laptop-01"},
		Extensions: []pkix.Extension{upnSAN(t, "user@corp.example.com")},
	}
	if len(certSANNames(held)) == 0 {
		t.Fatal("certSANNames does not enumerate otherName forms; the comparison would be blind to them")
	}

	elevated := &x509.CertificateRequest{
		Subject:    pkix.Name{CommonName: "laptop-01"},
		Extensions: []pkix.Extension{upnSAN(t, "admin@corp.example.com")},
	}
	if err := sameNames(held, elevated); err == nil {
		t.Error("a renewal swapping the userPrincipalName was accepted")
	}

	unchanged := &x509.CertificateRequest{
		Subject:    pkix.Name{CommonName: "laptop-01"},
		Extensions: []pkix.Extension{upnSAN(t, "user@corp.example.com")},
	}
	if err := sameNames(held, unchanged); err != nil {
		t.Errorf("a renewal keeping the same userPrincipalName was refused: %v", err)
	}
}
