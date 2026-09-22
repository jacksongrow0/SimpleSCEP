package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// csrWithKey builds a CSR for an arbitrary key, so the profile tests can probe
// key strength without going through GenerateLeafKey's own allowlist.
func csrWithKey(t *testing.T, key any, cn string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// issuingUnder builds a root and an issuing CA, which is the shape every leaf
// in these tests is signed under.
func issuingUnder(t *testing.T, svc Service, rootDays int) CertificateAuthority {
	t.Helper()
	root := createRoot(t, svc, rootDays)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{OrgID: testOrg, Name: "Issuing",
		Type: CATypeIssuing, ParentID: root.ID, Subject: SubjectInput{CommonName: "Issuing CA"}})
	if err != nil {
		t.Fatal(err)
	}
	return issuing
}

// TestIssuedLeafCarriesBasicConstraintsAndKeyIdentifiers covers the extensions
// a subscriber certificate is expected to carry. Before this, Go emitted no
// basicConstraints at all on a leaf — leaving a verifier to infer cA=FALSE
// rather than read it — and no subjectKeyIdentifier, because Go derives one
// only for CA certificates.
func TestIssuedLeafCarriesBasicConstraintsAndKeyIdentifiers(t *testing.T) {
	svc, _ := newTestService()
	issuing := issuingUnder(t, svc, 0)
	issuer := mustParseCert(t, issuing.CertificatePEM)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: issuing.ID,
		CSRPEM: csrWithKey(t, key, "device.example.test"), Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCert(t, cert.CertificatePEM)

	if !leaf.BasicConstraintsValid {
		t.Error("leaf carries no basicConstraints extension")
	}
	if leaf.IsCA {
		t.Error("leaf asserts cA=TRUE")
	}
	if len(leaf.SubjectKeyId) == 0 {
		t.Error("leaf carries no subjectKeyIdentifier")
	}
	// The AKI is filled by Go from the issuer's SKI; assert it rather than set it.
	if !bytes.Equal(leaf.AuthorityKeyId, issuer.SubjectKeyId) {
		t.Errorf("authorityKeyIdentifier = %x, want the issuer's subjectKeyIdentifier %x",
			leaf.AuthorityKeyId, issuer.SubjectKeyId)
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		t.Errorf("leaf does not verify against its issuer: %v", err)
	}
}

// TestIssuedLeafIsBackdatedForClockSkew guards against the failure a fleet hits
// when a device's clock runs fast: a certificate rejected as "not yet valid"
// seconds after it was issued.
func TestIssuedLeafIsBackdatedForClockSkew(t *testing.T) {
	svc, _ := newTestService()
	issuing := issuingUnder(t, svc, 0)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	cert, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: issuing.ID,
		CSRPEM: csrWithKey(t, key, "device.example.test"), Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCert(t, cert.CertificatePEM)

	if !leaf.NotBefore.Before(before) {
		t.Errorf("notBefore = %s, want it backdated before issuance at %s", leaf.NotBefore, before)
	}
	if skew := before.Sub(leaf.NotBefore); skew > clockSkew+time.Minute {
		t.Errorf("notBefore backdated by %s, want about %s", skew, clockSkew)
	}
	// notAfter must not have moved with it: backdating validity is not the same
	// as extending it.
	if want := before.Add(30 * 24 * time.Hour); leaf.NotAfter.After(want.Add(time.Minute)) {
		t.Errorf("notAfter = %s, want no later than %s", leaf.NotAfter, want)
	}
}

// TestIssueRefusesWeakKeys covers the gap that made this necessary: the
// administrator's own CSR form reaches Issue without passing through any
// protocol's key check, so an RSA-1024 CSR used to be signed.
func TestIssueRefusesWeakKeys(t *testing.T) {
	svc, _ := newTestService()
	issuing := issuingUnder(t, svc, 0)

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: issuing.ID,
		CSRPEM: csrWithKey(t, weak, "weak.example.test"), Days: 30})
	if err == nil {
		t.Fatal("an RSA-1024 CSR was signed")
	}
	if !strings.Contains(err.Error(), "2048") {
		t.Errorf("error = %q, want it to name the required key size", err)
	}
}

func TestValidatePublicKeyFloor(t *testing.T) {
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		key     any
		wantErr bool
	}{
		{name: "rsa 2048", key: &rsa2048.PublicKey},
		{name: "rsa 1024", key: &rsa1024.PublicKey, wantErr: true},
		{name: "p256", key: &p256.PublicKey},
		{name: "p224", key: &p224.PublicKey, wantErr: true},
		{name: "not a key", key: "hello", wantErr: true},
	}
	for _, tc := range cases {
		err := ValidatePublicKey(tc.key)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: ValidatePublicKey() error = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

// TestIssueRefusesAnExpiredCA covers what used to happen silently: signLeaf
// clamped a leaf's notAfter to the CA's without checking the CA was still
// valid, so an expired issuer produced certificates whose notAfter preceded
// their notBefore — nonsense that every client rejects, with nothing said about
// why. A refusal turns a silently broken fleet into a loudly broken one.
func TestIssueRefusesAnExpiredCA(t *testing.T) {
	store := newMemStore()
	provider := NewFakeProvider()
	svc := NewService(store, provider)
	issuing := issuingUnder(t, svc, 0)

	// Re-issue the CA's own certificate with dates in the past, keeping its key,
	// then age the stored record to match.
	ctx := context.Background()
	key, err := provider.KeyInfo(ctx, issuing.KMSKeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().UTC().AddDate(-2, 0, 0)
	notAfter := time.Now().UTC().AddDate(0, 0, -1)
	tmpl, err := caTemplate(pkix.Name{CommonName: "Expired Issuing CA"}, 0, key.PublicKey, notBefore, notAfter, "")
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey, NewKMSSigner(ctx, provider, key))
	if err != nil {
		t.Fatal(err)
	}
	aged := store.cas[issuing.ID]
	aged.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	aged.NotAfter = notAfter
	store.cas[issuing.ID] = aged

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Issue(ctx, IssueRequest{OrgID: testOrg, CAID: issuing.ID,
		CSRPEM: csrWithKey(t, leafKey, "device.example.test"), Days: 30})
	if err == nil {
		t.Fatal("an expired CA signed a certificate")
	}
	if !strings.Contains(err.Error(), "not valid at this time") {
		t.Errorf("error = %q, want it to say the CA is not currently valid", err)
	}
}

// TestIssuingCACarriesAIAAndRootDoesNot pins where each certificate's AIA
// points. A CA's AIA names its *issuer*, so a self-signed root has none.
func TestIssuingCACarriesAIAAndRootDoesNot(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{OrgID: testOrg, Name: "Issuing",
		Type: CATypeIssuing, ParentID: root.ID, Subject: SubjectInput{CommonName: "Issuing CA"}})
	if err != nil {
		t.Fatal(err)
	}

	if urls := mustParseCert(t, root.CertificatePEM).IssuingCertificateURL; len(urls) != 0 {
		t.Errorf("root AIA = %v, want none: a self-signed root has no issuer to fetch", urls)
	}
	urls := mustParseCert(t, issuing.CertificatePEM).IssuingCertificateURL
	if len(urls) != 1 || !strings.Contains(urls[0], root.ID) {
		t.Errorf("issuing CA AIA = %v, want one URL naming the root %s", urls, root.ID)
	}
	// Not shipped, and the reason is recorded on caTemplate: nothing behind the
	// CRL or the responder can answer for a CA's own serial yet.
	if points := mustParseCert(t, issuing.CertificatePEM).CRLDistributionPoints; len(points) != 0 {
		t.Errorf("issuing CA CRLDP = %v, want none until CA revocation is modelled", points)
	}
}

// TestSetCAStatusIsAudited covers a gap the audit had: taking a CA out of
// service is production-affecting and left no record at all, because the
// handler called the repository directly. Pairing the change with its audit row
// inside the service is what makes forgetting it impossible.
func TestSetCAStatusIsAudited(t *testing.T) {
	cases := map[string]string{
		CAStatusInactive: PurposeDeactivatedCA,
		CAStatusActive:   PurposeActivatedCA,
		CAStatusRetired:  PurposeRetiredCA,
	}
	for status, wantPurpose := range cases {
		svc, store := newTestService()
		ca := createRoot(t, svc, 0)
		store.events = nil

		if err := svc.SetCAStatus(context.Background(), testOrg, "user-1", ca.ID, status); err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if len(store.events) != 1 {
			t.Fatalf("%s: recorded %d events, want 1", status, len(store.events))
		}
		event := store.events[0]
		if event.Purpose != wantPurpose || event.CAID != ca.ID || event.UserID != "user-1" {
			t.Errorf("%s: event = %+v, want purpose %q", status, event, wantPurpose)
		}
		if event.KeyVersion != ca.KMSKeyVersion {
			t.Errorf("%s: key version = %q, want the CA's own %q", status, event.KeyVersion, ca.KMSKeyVersion)
		}
		if stored, err := store.CA(context.Background(), testOrg, ca.ID); err != nil || stored.Status != status {
			t.Errorf("%s: stored status = %q (err %v)", status, stored.Status, err)
		}
	}
}

// TestRotationIsAuditedAgainstTheRetiredCA pins which CA the rotation event
// names. CreateCA already logs the replacement's creation; what a reader needs
// from this row is that the old key stopped being used.
func TestRotationIsAuditedAgainstTheRetiredCA(t *testing.T) {
	svc, store := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := createIssuing(t, svc, root.ID, "Issuing")
	if err != nil {
		t.Fatal(err)
	}
	store.events = nil

	if _, err := svc.RotateIssuingCA(context.Background(), testOrg, "user-1", issuing.ID); err != nil {
		t.Fatal(err)
	}
	var rotations []signingRecord
	for _, e := range store.events {
		if e.Purpose == PurposeRotatedCA {
			rotations = append(rotations, e)
		}
	}
	if len(rotations) != 1 {
		t.Fatalf("recorded %d rotation events, want 1 (all: %+v)", len(rotations), store.events)
	}
	if rotations[0].CAID != issuing.ID || rotations[0].KeyVersion != issuing.KMSKeyVersion {
		t.Errorf("rotation event = %+v, want it against the retired CA %s", rotations[0], issuing.ID)
	}
}
