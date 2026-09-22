package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testOrg = "org-1"

func newTestService() (Service, *memStore) {
	store := newMemStore()
	return NewService(store, NewFakeProvider()), store
}

func mustParseCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	cert, err := parseCertificate(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func createRoot(t *testing.T, svc Service, days int) CertificateAuthority {
	t.Helper()
	ca, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:   testOrg,
		UserID:  "user-1",
		Name:    "Test Root",
		Type:    CATypeRoot,
		Subject: SubjectInput{CommonName: "Test Root CA", Organization: "Acme Inc", Country: "us"},
		Days:    days,
		EKUs:    []string{EKUClientAuth, EKUServerAuth, EKUCodeSigning, EKUSmartcardLogon, "1.2.840.113635.100.4.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestCreateRootCADefaults(t *testing.T) {
	svc, _ := newTestService()
	ca := createRoot(t, svc, 0)
	cert := mustParseCert(t, ca.CertificatePEM)
	if cert.Subject.CommonName != "Test Root CA" || cert.Subject.Country[0] != "US" {
		t.Errorf("subject = %s", cert.Subject)
	}
	wantExpiry := time.Now().UTC().Add(DefaultRootDays * 24 * time.Hour)
	if diff := cert.NotAfter.Sub(wantExpiry); diff > time.Hour || diff < -time.Hour {
		t.Errorf("NotAfter = %v, want ~%v", cert.NotAfter, wantExpiry)
	}
	if !cert.IsCA || cert.MaxPathLen != 1 {
		t.Errorf("IsCA=%v MaxPathLen=%d, want CA with path length 1", cert.IsCA, cert.MaxPathLen)
	}
	if len(cert.SubjectKeyId) != 20 {
		t.Errorf("SubjectKeyId length = %d, want 20", len(cert.SubjectKeyId))
	}
	if ca.ExportPosture != ExportPostureNonExportableSoftware {
		t.Errorf("export posture = %q", ca.ExportPosture)
	}
}

func TestCreateCAP384SignsWithSHA384(t *testing.T) {
	svc, _ := newTestService()
	ca, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:     testOrg,
		Name:      "P384 Root",
		Type:      CATypeRoot,
		Subject:   SubjectInput{CommonName: "P384 Root"},
		Algorithm: AlgorithmECDSAP384SHA384,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := mustParseCert(t, ca.CertificatePEM)
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("signature algorithm = %v, want ECDSAWithSHA384", cert.SignatureAlgorithm)
	}
	if ca.Algorithm != AlgorithmECDSAP384SHA384 {
		t.Errorf("stored algorithm = %q", ca.Algorithm)
	}
}

func TestCreateCARejectsHSMWhenProviderOnlySupportsSoftware(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID: testOrg, Name: "HSM Root", Type: CATypeRoot,
		Subject: SubjectInput{CommonName: "HSM Root"}, Protection: ProtectionHSM,
	})
	if err == nil || !strings.Contains(err.Error(), "does not support HSM") {
		t.Fatalf("err = %v, want unsupported-HSM rejection", err)
	}
}

func TestDuplicateRootRejected(t *testing.T) {
	svc, _ := newTestService()
	createRoot(t, svc, 0)
	_, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:   testOrg,
		Name:    "Second Root",
		Type:    CATypeRoot,
		Subject: SubjectInput{CommonName: "Second Root"},
	})
	if err == nil || !strings.Contains(err.Error(), "root CA already exists") {
		t.Fatalf("err = %v, want duplicate-root rejection", err)
	}
}

func TestIssuingCAClampedToParentExpiry(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 30)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		Name:     "Test Issuing",
		Type:     CATypeIssuing,
		ParentID: root.ID,
		Subject:  SubjectInput{CommonName: "Test Issuing CA"},
		Days:     10000,
	})
	if err != nil {
		t.Fatal(err)
	}
	rootCert := mustParseCert(t, root.CertificatePEM)
	issuingCert := mustParseCert(t, issuing.CertificatePEM)
	if issuingCert.NotAfter.After(rootCert.NotAfter) {
		t.Errorf("issuing NotAfter %v exceeds parent %v", issuingCert.NotAfter, rootCert.NotAfter)
	}
	if !issuingCert.MaxPathLenZero {
		t.Error("issuing CA should have MaxPathLenZero")
	}
	if issuing.ChainPEM == "" {
		t.Error("issuing CA chain should include the parent")
	}
}

func testCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"device.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestIssueAppliesEKUProfileAndClampsExpiry(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		Name:     "Profile Issuing",
		Type:     CATypeIssuing,
		ParentID: root.ID,
		Subject:  SubjectInput{CommonName: "Profile Issuing CA"},
		Days:     30,
		EKUs:     []string{EKUServerAuth, EKUCodeSigning},
	})
	if err != nil {
		t.Fatal(err)
	}
	if issuing.IssuanceEKUs != "server_auth,code_signing" {
		t.Fatalf("stored EKUs = %q", issuing.IssuanceEKUs)
	}
	// 3650 days is the longest a leaf may request; the 30-day CA still clamps it.
	cert, err := svc.Issue(context.Background(), IssueRequest{
		OrgID:  testOrg,
		CAID:   issuing.ID,
		CSRPEM: testCSR(t),
		Days:   3650,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCert(t, cert.CertificatePEM)
	if len(leaf.ExtKeyUsage) != 2 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.ExtKeyUsage[1] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("leaf EKUs = %v, want [ServerAuth CodeSigning]", leaf.ExtKeyUsage)
	}
	issuingCert := mustParseCert(t, issuing.CertificatePEM)
	if leaf.NotAfter.After(issuingCert.NotAfter) {
		t.Errorf("leaf NotAfter %v exceeds CA %v", leaf.NotAfter, issuingCert.NotAfter)
	}
}

func TestIssueRejectsPrivateKeyInCSRField(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		Name:     "Issuing",
		Type:     CATypeIssuing,
		ParentID: root.ID,
		Subject:  SubjectInput{CommonName: "Issuing CA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Issue(context.Background(), IssueRequest{
		OrgID:  testOrg,
		CAID:   issuing.ID,
		CSRPEM: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
	})
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("err = %v, want private key rejection", err)
	}
}

func TestIssuingEKUsConstrainedByParent(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0) // allows client_auth, server_auth, code_signing, smartcard_logon, custom OID
	_, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		Name:     "Overreaching Issuing",
		Type:     CATypeIssuing,
		ParentID: root.ID,
		Subject:  SubjectInput{CommonName: "Overreaching CA"},
		EKUs:     []string{EKUTimeStamping},
	})
	if err == nil || !strings.Contains(err.Error(), "not permitted by the parent") {
		t.Fatalf("err = %v, want parent EKU constraint violation", err)
	}
}

func TestIssueEmitsNamedAndCustomOIDEKUs(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		Name:     "OID Issuing",
		Type:     CATypeIssuing,
		ParentID: root.ID,
		Subject:  SubjectInput{CommonName: "OID Issuing CA"},
		EKUs:     []string{EKUClientAuth, EKUSmartcardLogon, "1.2.840.113635.100.4.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: issuing.ID, CSRPEM: testCSR(t)})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCert(t, cert.CertificatePEM)
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("standard EKUs = %v", leaf.ExtKeyUsage)
	}
	var got []string
	for _, oid := range leaf.UnknownExtKeyUsage {
		got = append(got, oid.String())
	}
	want := map[string]bool{"1.3.6.1.4.1.311.20.2.2": false, "1.2.840.113635.100.4.10": false}
	for _, oid := range got {
		if _, ok := want[oid]; ok {
			want[oid] = true
		}
	}
	for oid, found := range want {
		if !found {
			t.Errorf("leaf missing EKU OID %s (got %v)", oid, got)
		}
	}
}

func TestDeleteCAAllowsReplacementRoot(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	if err := svc.DeleteCA(context.Background(), testOrg, "user-1", root.ID); err != nil {
		t.Fatal(err)
	}
	// Deleted root no longer blocks a new one.
	replacement := createRoot(t, svc, 0)
	if replacement.ID == root.ID {
		t.Fatal("expected a new root CA row")
	}
	// The deleted CA's key is gone from the provider.
	if _, err := svc.provider.KeyInfo(context.Background(), root.KMSKeyVersion); err == nil {
		t.Error("deleted CA key should be destroyed")
	}
	// Deleting again reports not found.
	if err := svc.DeleteCA(context.Background(), testOrg, "user-1", root.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("second delete err = %v, want ErrNoRows", err)
	}
}

func TestDeleteCARejectsRootWithLiveChildren(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		Name:     "Child Issuing",
		Type:     CATypeIssuing,
		ParentID: root.ID,
		Subject:  SubjectInput{CommonName: "Child Issuing CA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteCA(context.Background(), testOrg, "user-1", root.ID); err == nil || !strings.Contains(err.Error(), "issuing CAs before") {
		t.Fatalf("err = %v, want live-children rejection", err)
	}
	if err := svc.DeleteCA(context.Background(), testOrg, "user-1", issuing.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteCA(context.Background(), testOrg, "user-1", root.ID); err != nil {
		t.Fatalf("root delete after child delete failed: %v", err)
	}
}

func TestDeletedCACannotIssue(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		Name:     "Doomed Issuing",
		Type:     CATypeIssuing,
		ParentID: root.ID,
		Subject:  SubjectInput{CommonName: "Doomed Issuing CA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteCA(context.Background(), testOrg, "user-1", issuing.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: issuing.ID, CSRPEM: testCSR(t)}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("issue from deleted CA err = %v, want ErrNoRows", err)
	}
}

func createIssuing(t *testing.T, svc Service, rootID, name string) (CertificateAuthority, error) {
	t.Helper()
	return svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		UserID:   "user-1",
		Name:     name,
		Type:     CATypeIssuing,
		ParentID: rootID,
		Subject:  SubjectInput{CommonName: name},
	})
}

func TestRotationRetiresOldCA(t *testing.T) {
	svc, store := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := createIssuing(t, svc, root.ID, "Only Issuing")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.RotateIssuingCA(context.Background(), testOrg, "user-1", issuing.ID)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	old, err := store.CA(context.Background(), testOrg, issuing.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != CAStatusRetired {
		t.Errorf("old CA status = %q, want retired", old.Status)
	}
	if n, _ := store.IssuingCACount(context.Background(), testOrg); n != 1 {
		t.Errorf("issuing CA count after rotation = %d, want 1", n)
	}
	if rotated.Status != CAStatusActive {
		t.Errorf("rotated CA status = %q, want active", rotated.Status)
	}
}

func TestRotationOfNearExpiredCAUsesOriginalSpan(t *testing.T) {
	svc, store := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := createIssuing(t, svc, root.ID, "Old Issuing")
	if err != nil {
		t.Fatal(err)
	}
	// Age the CA so under a day of its five-year span remains.
	aged := store.cas[issuing.ID]
	aged.NotBefore = time.Now().UTC().Add(-time.Duration(DefaultIssuingDays)*24*time.Hour + 12*time.Hour)
	aged.NotAfter = time.Now().UTC().Add(12 * time.Hour)
	store.cas[issuing.ID] = aged
	rotated, err := svc.RotateIssuingCA(context.Background(), testOrg, "user-1", issuing.ID)
	if err != nil {
		t.Fatalf("rotating a near-expired CA failed: %v", err)
	}
	wantExpiry := time.Now().UTC().Add(time.Duration(DefaultIssuingDays) * 24 * time.Hour)
	if diff := rotated.NotAfter.Sub(wantExpiry); diff > 24*time.Hour || diff < -24*time.Hour {
		t.Errorf("rotated NotAfter = %v, want ~%v (the original validity span)", rotated.NotAfter, wantExpiry)
	}
}

func TestRootCAAuditRecordsOwnKeyVersion(t *testing.T) {
	svc, store := newTestService()
	ca := createRoot(t, svc, 0)
	var rootSigning *signingRecord
	for i := range store.signings {
		if store.signings[i].Purpose == "root_ca" {
			rootSigning = &store.signings[i]
		}
	}
	if rootSigning == nil {
		t.Fatal("root_ca audit record missing")
	}
	if rootSigning.KeyVersion != ca.KMSKeyVersion {
		t.Errorf("audit key version = %q, want the root's own key %q", rootSigning.KeyVersion, ca.KMSKeyVersion)
	}
}

func TestDeleteCARecordsAuditEvent(t *testing.T) {
	svc, store := newTestService()
	ca := createRoot(t, svc, 0)
	if err := svc.DeleteCA(context.Background(), testOrg, "user-1", ca.ID); err != nil {
		t.Fatal(err)
	}
	if len(store.events) != 1 {
		t.Fatalf("recorded %d CA events, want 1", len(store.events))
	}
	event := store.events[0]
	if event.Purpose != "deleted_ca" || event.UserID != "user-1" || event.CAID != ca.ID || event.KeyVersion != ca.KMSKeyVersion {
		t.Errorf("delete audit event = %+v", event)
	}
}

func createIssuingWithEKUs(t *testing.T, svc Service, rootID, name string, ekus []string) CertificateAuthority {
	t.Helper()
	ca, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:    testOrg,
		UserID:   "user-1",
		Name:     name,
		Type:     CATypeIssuing,
		ParentID: rootID,
		Subject:  SubjectInput{CommonName: name},
		EKUs:     ekus,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestIssueGeneratedServerCertificate(t *testing.T) {
	svc, store := newTestService()
	root := createRoot(t, svc, 0)
	issuing := createIssuingWithEKUs(t, svc, root.ID, "Server Issuing", []string{EKUServerAuth, EKUClientAuth, EKUCodeSigning})
	for _, algorithm := range []string{LeafECP256, LeafRSA2048} {
		cert, keyPEM, err := svc.IssueGenerated(context.Background(), IssueGeneratedRequest{
			OrgID:     testOrg,
			UserID:    "user-1",
			CAID:      issuing.ID,
			Profile:   CertProfileServer,
			Subject:   SubjectInput{CommonName: "vpn.example.com", Organization: "Acme Inc"},
			DNSNames:  []string{"vpn.example.com", "api.example.com"},
			IPs:       []string{"10.0.0.12"},
			Emails:    []string{"ops@example.com"},
			Algorithm: algorithm,
			EKUs:      []string{EKUCodeSigning},
		})
		if err != nil {
			t.Fatalf("%s: %v", algorithm, err)
		}
		block, _ := pem.Decode([]byte(keyPEM))
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Fatalf("%s: key PEM = %q", algorithm, keyPEM[:40])
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		leaf := mustParseCert(t, cert.CertificatePEM)
		if !publicKeysEqual(key.(interface{ Public() crypto.PublicKey }).Public(), leaf.PublicKey) {
			t.Errorf("%s: returned key does not match the certificate", algorithm)
		}
		wantEKUs := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning}
		if len(leaf.ExtKeyUsage) != 2 || leaf.ExtKeyUsage[0] != wantEKUs[0] || leaf.ExtKeyUsage[1] != wantEKUs[1] {
			t.Errorf("%s: EKUs = %v, want server_auth+code_signing", algorithm, leaf.ExtKeyUsage)
		}
		if len(leaf.DNSNames) != 2 || len(leaf.IPAddresses) != 1 || len(leaf.EmailAddresses) != 1 {
			t.Errorf("%s: SANs = %v %v %v", algorithm, leaf.DNSNames, leaf.IPAddresses, leaf.EmailAddresses)
		}
		wantUsage := x509.KeyUsageDigitalSignature
		if algorithm == LeafRSA2048 {
			wantUsage |= x509.KeyUsageKeyEncipherment
		}
		if leaf.KeyUsage != wantUsage {
			t.Errorf("%s: KeyUsage = %v, want %v", algorithm, leaf.KeyUsage, wantUsage)
		}
		stored := store.certs[cert.ID]
		if stored.Profile != CertProfileServer || stored.EKUs != "server_auth,code_signing" {
			t.Errorf("%s: stored profile=%q ekus=%q", algorithm, stored.Profile, stored.EKUs)
		}
		if strings.Contains(stored.CertificatePEM+stored.ChainPEM+stored.CSRDigest, "PRIVATE KEY") {
			t.Errorf("%s: private key material leaked into the stored certificate", algorithm)
		}
	}
	if got := store.signings[len(store.signings)-1].Purpose; got != "server" {
		t.Errorf("audit purpose = %q, want server", got)
	}
}

func TestIssueGeneratedRejectsEKUOutsideCAProfile(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	clientOnly := createIssuingWithEKUs(t, svc, root.ID, "Client Only", []string{EKUClientAuth})
	_, _, err := svc.IssueGenerated(context.Background(), IssueGeneratedRequest{
		OrgID:   testOrg,
		CAID:    clientOnly.ID,
		Profile: CertProfileServer,
		Subject: SubjectInput{CommonName: "vpn.example.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "not permitted by this issuing CA") {
		t.Fatalf("err = %v, want EKU-outside-profile rejection", err)
	}
	// The required client_auth EKU makes the same CA fine for client certs.
	if _, _, err := svc.IssueGenerated(context.Background(), IssueGeneratedRequest{
		OrgID:   testOrg,
		CAID:    clientOnly.ID,
		Profile: CertProfileClient,
		Subject: SubjectInput{CommonName: "jane.doe"},
	}); err != nil {
		t.Fatalf("client issuance from client_auth CA failed: %v", err)
	}
}

func TestIssueGeneratedValidatesInput(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing := createIssuingWithEKUs(t, svc, root.ID, "Validating Issuing", []string{EKUServerAuth, EKUClientAuth})
	cases := []struct {
		name string
		req  IssueGeneratedRequest
		want string
	}{
		{"bad profile", IssueGeneratedRequest{Profile: "root", Subject: SubjectInput{CommonName: "x"}}, "invalid certificate profile"},
		{"missing CN", IssueGeneratedRequest{Profile: CertProfileServer}, "common name"},
		{"bad IP", IssueGeneratedRequest{Profile: CertProfileServer, Subject: SubjectInput{CommonName: "x"}, IPs: []string{"nope"}}, "invalid IP address"},
		{"bad DNS", IssueGeneratedRequest{Profile: CertProfileServer, Subject: SubjectInput{CommonName: "x"}, DNSNames: []string{"has space"}}, "invalid DNS name"},
		{"bad email", IssueGeneratedRequest{Profile: CertProfileServer, Subject: SubjectInput{CommonName: "x"}, Emails: []string{"nope"}}, "invalid email"},
		{"bad algorithm", IssueGeneratedRequest{Profile: CertProfileServer, Subject: SubjectInput{CommonName: "x"}, Algorithm: "DSA"}, "unsupported key algorithm"},
		{"bad days", IssueGeneratedRequest{Profile: CertProfileServer, Subject: SubjectInput{CommonName: "x"}, Days: 99999}, "validity"},
	}
	for _, tc := range cases {
		tc.req.OrgID = testOrg
		tc.req.CAID = issuing.ID
		_, _, err := svc.IssueGenerated(context.Background(), tc.req)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestActiveIdentityCountTracksDistinctSubjects pins the identity-counting
// behavior the dashboard's certificate-identity metric relies on: two
// certificates for the same subject are one identity, and an identity is
// freed only once every certificate holding it is revoked.
func TestActiveIdentityCountTracksDistinctSubjects(t *testing.T) {
	svc, store := newTestService()
	root := createRoot(t, svc, 0)
	issuing := createIssuingWithEKUs(t, svc, root.ID, "Issuing", []string{EKUServerAuth, EKUClientAuth})
	issue := func(cn string) (Certificate, error) {
		cert, _, err := svc.IssueGenerated(context.Background(), IssueGeneratedRequest{
			OrgID:   testOrg,
			UserID:  "user-1",
			CAID:    issuing.ID,
			Profile: CertProfileServer,
			Subject: SubjectInput{CommonName: cn},
		})
		return cert, err
	}
	first, err := issue("vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// The same subject re-issued is what a renewal, and an MDM enrolling a
	// device it has already enrolled, looks like — it must not create a
	// second identity.
	second, err := issue("vpn.example.com")
	if err != nil {
		t.Fatalf("re-issuing for the same subject failed: %v", err)
	}
	if n, _ := store.ActiveIdentityCount(context.Background(), testOrg); n != 1 {
		t.Errorf("identity count = %d, want 1: two certificates for one subject are one identity", n)
	}
	// The identity is only freed once no live certificate holds it, so
	// revoking one of the pair changes nothing.
	if err := svc.Revoke(context.Background(), RevokeRequest{OrgID: testOrg, UserID: "user-1", CertificateID: first.ID, Reason: "superseded"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.ActiveIdentityCount(context.Background(), testOrg); n != 1 {
		t.Errorf("identity count = %d, want 1: revoking one of two certificates should not free the identity", n)
	}
	if err := svc.Revoke(context.Background(), RevokeRequest{OrgID: testOrg, UserID: "user-1", CertificateID: second.ID, Reason: "superseded"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.ActiveIdentityCount(context.Background(), testOrg); n != 0 {
		t.Errorf("identity count = %d, want 0 once every certificate for the subject is revoked", n)
	}
	if _, err := issue("api.example.com"); err != nil {
		t.Fatalf("issuance for a new subject failed: %v", err)
	}
	if n, _ := store.ActiveIdentityCount(context.Background(), testOrg); n != 1 {
		t.Errorf("identity count = %d, want 1", n)
	}
}

func TestIssueCSRWithEKUSubsetAndEmailSAN(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing := createIssuingWithEKUs(t, svc, root.ID, "Subset Issuing", []string{EKUServerAuth, EKUClientAuth, EKUCodeSigning})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("ID:JAMF:GUID:device-1")
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames:       []string{"device.example.com"},
		EmailAddresses: []string{"device@example.com"},
		URIs:           []*url.URL{uri},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	cert, err := svc.Issue(context.Background(), IssueRequest{
		OrgID:  testOrg,
		CAID:   issuing.ID,
		CSRPEM: csrPEM,
		EKUs:   []string{EKUServerAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCert(t, cert.CertificatePEM)
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("EKUs = %v, want [ServerAuth] only", leaf.ExtKeyUsage)
	}
	if len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "device@example.com" {
		t.Errorf("email SANs = %v, want the CSR's email copied", leaf.EmailAddresses)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != uri.String() {
		t.Errorf("URI SANs = %v, want the CSR's URI copied", leaf.URIs)
	}
	if cert.Profile != CertProfileCSR {
		t.Errorf("profile = %q, want csr", cert.Profile)
	}
	// A subset outside the profile is rejected.
	if _, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: issuing.ID, CSRPEM: csrPEM, EKUs: []string{EKUTimeStamping}}); err == nil || !strings.Contains(err.Error(), "not permitted by this issuing CA") {
		t.Fatalf("err = %v, want subset rejection", err)
	}
}

func TestRevokeCertificate(t *testing.T) {
	svc, store := newTestService()
	root := createRoot(t, svc, 0)
	issuing := createIssuingWithEKUs(t, svc, root.ID, "Revoking Issuing", []string{EKUClientAuth})
	cert, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, UserID: "user-1", CAID: issuing.ID, CSRPEM: testCSR(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(context.Background(), RevokeRequest{OrgID: testOrg, UserID: "user-1", CertificateID: cert.ID, Reason: "bogus"}); err == nil || !strings.Contains(err.Error(), "invalid revocation reason") {
		t.Fatalf("err = %v, want reason rejection", err)
	}
	if err := svc.Revoke(context.Background(), RevokeRequest{OrgID: testOrg, UserID: "user-1", CertificateID: cert.ID, Reason: "key_compromise"}); err != nil {
		t.Fatal(err)
	}
	revoked := store.certs[cert.ID]
	if revoked.Status != CertStatusRevoked || revoked.RevokedAt == nil {
		t.Errorf("status = %q revoked_at = %v", revoked.Status, revoked.RevokedAt)
	}
	if len(store.revocations) != 1 || store.revocations[0].Reason != "key_compromise" {
		t.Errorf("revocations = %+v", store.revocations)
	}
	event := store.events[len(store.events)-1]
	if event.Purpose != "revoked_certificate" || event.CAID != issuing.ID || event.UserID != "user-1" {
		t.Errorf("audit event = %+v", event)
	}
	// Double revoke and cross-org revoke report not found.
	if err := svc.Revoke(context.Background(), RevokeRequest{OrgID: testOrg, CertificateID: cert.ID, Reason: "superseded"}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("double revoke err = %v, want ErrNoRows", err)
	}
	if err := svc.Revoke(context.Background(), RevokeRequest{OrgID: "org-2", CertificateID: cert.ID, Reason: "superseded"}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("cross-org revoke err = %v, want ErrNoRows", err)
	}
}

// failingCreateStore rejects CA inserts to simulate a DB failure after the
// KMS key was already created.
type failingCreateStore struct {
	*memStore
}

func (f failingCreateStore) CreateCA(context.Context, CertificateAuthority) (string, error) {
	return "", errors.New("insert failed")
}

func TestCreateCADBFailureDestroysKey(t *testing.T) {
	provider := NewFakeProvider()
	svc := NewService(failingCreateStore{newMemStore()}, provider)
	_, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:   testOrg,
		Name:    "Doomed Root",
		Type:    CATypeRoot,
		Subject: SubjectInput{CommonName: "Doomed Root CA"},
	})
	if err == nil || !strings.Contains(err.Error(), "insert failed") {
		t.Fatalf("err = %v, want insert failure", err)
	}
	provider.mu.Lock()
	keys := len(provider.keys)
	provider.mu.Unlock()
	if keys != 0 {
		t.Errorf("provider still holds %d keys; the orphaned key should be destroyed", keys)
	}
}

func TestRotationPreservesSubjectAlgorithmEKUs(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{
		OrgID:     testOrg,
		Name:      "Rotate Me",
		Type:      CATypeIssuing,
		ParentID:  root.ID,
		Subject:   SubjectInput{CommonName: "Rotate Me CA", Organization: "Acme Inc"},
		Algorithm: AlgorithmECDSAP384SHA384,
		EKUs:      []string{EKUServerAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.RotateIssuingCA(context.Background(), testOrg, "user-1", issuing.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldCert := mustParseCert(t, issuing.CertificatePEM)
	newCert := mustParseCert(t, rotated.CertificatePEM)
	if oldCert.Subject.String() != newCert.Subject.String() {
		t.Errorf("subject changed: %s -> %s", oldCert.Subject, newCert.Subject)
	}
	if rotated.Algorithm != AlgorithmECDSAP384SHA384 {
		t.Errorf("rotated algorithm = %q", rotated.Algorithm)
	}
	if rotated.IssuanceEKUs != issuing.IssuanceEKUs {
		t.Errorf("rotated EKUs = %q, want %q", rotated.IssuanceEKUs, issuing.IssuanceEKUs)
	}
	if rotated.KMSKeyVersion == issuing.KMSKeyVersion {
		t.Error("rotation should create a new key")
	}
}

// intuneStyleCSR builds what Windows sends for a profile with subject
// "CN={{UserName}},E={{EmailAddress}}" and a UPN subject alternative name.
// Neither the emailAddress RDN nor the UPN otherName is representable in the
// structs x509 parses into, so both have to be supplied as raw DER.
func intuneStyleCSR(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	email := pkix.AttributeTypeAndValue{
		Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jacksongnav@l07n.onmicrosoft.com")},
	}
	upn, err := asn1.MarshalWithParams(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: mustMarshal(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String,
				Bytes: []byte("jacksongnav@l07n.onmicrosoft.com")}),
		}),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	sans, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: upn})
	if err != nil {
		t.Fatal(err)
	}
	// DER order is [emailAddress, CN], which is what the captured Windows
	// request carried: RDNs render in reverse, and it logged "CN=...,E=...".
	cn := pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "jacksongnav"}
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{email, cn}},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sans}},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func mustMarshal(t *testing.T, values ...any) []byte {
	t.Helper()
	var out []byte
	for _, v := range values {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, der...)
	}
	return out
}

// An Intune profile asking for CN + E + UPN must produce a certificate carrying
// all three. Rebuilding the subject or the SAN set from Go's parsed structs
// silently drops the emailAddress RDN and the UPN otherName.
func TestIssuePreservesEmailRDNAndUPNSubjectAltName(t *testing.T) {
	svc, _ := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := svc.CreateCA(context.Background(), CreateCARequest{OrgID: testOrg, Name: "Issuing",
		Type: CATypeIssuing, ParentID: root.ID, Subject: SubjectInput{CommonName: "Issuing CA"}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: issuing.ID,
		CSRPEM: intuneStyleCSR(t), Days: 365})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCert(t, cert.CertificatePEM)

	if got := RenderSubject(leaf.RawSubject, leaf.Subject); got != "CN=jacksongnav,E=jacksongnav@l07n.onmicrosoft.com" {
		t.Errorf("issued subject = %q, want CN and the emailAddress RDN", got)
	}
	if leaf.Subject.CommonName != "jacksongnav" {
		t.Errorf("common name = %q", leaf.Subject.CommonName)
	}
	upns := UnparsedSANs(subjectAltNameOf(leaf))
	if len(upns) != 1 || upns[0] != "jacksongnav@l07n.onmicrosoft.com" {
		t.Errorf("issued UPN SAN = %v, want the requested UPN preserved", upns)
	}
	// The stored record has to describe what was actually issued.
	if !strings.Contains(cert.Subject, "jacksongnav@l07n.onmicrosoft.com") {
		t.Errorf("stored subject = %q", cert.Subject)
	}
	if !strings.Contains(cert.SANs, "jacksongnav@l07n.onmicrosoft.com") {
		t.Errorf("stored SANs = %q", cert.SANs)
	}
}

func subjectAltNameOf(cert *x509.Certificate) *pkix.Extension {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			found := ext
			return &found
		}
	}
	return nil
}
