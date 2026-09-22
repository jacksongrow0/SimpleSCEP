package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCA generates a self-signed EC P-256 CA for import tests.
func testCA(t *testing.T, cn string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// wrapKey wraps a private key with the job's OAEP wrapping key the way a
// customer would with openssl.
func wrapKey(t *testing.T, wrappingPEM string, key crypto.PrivateKey) string {
	t.Helper()
	block, _ := pem.Decode([]byte(wrappingPEM))
	if block == nil {
		t.Fatal("invalid wrapping key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub.(*rsa.PublicKey), der, nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(wrapped)
}

func startImport(t *testing.T, svc Service, name, caType, certPEM, chainPEM string) CAImportJob {
	t.Helper()
	job, err := svc.StartCAImport(context.Background(), StartCAImportRequest{
		OrgID:          testOrg,
		UserID:         "user-1",
		Name:           name,
		Type:           caType,
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestCAImportHappyPath(t *testing.T) {
	svc, store := newTestService()
	key, certPEM := testCA(t, "Imported Root")
	job := startImport(t, svc, "Imported Root", CATypeRoot, certPEM, "")
	if job.State != ImportStateReadyToWrap {
		t.Fatalf("state = %q, want ready_to_wrap", job.State)
	}
	if job.Algorithm != AlgorithmECDSAP256SHA256 {
		t.Fatalf("derived algorithm = %q", job.Algorithm)
	}
	if job.WrappingPublicKeyPEM == "" {
		t.Fatal("wrapping public key missing")
	}
	done, err := svc.SubmitWrappedKey(context.Background(), testOrg, "user-1", job.ID, wrapKey(t, job.WrappingPublicKeyPEM, key))
	if err != nil {
		t.Fatal(err)
	}
	if done.State != ImportStateCompleted {
		t.Fatalf("state = %q (%s), want completed", done.State, done.FailureReason)
	}
	ca, err := store.CA(context.Background(), testOrg, done.CertificateAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	if ca.ExportPosture != ExportPostureImportedSoftware {
		t.Errorf("export posture = %q, want imported_software", ca.ExportPosture)
	}
	if ca.Status != CAStatusActive || ca.Type != CATypeRoot {
		t.Errorf("ca status=%q type=%q", ca.Status, ca.Type)
	}
	found := false
	for _, signing := range store.signings {
		if signing.Purpose == "imported_ca" {
			found = true
		}
	}
	if !found {
		t.Error("imported_ca audit record missing")
	}
	// The imported CA must be able to sign.
	issued, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: ca.ID, CSRPEM: testCSR(t)})
	if err == nil {
		_ = issued
		t.Error("issue from a root should be rejected (issuing CAs only)")
	}
}

func TestCAImportKeyMismatchFailsAndDestroys(t *testing.T) {
	svc, _ := newTestService()
	_, certPEM := testCA(t, "Mismatch Root")
	otherKey, _ := testCA(t, "Other CA")
	job := startImport(t, svc, "Mismatch Root", CATypeRoot, certPEM, "")
	done, err := svc.SubmitWrappedKey(context.Background(), testOrg, "user-1", job.ID, wrapKey(t, job.WrappingPublicKeyPEM, otherKey))
	if err != nil {
		t.Fatal(err)
	}
	if done.State != ImportStateFailed {
		t.Fatalf("state = %q, want failed", done.State)
	}
	if !strings.Contains(done.FailureReason, "does not match") {
		t.Errorf("failure reason = %q", done.FailureReason)
	}
	provider := svc.provider.(*FakeProvider)
	state, _, err := provider.ImportedKeyState(context.Background(), done.KMSKeyVersion)
	if err != nil || state != "DESTROYED" {
		t.Errorf("key version state = %q (%v), want DESTROYED", state, err)
	}
}

func TestCAImportRejectsPrivateKeyMaterial(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.StartCAImport(context.Background(), StartCAImportRequest{
		OrgID:          testOrg,
		Name:           "Bad",
		Type:           CATypeRoot,
		CertificatePEM: "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
	})
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("err = %v, want private key rejection", err)
	}
}

func TestCAImportRejectsNonCACert(t *testing.T) {
	svc, _ := newTestService()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	_, err = svc.StartCAImport(context.Background(), StartCAImportRequest{
		OrgID: testOrg, Name: "Bad", Type: CATypeRoot, CertificatePEM: leafPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("err = %v, want non-CA rejection", err)
	}
}

func TestCAImportRootMustBeSelfSignedAndChainless(t *testing.T) {
	svc, _ := newTestService()
	_, certPEM := testCA(t, "Root")
	_, otherPEM := testCA(t, "Other")
	_, err := svc.StartCAImport(context.Background(), StartCAImportRequest{
		OrgID: testOrg, Name: "Root", Type: CATypeRoot, CertificatePEM: certPEM, ChainPEM: otherPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "chain empty") {
		t.Fatalf("err = %v, want chain rejection for roots", err)
	}
}

func TestCAImportDuplicateRootRejected(t *testing.T) {
	svc, _ := newTestService()
	createRoot(t, svc, 0)
	_, certPEM := testCA(t, "Second Root")
	_, err := svc.StartCAImport(context.Background(), StartCAImportRequest{
		OrgID: testOrg, Name: "Second Root", Type: CATypeRoot, CertificatePEM: certPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "root CA already exists") {
		t.Fatalf("err = %v, want duplicate-root rejection", err)
	}
}

func TestCAImportExpiredJobRejectsWrappedKey(t *testing.T) {
	svc, store := newTestService()
	key, certPEM := testCA(t, "Expiring Root")
	job := startImport(t, svc, "Expiring Root", CATypeRoot, certPEM, "")
	past := time.Now().Add(-time.Minute)
	if err := store.updateJob(testOrg, job.ID, func(j *CAImportJob) { j.ExpiresAt = &past }); err != nil {
		t.Fatal(err)
	}
	done, err := svc.SubmitWrappedKey(context.Background(), testOrg, "user-1", job.ID, wrapKey(t, job.WrappingPublicKeyPEM, key))
	if err != nil {
		t.Fatal(err)
	}
	if done.State != ImportStateExpired {
		t.Fatalf("state = %q, want expired", done.State)
	}
}

func TestCAImportIssuingChainVerified(t *testing.T) {
	svc, _ := newTestService()
	// Build parent -> child chain.
	parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parentTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "External Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	parentDER, err := x509.CreateCertificate(rand.Reader, parentTmpl, parentTmpl, parentKey.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parentCert, err := x509.ParseCertificate(parentDER)
	if err != nil {
		t.Fatal(err)
	}
	childKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	childTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "External Issuing"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	childDER, err := x509.CreateCertificate(rand.Reader, childTmpl, parentCert, childKey.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	childPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: childDER}))
	parentPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parentDER}))

	// Valid chain accepted.
	job := startImport(t, svc, "External Issuing", CATypeIssuing, childPEM, parentPEM)
	if job.State != ImportStateReadyToWrap {
		t.Fatalf("state = %q", job.State)
	}

	// Wrong chain rejected.
	_, wrongPEM := testCA(t, "Unrelated")
	_, err = svc.StartCAImport(context.Background(), StartCAImportRequest{
		OrgID: testOrg, Name: "Bad Chain", Type: CATypeIssuing, CertificatePEM: childPEM, ChainPEM: wrongPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "does not sign") {
		t.Fatalf("err = %v, want chain verification failure", err)
	}
}
