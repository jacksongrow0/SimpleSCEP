package est

import (
	"context"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

// mustCredential mints a credential and returns it with its password.
func mustCredential(t *testing.T, svc Service, e Endpoint, spec CredentialSpec) (Credential, string) {
	t.Helper()
	if spec.Username == "" {
		spec.Username = "gateways"
	}
	cred, password, err := svc.CreateCredential(context.Background(), e, spec)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	return cred, password
}

// statusOf reports the HTTP status an error would reach a client as. Anything
// that is not an *Error is a fault on our side and must never be described to an
// unauthenticated caller, which is what a zero here means.
func statusOf(err error) int {
	var estErr *Error
	if errors.As(err, &estErr) {
		return estErr.Status
	}
	return 0
}

// ---------------------------------------------------------------------------
// Endpoint administration
// ---------------------------------------------------------------------------

func TestCreateEndpointDefaultsAreConservative(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)

	e, err := svc.CreateEndpoint(context.Background(), testOrg, "Gateways", testCA)
	if err != nil {
		t.Fatalf("CreateEndpoint: %v", err)
	}
	// A new endpoint is off until an administrator has seen its policy, and
	// starts with the narrowest usage rather than the CA's whole profile.
	if e.Enabled {
		t.Error("a new endpoint is enabled before anyone has looked at its policy")
	}
	if e.AllowedEKUs != appPKI.EKUClientAuth {
		t.Errorf("AllowedEKUs = %q, want %q", e.AllowedEKUs, appPKI.EKUClientAuth)
	}
	if e.ValidityDays != DefaultValidityDays || e.RenewalWindowDays != DefaultRenewalWindowDays {
		t.Errorf("validity/window = %d/%d, want %d/%d", e.ValidityDays, e.RenewalWindowDays,
			DefaultValidityDays, DefaultRenewalWindowDays)
	}
}

func TestUpdatePolicyRejectsAnUncompilablePattern(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()

	err := svc.UpdatePolicy(context.Background(), testOrg, e.ID, PolicyUpdate{
		Name: e.Name, ValidityDays: 365, RenewalWindowDays: 30,
		SubjectPattern: "([unclosed", AllowedEKUs: appPKI.EKUClientAuth,
	})
	if err == nil {
		t.Fatal("an invalid regular expression was stored")
	}
	// Reported to the administrator who typed it, rather than to a device at
	// three in the morning.
	if !strings.Contains(err.Error(), "regular expression") {
		t.Errorf("error = %q, want it to name the problem", err)
	}
}

func TestUpdatePolicyBoundsTheRenewalWindow(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()

	err := svc.UpdatePolicy(context.Background(), testOrg, e.ID, PolicyUpdate{
		Name: e.Name, ValidityDays: 365, RenewalWindowDays: 0, AllowedEKUs: appPKI.EKUClientAuth,
	})
	if err == nil {
		t.Fatal("a renewal window of zero was accepted, which would close re-enrollment entirely")
	}
}

// ---------------------------------------------------------------------------
// Credentials and authentication
// ---------------------------------------------------------------------------

func TestCreateCredentialRejectsAColonInTheUsername(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()

	// A colon separates the halves of a Basic credential, so one inside the
	// username makes the pair ambiguous on the wire.
	_, _, err := svc.CreateCredential(context.Background(), e, CredentialSpec{Username: "gw:01"})
	if err == nil {
		t.Fatal("a username containing a colon was accepted")
	}
}

func TestAuthenticateAcceptsTheMintedPassword(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, password := mustCredential(t, svc, e, CredentialSpec{})

	got, err := svc.Authenticate(context.Background(), e, cred.Username, password)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != cred.ID {
		t.Errorf("authenticated as %s, want %s", got.ID, cred.ID)
	}
}

func TestAuthenticateRefusesAWrongPassword(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	_, err := svc.Authenticate(context.Background(), e, cred.Username, "not-the-password")
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", statusOf(err))
	}
}

// TestAuthenticateSaysTheSameThingForEveryFailure pins the property that keeps a
// caller from probing which usernames exist.
func TestAuthenticateSaysTheSameThingForEveryFailure(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, password := mustCredential(t, svc, e, CredentialSpec{})

	expired := time.Now().Add(-time.Hour)
	revoked := cred
	revoked.RevokedAt = &expired
	repo.credentials[cred.ID] = revoked

	_, unknownErr := svc.Authenticate(context.Background(), e, "no-such-user", password)
	_, wrongErr := svc.Authenticate(context.Background(), e, cred.Username, "wrong")
	_, revokedErr := svc.Authenticate(context.Background(), e, cred.Username, password)

	for _, err := range []error{unknownErr, wrongErr, revokedErr} {
		if statusOf(err) != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", statusOf(err))
		}
	}
	if unknownErr.Error() != wrongErr.Error() || wrongErr.Error() != revokedErr.Error() {
		t.Errorf("failures are distinguishable: unknown=%q wrong=%q revoked=%q",
			unknownErr, wrongErr, revokedErr)
	}
}

func TestAuthenticateRefusesAnExpiredCredential(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, password := mustCredential(t, svc, e, CredentialSpec{TTLHours: 1})

	past := time.Now().Add(-time.Minute)
	stale := cred
	stale.ExpiresAt = &past
	repo.credentials[cred.ID] = stale

	if _, err := svc.Authenticate(context.Background(), e, cred.Username, password); err == nil {
		t.Fatal("an expired credential still authenticated")
	}
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

func TestEnrollIssuesWithTheESTProfile(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	cert, _, err := svc.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{}))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if cert.ID == "" {
		t.Fatal("no certificate came back")
	}
	// The profile and purpose are what keep EST issuance out of the
	// infrastructure exclusion and inside the audit log's "certificate issued".
	if issuer.lastReq.Profile != appPKI.CertProfileEST {
		t.Errorf("profile = %q, want %q", issuer.lastReq.Profile, appPKI.CertProfileEST)
	}
	if issuer.lastReq.Purpose != "est" {
		t.Errorf("purpose = %q, want est", issuer.lastReq.Purpose)
	}
	if len(repo.enrollments) != 1 || repo.enrollments[0].Operation != OperationEnroll {
		t.Errorf("enrollments = %+v, want one enroll row", repo.enrollments)
	}
}

func TestEnrollRefusesASubjectThePolicyForbids(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	e.SubjectPattern = `CN=gw-\d+\.example\.internal`
	repo.endpoints[e.ID] = e
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	_, _, err := svc.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{commonName: "laptop.example.com"}))
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", statusOf(err))
	}
}

func TestEnrollRefusesAnUndersizedRSAKey(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	csr := testCSR(t, csrOptions{rsaBits: 1024})
	_, _, err := svc.Enroll(context.Background(), e, cred, csr)
	if statusOf(err) != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", statusOf(err))
	}
}

func TestEnrollAcceptsP384(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	if _, _, err := svc.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{curve: elliptic.P384()})); err != nil {
		t.Fatalf("Enroll with P-384: %v", err)
	}
}

// TestEnrollNarrowsToTheRequestedEKUs pins the ceiling semantics EST shares with
// SCEP: a request asking for a subset is issued that subset.
func TestEnrollNarrowsToTheRequestedEKUs(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	e := repo.seedEndpoint()
	e.AllowedEKUs = appPKI.EKUClientAuth + "," + appPKI.EKUServerAuth
	repo.endpoints[e.ID] = e
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	// id-kp-serverAuth alone, out of an endpoint that permits both.
	csr := testCSR(t, csrOptions{ekus: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}}})
	if _, _, err := svc.Enroll(context.Background(), e, cred, csr); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(issuer.lastReq.EKUs) != 1 || issuer.lastReq.EKUs[0] != appPKI.EKUServerAuth {
		t.Errorf("EKUs = %v, want just %q", issuer.lastReq.EKUs, appPKI.EKUServerAuth)
	}
}

func TestEnrollRefusesAnEKUOutsideTheCeiling(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint() // client_auth only
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	// id-kp-codeSigning, which this endpoint does not permit. Refused rather
	// than silently narrowed, so the mismatch surfaces instead of issuing a
	// certificate that will not do what the device expects.
	csr := testCSR(t, csrOptions{ekus: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 3}}})
	_, _, err := svc.Enroll(context.Background(), e, cred, csr)
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", statusOf(err))
	}
}

func TestEnrollHonoursACredentialsIdentifierPin(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{Identifiers: "gw-01.example.internal"})

	if _, _, err := svc.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{})); err != nil {
		t.Fatalf("the pinned name was refused: %v", err)
	}
	_, _, err := svc.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{commonName: "gw-02.example.internal"}))
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a name outside the pin", statusOf(err))
	}
}

// TestEnrollDoesNotDescribeAnInternalFailure keeps a database or KMS fault from
// explaining itself to an unauthenticated caller.
func TestEnrollDoesNotDescribeAnInternalFailure(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	// A failure writing the enrollment row is ours, not the client's.
	broken := NewService(brokenEnrollmentStore{repo}, &fakeIssuer{}, fakeCertificates{}, testURL)
	_, _, err := broken.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{}))
	if err == nil {
		t.Fatal("a failed enrollment write was reported as success")
	}
	if statusOf(err) != 0 {
		t.Errorf("an internal failure surfaced as HTTP %d; it must be opaque", statusOf(err))
	}
}

type brokenEnrollmentStore struct{ *fakeStore }

func (brokenEnrollmentStore) CreateEnrollment(context.Context, Enrollment) error {
	return errors.New("database is on fire")
}

// ---------------------------------------------------------------------------
// Re-enrollment
// ---------------------------------------------------------------------------

func TestReenrollRefusesASubjectThisEndpointNeverIssued(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	// This is the check that stands in for the TLS client certificate RFC 7030
	// would authenticate with, so it is the load-bearing one.
	_, _, err := svc.Reenroll(context.Background(), e, cred, testCSR(t, csrOptions{}))
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", statusOf(err))
	}
	if !strings.Contains(err.Error(), "simpleenroll") {
		t.Errorf("error = %q, want it to point at the enrollment endpoint", err)
	}
}

func TestReenrollRefusesOutsideTheRenewalWindow(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	csr := testCSR(t, csrOptions{})
	subject := appPKI.RenderSubject(csr.RawSubject, csr.Subject)
	// Expires in a year; the window opens 73 days out.
	repo.seedRenewable(e, cred, subject, time.Now().AddDate(0, 0, 365), "")

	_, _, err := svc.Reenroll(context.Background(), e, cred, csr)
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", statusOf(err))
	}
	// A device that asks too early is told when to come back, so a misconfigured
	// renewal timer reports itself rather than failing silently.
	if !strings.Contains(err.Error(), "cannot be renewed until") {
		t.Errorf("error = %q, want it to name the date renewal opens", err)
	}
}

func TestReenrollSucceedsInsideTheRenewalWindow(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	csr := testCSR(t, csrOptions{})
	subject := appPKI.RenderSubject(csr.RawSubject, csr.Subject)
	repo.seedRenewable(e, cred, subject, time.Now().AddDate(0, 0, 10), "")

	if _, _, err := svc.Reenroll(context.Background(), e, cred, csr); err != nil {
		t.Fatalf("Reenroll: %v", err)
	}
	if issuer.issued != 1 {
		t.Errorf("issued %d certificates, want 1", issuer.issued)
	}
	if len(repo.enrollments) != 1 || repo.enrollments[0].Operation != OperationReenroll {
		t.Errorf("enrollments = %+v, want one reenroll row", repo.enrollments)
	}
}

// ---------------------------------------------------------------------------
// Recording refusals
// ---------------------------------------------------------------------------

// TestRefusalsCarryAFailureToRecord is what makes the endpoint page useful when
// a device is being turned away. Every refusal an operator could act on has to
// come back with the context needed to write a row, or the log stays empty in
// exactly the situation someone is looking at it.
func TestRefusalsCarryAFailureToRecord(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	e.SubjectPattern = `CN=gw-\d+\.example\.internal`
	repo.endpoints[e.ID] = e
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	cases := []struct {
		name      string
		run       func() (appPKI.Certificate, *Failure, error)
		operation string
	}{
		{"policy", func() (appPKI.Certificate, *Failure, error) {
			return svc.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{commonName: "laptop.example.com"}))
		}, OperationEnroll},
		{"weak key", func() (appPKI.Certificate, *Failure, error) {
			return svc.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{rsaBits: 1024}))
		}, OperationEnroll},
		{"eku outside the ceiling", func() (appPKI.Certificate, *Failure, error) {
			return svc.Enroll(context.Background(), e, cred,
				testCSR(t, csrOptions{ekus: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 3}}}))
		}, OperationEnroll},
		{"never enrolled", func() (appPKI.Certificate, *Failure, error) {
			return svc.Reenroll(context.Background(), e, cred, testCSR(t, csrOptions{}))
		}, OperationReenroll},
	}
	for _, tc := range cases {
		_, failure, err := tc.run()
		if err == nil {
			t.Errorf("%s: expected a refusal", tc.name)
			continue
		}
		if failure == nil {
			t.Errorf("%s: refused with no Failure to record", tc.name)
			continue
		}
		if failure.CredentialID != cred.ID {
			t.Errorf("%s: CredentialID = %q, want %q", tc.name, failure.CredentialID, cred.ID)
		}
		if failure.Operation != tc.operation {
			t.Errorf("%s: Operation = %q, want %q", tc.name, failure.Operation, tc.operation)
		}
		if failure.Subject == "" {
			t.Errorf("%s: no subject recorded; the log row would not say who was refused", tc.name)
		}
		// The reason the operator reads and the reason the device was given are
		// the same string, so the two accounts of an incident cannot disagree.
		if failure.Reason != err.Error() {
			t.Errorf("%s: Reason = %q, want the client's message %q", tc.name, failure.Reason, err.Error())
		}
	}
}

// TestInternalFailuresAreNotRecordedAsRefusals: a database fault is not the
// device's doing, and writing it to the endpoint's log would send an operator
// looking at a device that did nothing wrong.
func TestInternalFailuresAreNotRecordedAsRefusals(t *testing.T) {
	repo := newFakeStore()
	e := repo.seedEndpoint()
	svc, _ := newTestService(repo)
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	broken := NewService(brokenEnrollmentStore{repo}, &fakeIssuer{}, fakeCertificates{}, testURL)
	_, failure, err := broken.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{}))
	if err == nil {
		t.Fatal("a failed enrollment write was reported as success")
	}
	if failure != nil {
		t.Error("an internal fault produced a Failure, which would blame the device")
	}
}

// TestSuccessfulEnrollmentRecordsIssued keeps the log's two outcomes honest: the
// status column has to distinguish them, because EndpointSummaries counts on it.
func TestSuccessfulEnrollmentRecordsIssued(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()
	cred, _ := mustCredential(t, svc, e, CredentialSpec{})

	if _, _, err := svc.Enroll(context.Background(), e, cred, testCSR(t, csrOptions{})); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(repo.enrollments) != 1 {
		t.Fatalf("recorded %d enrollments, want 1", len(repo.enrollments))
	}
	if got := repo.enrollments[0]; got.Status != StatusIssued || got.CertificateID == "" {
		t.Errorf("recorded %+v, want an issued row carrying its certificate", got)
	}
}

// ---------------------------------------------------------------------------
// CA distribution
// ---------------------------------------------------------------------------

func TestCACertsReturnsTheWholeChain(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()

	body, err := svc.CACerts(context.Background(), e)
	if err != nil {
		t.Fatalf("CACerts: %v", err)
	}
	certs := parseCertsOnly(t, body)
	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want the issuing CA and its root", len(certs))
	}
	if certs[0].Subject.CommonName != "Test Issuing CA" || certs[1].Subject.CommonName != "Test Root" {
		t.Errorf("chain = %q, %q; want the issuing CA first",
			certs[0].Subject.CommonName, certs[1].Subject.CommonName)
	}
}

func TestCSRAttrsDescribesTheCAsAlgorithm(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := repo.seedEndpoint()

	body, ok, err := svc.CSRAttrs(context.Background(), e)
	if err != nil {
		t.Fatalf("CSRAttrs: %v", err)
	}
	if !ok {
		t.Fatal("an EC CA advertised nothing; a client cannot tell which curve to use")
	}
	if len(body) == 0 {
		t.Error("the CsrAttrs body is empty")
	}
}
