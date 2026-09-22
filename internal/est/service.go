package est

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/jacksongrow0/SimpleSCEP/internal/scep"
)

// The service depends on narrow interfaces rather than on concrete
// repositories, so its policy can be exercised without a database and without a
// KMS. Repository, appPKI.Service, and scep.Repository satisfy them structurally.
type store interface {
	Endpoints(ctx context.Context, orgID string) ([]Endpoint, error)
	EndpointByID(ctx context.Context, orgID, id string) (Endpoint, error)
	InsertEndpoint(ctx context.Context, e Endpoint) error
	DeleteEndpoint(ctx context.Context, orgID, id string) error
	SetEnabled(ctx context.Context, orgID, id string, enabled bool) error
	UpdatePolicy(ctx context.Context, orgID, id string, p PolicyUpdate) error

	CreateCredential(ctx context.Context, c Credential) error
	CredentialByUsername(ctx context.Context, endpointID, username string) (Credential, error)
	Credentials(ctx context.Context, endpointID string) ([]Credential, error)
	TouchCredential(ctx context.Context, id string) error
	RevokeCredential(ctx context.Context, orgID, endpointID, id string) error

	CreateEnrollment(ctx context.Context, n Enrollment) error
	RenewableCertificate(ctx context.Context, endpointID, credentialID, username, subject string) (RenewableCert, error)
}

// issuer is the signing seam, so endpoint administration and policy can be
// tested without a KMS.
type issuer interface {
	Issue(ctx context.Context, req appPKI.IssueRequest) (appPKI.Certificate, error)
}

// certificates is the slice of the PKI repository EST reads: the CA whose chain
// /cacerts returns.
type certificates interface {
	CA(ctx context.Context, orgID, id string) (appPKI.CertificateAuthority, error)
}

type Service struct {
	repo      store
	pki       issuer
	pkiRepo   certificates
	publicURL string
}

func NewService(repo store, pki issuer, pkiRepo certificates, publicURL string) Service {
	return Service{repo: repo, pki: pki, pkiRepo: pkiRepo,
		publicURL: strings.TrimRight(publicURL, "/")}
}

// ---------------------------------------------------------------------------
// Endpoint administration
// ---------------------------------------------------------------------------

// EndpointURL is the base a client is configured with. RFC 7030 §3.2.2 reserves
// a free-form label between /.well-known/est and the operation so one server can
// front several CAs, which is exactly what the endpoint ID is doing here.
func (s Service) EndpointURL(id string) string {
	return s.publicURL + "/.well-known/est/" + id
}

// CreateEndpoint adds an endpoint.
func (s Service) CreateEndpoint(ctx context.Context, orgID, name, caID string) (Endpoint, error) {
	name = strings.TrimSpace(name)
	if err := validEndpointName(name); err != nil {
		return Endpoint{}, err
	}
	if _, err := uuid.Parse(caID); err != nil {
		return Endpoint{}, fmt.Errorf("choose a certificate authority to issue from")
	}
	// SANPattern starts permissive rather than at its zero value. An empty SAN
	// pattern permits no subject alternative names at all (see NamePolicy), which
	// is the right default for an endpoint an administrator has deliberately
	// locked down, but the wrong one for an endpoint that was just created and
	// has not been configured either way — that should work out of the box and
	// be narrowed from here, not start silently refusing every SAN.
	e := Endpoint{
		ID:                uuid.NewString(),
		OrganizationID:    orgID,
		CAID:              caID,
		Name:              name,
		ValidityDays:      DefaultValidityDays,
		RenewalWindowDays: DefaultRenewalWindowDays,
		AllowedEKUs:       appPKI.EKUClientAuth,
		SANPattern:        ".*",
	}
	if err := s.repo.InsertEndpoint(ctx, e); err != nil {
		return Endpoint{}, err
	}
	return e, nil
}

func validEndpointName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("give the endpoint a name")
	case len(name) > 64:
		return fmt.Errorf("endpoint names are at most 64 characters")
	}
	return nil
}

func (s Service) SetEnabled(ctx context.Context, orgID, id string, enabled bool) error {
	return s.repo.SetEnabled(ctx, orgID, id, enabled)
}

func (s Service) DeleteEndpoint(ctx context.Context, orgID, id string) error {
	return s.repo.DeleteEndpoint(ctx, orgID, id)
}

// UpdatePolicy validates and stores the issuance policy. The patterns are
// compiled here rather than at enrollment time so a typo is reported to the
// administrator who made it, instead of to a device at three in the morning.
func (s Service) UpdatePolicy(ctx context.Context, orgID, id string, p PolicyUpdate) error {
	p.Name = strings.TrimSpace(p.Name)
	if err := validEndpointName(p.Name); err != nil {
		return err
	}
	if p.ValidityDays < 1 || p.ValidityDays > 3650 {
		return fmt.Errorf("validity must be between 1 and 3650 days")
	}
	if p.RenewalWindowDays < 1 || p.RenewalWindowDays > 365 {
		return fmt.Errorf("the renewal window must be between 1 and 365 days")
	}
	for _, pattern := range []string{p.SubjectPattern, p.SANPattern} {
		if pattern == "" {
			continue
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("%q is not a valid regular expression", pattern)
		}
	}
	if _, err := appPKI.ValidateEKUs(enroll.SplitCSV(p.AllowedEKUs)); err != nil {
		return err
	}
	return s.repo.UpdatePolicy(ctx, orgID, id, p)
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// CreateCredential mints an HTTP Basic identity and returns the password once.
// Only the argon2id verifier is stored, so this return value is the single
// opportunity to copy it; the administration page is built around that.
func (s Service) CreateCredential(ctx context.Context, e Endpoint, spec CredentialSpec) (Credential, string, error) {
	username := strings.TrimSpace(spec.Username)
	if username == "" {
		return Credential{}, "", fmt.Errorf("give the credential a username")
	}
	if len(username) > 64 {
		return Credential{}, "", fmt.Errorf("usernames are at most 64 characters")
	}
	if strings.ContainsAny(username, ": \t\r\n") {
		// A colon separates the two halves of a Basic credential, so one inside
		// the username makes the pair ambiguous on the wire.
		return Credential{}, "", fmt.Errorf("usernames cannot contain spaces or colons")
	}
	if spec.TTLHours < 0 {
		return Credential{}, "", fmt.Errorf("an expiry cannot be in the past")
	}
	password, err := enroll.RandomSecret()
	if err != nil {
		return Credential{}, "", err
	}
	hash, err := enroll.HashSecret(password)
	if err != nil {
		return Credential{}, "", err
	}
	c := Credential{
		ID:             uuid.NewString(),
		OrganizationID: e.OrganizationID,
		EndpointID:     e.ID,
		Label:          strings.TrimSpace(spec.Label),
		Username:       username,
		SecretHash:     hash,
		IdentifierPin:  strings.Join(enroll.SplitCSV(spec.Identifiers), ","),
	}
	if spec.TTLHours > 0 {
		expires := time.Now().Add(time.Duration(spec.TTLHours) * time.Hour)
		c.ExpiresAt = &expires
	}
	if err := s.repo.CreateCredential(ctx, c); err != nil {
		return Credential{}, "", err
	}
	return c, password, nil
}

func (s Service) RevokeCredential(ctx context.Context, orgID, endpointID, id string) error {
	return s.repo.RevokeCredential(ctx, orgID, endpointID, id)
}

// Authenticate resolves the credential behind a Basic exchange.
//
// The argon2 verification runs even when the username is unknown, against a
// throwaway hash, so the time a wrong username takes matches the time a wrong
// password takes. Without that, the response time enumerates valid usernames.
func (s Service) Authenticate(ctx context.Context, e Endpoint, username, password string) (Credential, error) {
	c, err := s.repo.CredentialByUsername(ctx, e.ID, username)
	if err != nil {
		_ = enroll.VerifySecret(decoyHash, password)
		return Credential{}, unauthorized()
	}
	if !enroll.VerifySecret(c.SecretHash, password) {
		return Credential{}, unauthorized()
	}
	if !c.Usable(time.Now()) {
		return Credential{}, unauthorized()
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Client operations
// ---------------------------------------------------------------------------

// CACerts returns the endpoint's CA chain as the base64 degenerate PKCS#7 body
// of RFC 7030 §4.1.3. It is the one operation that must never require
// authentication: a client that does not yet trust the CA has to be able to
// fetch it before anything else can succeed.
func (s Service) CACerts(ctx context.Context, e Endpoint) ([]byte, error) {
	ca, err := s.pkiRepo.CA(ctx, e.OrganizationID, e.CAID)
	if err != nil {
		return nil, err
	}
	certs, err := parseChain(ca.CertificatePEM, ca.ChainPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("endpoint %s has no CA certificate to publish", e.ID)
	}
	return certsOnly(certs)
}

// CSRAttrs describes what this endpoint expects a request to contain. The second
// return value is false when there is nothing worth saying, which the handler
// answers with the 204 §4.5 requires.
func (s Service) CSRAttrs(ctx context.Context, e Endpoint) ([]byte, bool, error) {
	ca, err := s.pkiRepo.CA(ctx, e.OrganizationID, e.CAID)
	if err != nil {
		return nil, false, err
	}
	certs, err := parseChain(ca.CertificatePEM)
	if err != nil || len(certs) == 0 {
		return nil, false, err
	}
	return csrAttributes(certs[0], enroll.SplitCSV(e.AllowedEKUs))
}

// Enroll issues a certificate for a CSR. The checks run cheapest first, so a
// request that was never going to be issued is refused before it costs a KMS
// operation: local policy, then the signature.
// A non-nil *Failure accompanies every refusal the endpoint's owner could act
// on, for the handler to record once the request transaction is rolled back.
func (s Service) Enroll(ctx context.Context, e Endpoint, cred Credential, csr *x509.CertificateRequest) (appPKI.Certificate, *Failure, error) {
	return s.enroll(ctx, e, cred, csr, OperationEnroll)
}

// Reenroll issues against a subject this endpoint has already certified.
//
// RFC 7030 authenticates /simplereenroll with the certificate the client holds,
// presented over mutual TLS. That certificate never reaches this process, so the
// binding is checked against what the endpoint issued instead: the subject must
// hold a live certificate from this endpoint, and it must be close enough to
// expiry to be worth renewing. A client that has drifted outside the window is
// told when to come back rather than being refused without explanation.
func (s Service) Reenroll(ctx context.Context, e Endpoint, cred Credential, csr *x509.CertificateRequest) (appPKI.Certificate, *Failure, error) {
	subject := appPKI.RenderSubject(csr.RawSubject, csr.Subject)
	refuse := refusal(cred, subject, OperationReenroll)

	live, err := s.repo.RenewableCertificate(ctx, e.ID, cred.ID, cred.Username, subject)
	if err != nil {
		// Deliberately the same answer whether the subject was never enrolled or
		// was enrolled by somebody else's credential: a caller holding one
		// credential learns nothing about what another has enrolled.
		return refuse(http.StatusForbidden,
			"this credential holds no live certificate for %q; enroll it at /simpleenroll first", subject)
	}
	opensAt := live.ExpiresAt.AddDate(0, 0, -e.RenewalWindowDays)
	if time.Now().Before(opensAt) {
		return refuse(http.StatusForbidden,
			"this certificate cannot be renewed until %s, %d days before it expires",
			opensAt.Format("2 January 2006"), e.RenewalWindowDays)
	}
	if e.ReenrollRequiresSameKey {
		if err := samePublicKey(live.CertificatePEM, csr); err != nil {
			return refuse(http.StatusForbidden, "%s", err.Error())
		}
	}
	return s.enroll(ctx, e, cred, csr, OperationReenroll)
}

// samePublicKey reports whether the CSR carries the same public key as the
// certificate being renewed.
//
// parseCSR has already verified the CSR's self-signature, so a matching
// SubjectPublicKeyInfo means the caller holds the private key the live
// certificate was issued for. Comparing the encoded SPKI rather than the parsed
// key is the whole test: it is exact, and it needs no per-algorithm cases.
func samePublicKey(certificatePEM string, csr *x509.CertificateRequest) error {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		return errors.New("the certificate on record could not be read")
	}
	live, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("the certificate on record could not be read")
	}
	if !bytes.Equal(live.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return errors.New("this endpoint requires re-enrollment to reuse the key of the certificate being renewed")
	}
	return nil
}

// refusal builds the "reject and record" return for one enrollment attempt, so
// every refusal below carries the same context without repeating it. The reason
// written to the log is the message the client is given, which is what makes the
// endpoint page and the device's own error agree.
func refusal(cred Credential, subject, operation string) func(status int, format string, args ...any) (appPKI.Certificate, *Failure, error) {
	return func(status int, format string, args ...any) (appPKI.Certificate, *Failure, error) {
		err := errorf(status, format, args...)
		return appPKI.Certificate{}, &Failure{CredentialID: cred.ID, Subject: subject,
			Operation: operation, Reason: err.Message}, err
	}
}

func (s Service) enroll(ctx context.Context, e Endpoint, cred Credential, csr *x509.CertificateRequest, operation string) (appPKI.Certificate, *Failure, error) {
	subject := appPKI.RenderSubject(csr.RawSubject, csr.Subject)
	refuse := refusal(cred, subject, operation)

	if err := enroll.ValidatePublicKey(csr.PublicKey); err != nil {
		return refuse(http.StatusBadRequest, "%s", err.Error())
	}
	if err := checkNames(e, subject, scep.CSRSANNames(csr)); err != nil {
		var estErr *Error
		if !errors.As(err, &estErr) {
			return appPKI.Certificate{}, nil, err
		}
		return refuse(estErr.Status, "%s", estErr.Message)
	}
	if err := checkIdentifierPin(cred, csr); err != nil {
		return refuse(http.StatusForbidden, "%s", err.Error())
	}
	requested, err := scep.RequestedEKUs(csr)
	if err != nil {
		return refuse(http.StatusBadRequest, "%s", err.Error())
	}
	ekus, err := scep.ResolveEKUs(e.AllowedEKUs, requested)
	if err != nil {
		return refuse(http.StatusForbidden, "%s", err.Error())
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	cert, err := s.pki.Issue(ctx, appPKI.IssueRequest{
		OrgID:   e.OrganizationID,
		CAID:    e.CAID,
		CSRPEM:  string(csrPEM),
		Days:    e.ValidityDays,
		EKUs:    ekus,
		Purpose: "est",
		Profile: appPKI.CertProfileEST,
	})
	if err != nil {
		// Issue's refusal is the CA's own profile — something the operator of
		// the device can act on.
		return refuse(http.StatusForbidden, "%s", err.Error())
	}
	record := Enrollment{
		OrganizationID: e.OrganizationID,
		EndpointID:     e.ID,
		CredentialID:   cred.ID,
		CertificateID:  cert.ID,
		Subject:        subject,
		Operation:      operation,
		Status:         StatusIssued,
	}
	if err := s.repo.CreateEnrollment(ctx, record); err != nil {
		return appPKI.Certificate{}, nil, err
	}
	// A last-seen stamp is for the administrator's benefit; failing to write it
	// must not undo an issuance that has already happened.
	_ = s.repo.TouchCredential(ctx, cred.ID)
	return cert, nil, nil
}

// RecordFailure writes a refused enrollment on its own transaction, because the
// public handler rolls its request transaction back before replying.
//
// Every error is swallowed: a log that cannot be written must not change the
// answer the device already received.
func (s Service) RecordFailure(ctx context.Context, db *sql.DB, e Endpoint, f Failure) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txctx, "app.organization_id", e.OrganizationID); err != nil {
		return
	}
	record := Enrollment{
		OrganizationID: e.OrganizationID,
		EndpointID:     e.ID,
		CredentialID:   f.CredentialID,
		Subject:        f.Subject,
		Operation:      f.Operation,
		Status:         StatusFailed,
		FailureReason:  truncate(f.Reason, maxFailureReason),
	}
	if err := s.repo.CreateEnrollment(txctx, record); err != nil {
		log.Printf("est endpoint=%s: refusal not recorded: %v", e.ID, err)
		return
	}
	_ = tx.Commit()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// CertificateResponse renders an issued certificate as the enrollment response
// body: base64 of a degenerate PKCS#7 holding the leaf alone, which is what
// §4.2.3 specifies.
func CertificateResponse(cert appPKI.Certificate) ([]byte, error) {
	certs, err := parseChain(cert.CertificatePEM)
	if err != nil {
		return nil, err
	}
	return certsOnly(certs)
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------

// checkNames applies the endpoint's subject and SAN patterns. The subject is the
// rendering the certificate will carry, so what an administrator sees in the log
// is what the pattern was tested against, and each subjectAltName is tested on
// its own — see pki.NamePolicy for what the two rules used to share and why that
// was wrong.
func checkNames(e Endpoint, subject string, sans []string) error {
	err := (appPKI.NamePolicy{Subject: e.SubjectPattern, SAN: e.SANPattern}).Check(subject, sans)
	switch {
	case errors.Is(err, appPKI.ErrPolicyInvalid):
		// Already validated on the way in, so this is a corrupted row rather
		// than something the client did; it must not read as the client's fault.
		return fmt.Errorf("endpoint %s has an invalid issuance policy: %w", e.ID, err)
	case err != nil:
		return errorf(http.StatusForbidden,
			"the request is not permitted by this endpoint's issuance policy")
	}
	return nil
}

// checkIdentifierPin applies a credential's own restriction, which narrows the
// endpoint's policy rather than widening it: a credential handed to one team can
// be pinned to the names that team is responsible for.
func checkIdentifierPin(cred Credential, csr *x509.CertificateRequest) error {
	pinned := enroll.SplitCSV(cred.IdentifierPin)
	if len(pinned) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, name := range pinned {
		allowed[strings.ToLower(name)] = true
	}
	// Every SAN form, not just the ones x509 models. pki copies the requested
	// SAN DER into the issued certificate untouched, so reading only DNSNames and
	// IPAddresses here would let a pinned credential obtain a certificate
	// carrying a userPrincipalName naming somebody else entirely.
	requested := scep.CSRSANNames(csr)
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		requested = append(requested, cn)
	}
	if len(requested) == 0 {
		return errorf(http.StatusForbidden, "this credential may only enroll %s", strings.Join(pinned, ", "))
	}
	for _, name := range requested {
		if !allowed[strings.ToLower(name)] {
			return errorf(http.StatusForbidden,
				"this credential may not enroll %q; it is pinned to %s", name, strings.Join(pinned, ", "))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Secrets
//
// The argon2id parameters and encoding live in internal/enroll, shared with the
// SCEP challenges and ACME external-account keys, so a change to the cost
// parameters cannot be applied to one protocol and forgotten in the others.
// ---------------------------------------------------------------------------

// decoyHash is verified against when no credential matched, so that an unknown
// username costs the same time as a wrong password. It is a hash of a value
// nobody holds.
var decoyHash = func() string {
	h, err := enroll.HashSecret("est-decoy")
	if err != nil {
		return ""
	}
	return h
}()
