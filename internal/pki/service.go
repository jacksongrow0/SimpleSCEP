package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Store is the persistence surface Service depends on; Repository satisfies
// it, and tests substitute an in-memory fake.
type Store interface {
	CreateCA(ctx context.Context, ca CertificateAuthority) (string, error)
	CA(ctx context.Context, orgID, id string) (CertificateAuthority, error)
	CAs(ctx context.Context, orgID string) ([]CertificateAuthority, error)
	RootCA(ctx context.Context, orgID string) (CertificateAuthority, error)
	RecordCertificate(ctx context.Context, cert Certificate) (string, error)
	Certificate(ctx context.Context, orgID, id string) (Certificate, error)
	Certificates(ctx context.Context, orgID string) ([]Certificate, error)
	CertificateBySerial(ctx context.Context, orgID, caID, serial string) (Certificate, error)
	Revocations(ctx context.Context, orgID string) ([]Revocation, error)
	RevokeCertificate(ctx context.Context, orgID, id, reason string) error
	CRLPublication(ctx context.Context, orgID, caID string) (CRLPublication, error)
	LockCRL(ctx context.Context, caID string) error
	SaveCRL(ctx context.Context, publication CRLPublication) error
	SaveCRLError(ctx context.Context, orgID, caID, message string) error
	CachedOCSP(ctx context.Context, orgID, caID, serial string, hash int, status string, now time.Time) (OCSPCacheEntry, error)
	SaveOCSP(ctx context.Context, orgID, caID, serial string, hash int, entry OCSPCacheEntry) error
	ActiveIdentityCount(ctx context.Context, orgID string) (int, error)
	RecordSigning(ctx context.Context, orgID, caID, userID, keyVersion, csrDigest, serial, purpose string) error
	RecordCAEvent(ctx context.Context, orgID, caID, userID, keyVersion, purpose string) error
	UpdateCAStatus(ctx context.Context, orgID, id, status string) error
	MarkCADeleted(ctx context.Context, orgID, id string) error
	ActiveChildCount(ctx context.Context, orgID, id string) (int, error)
	IssuingCACount(ctx context.Context, orgID string) (int, error)
	EnabledSCEPEndpointCount(ctx context.Context, orgID, caID string) (int, error)
	EnabledACMEEndpointCount(ctx context.Context, orgID, caID string) (int, error)
	EnabledESTEndpointCount(ctx context.Context, orgID, caID string) (int, error)

	CreateCAImportJob(ctx context.Context, job CAImportJob) (string, error)
	CAImportJob(ctx context.Context, orgID, id string) (CAImportJob, error)
	CAImportJobs(ctx context.Context, orgID string) ([]CAImportJob, error)
	UpdateCAImportJobState(ctx context.Context, orgID, id, state, failureReason string) error
	SetCAImportJobWrapping(ctx context.Context, orgID, id, state, wrappingPEM, method string, expiresAt time.Time) error
	SetCAImportJobKeyVersion(ctx context.Context, orgID, id, keyVersion string) error
	CompleteCAImportJob(ctx context.Context, orgID, id, caID string) error
	CancelCAImportJob(ctx context.Context, orgID, id, userID string) error
}

type Service struct {
	repo      Store
	provider  KeyProvider
	publicURL string
}

func NewService(repo Store, provider KeyProvider) Service {
	return NewServiceWithURL(repo, provider, "https://example.com")
}

func NewServiceWithURL(repo Store, provider KeyProvider, publicURL string) Service {
	return Service{repo: repo, provider: provider, publicURL: strings.TrimRight(publicURL, "/")}
}

func (s Service) CreateCA(ctx context.Context, req CreateCARequest) (CertificateAuthority, error) {
	if req.Type != CATypeRoot && req.Type != CATypeIssuing {
		return CertificateAuthority{}, fmt.Errorf("invalid CA type")
	}
	if req.Name == "" {
		return CertificateAuthority{}, fmt.Errorf("CA name required")
	}
	if req.Type == CATypeRoot {
		if _, err := s.repo.RootCA(ctx, req.OrgID); err == nil {
			return CertificateAuthority{}, fmt.Errorf("root CA already exists")
		} else if !errors.Is(err, sql.ErrNoRows) {
			return CertificateAuthority{}, err
		}
	}
	if req.Type == CATypeIssuing && req.ParentID == "" {
		return CertificateAuthority{}, fmt.Errorf("parent root CA required")
	}
	days, err := validityDays(req.Type, req.Days)
	if err != nil {
		return CertificateAuthority{}, err
	}
	algorithm, err := ValidateAlgorithm(req.Algorithm)
	if err != nil {
		return CertificateAuthority{}, err
	}
	protection := strings.TrimSpace(req.Protection)
	if protection == "" {
		protection = ProtectionHSM
		if !s.provider.SupportsHSM() {
			protection = ProtectionSoftware
		}
	} else if protection, err = ValidateProtection(protection); err != nil {
		return CertificateAuthority{}, err
	}
	if protection == ProtectionHSM && !s.provider.SupportsHSM() {
		return CertificateAuthority{}, fmt.Errorf("the configured key provider does not support HSM keys")
	}
	ekus, err := ValidateEKUs(req.EKUs)
	if err != nil {
		return CertificateAuthority{}, err
	}
	pathLen := 1
	if req.MaxPathLen != nil {
		pathLen = *req.MaxPathLen
	}
	if pathLen < 0 || pathLen > 4 {
		return CertificateAuthority{}, fmt.Errorf("path length must be between 0 and 4")
	}
	if req.Type == CATypeIssuing {
		pathLen = 0
	}
	var name pkix.Name
	if req.subjectName != nil {
		name = *req.subjectName
	} else if name, err = BuildSubject(req.Subject); err != nil {
		return CertificateAuthority{}, err
	}
	notBefore, notAfter := DaysFromNow(days)
	var parent *x509.Certificate
	var parentKey KeyInfo
	chain := ""
	// A certificate's AIA names where to fetch *its issuer*, so a self-signed
	// root carries none — there is nothing above it to fetch.
	issuerURL := ""
	if req.Type == CATypeIssuing {
		parentCA, err := s.repo.CA(ctx, req.OrgID, req.ParentID)
		if err != nil {
			return CertificateAuthority{}, err
		}
		parent, err = parseCertificate(parentCA.CertificatePEM)
		if err != nil {
			return CertificateAuthority{}, err
		}
		parentKey, err = s.provider.KeyInfo(ctx, parentCA.KMSKeyVersion)
		if err != nil {
			return CertificateAuthority{}, err
		}
		// The issuing CA must not outlive its parent.
		if notAfter.After(parent.NotAfter) {
			notAfter = parent.NotAfter
		}
		// An issuing CA may only carry EKUs its root CA allows.
		if err := ekusWithinParent(ekus, parentCA.IssuanceEKUs); err != nil {
			return CertificateAuthority{}, err
		}
		chain = parentCA.CertificatePEM + parentCA.ChainPEM
		issuerURL = s.PublicEndpoint(parentCA.OrganizationID, parentCA.ID, "issuer")
	}
	key, err := s.provider.CreateSigningKey(ctx, CreateKeyRequest{OrgID: req.OrgID, CAName: req.Name, CAType: req.Type, Algorithm: algorithm, Protection: protection})
	if err != nil {
		return CertificateAuthority{}, err
	}
	if err := validateKeyInfo(key); err != nil {
		return CertificateAuthority{}, s.destroyOnError(ctx, key.Name, err)
	}
	if !keyMatchesProtection(key, protection) {
		return CertificateAuthority{}, s.destroyOnError(ctx, key.Name,
			fmt.Errorf("key provider returned %s protection for a %s CA request", strings.ToLower(key.ProtectionLevel), protection))
	}
	template, err := caTemplate(name, pathLen, key.PublicKey, notBefore, notAfter, issuerURL)
	if err != nil {
		return CertificateAuthority{}, s.destroyOnError(ctx, key.Name, err)
	}
	signerKey := key
	if req.Type == CATypeIssuing {
		signerKey = parentKey
	} else {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.PublicKey, NewKMSSigner(ctx, s.provider, signerKey))
	if err != nil {
		return CertificateAuthority{}, s.destroyOnError(ctx, key.Name, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ca := CertificateAuthority{
		OrganizationID: req.OrgID,
		ParentID:       req.ParentID,
		Name:           req.Name,
		Type:           req.Type,
		Status:         CAStatusActive,
		Subject:        name.String(),
		Algorithm:      key.Algorithm,
		KMSKeyVersion:  key.Name,
		CertificatePEM: string(certPEM),
		ChainPEM:       chain,
		ExportPosture:  exportPosture(key.ProtectionLevel, false),
		IssuanceEKUs:   strings.Join(ekus, ","),
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}
	ca.ID, err = s.repo.CreateCA(ctx, ca)
	if err != nil {
		return CertificateAuthority{}, s.destroyOnError(ctx, key.Name, err)
	}
	if err := s.repo.RecordSigning(ctx, req.OrgID, ca.ID, req.UserID, signerKey.Name, "", template.SerialNumber.Text(16), req.Type+"_ca"); err != nil {
		return CertificateAuthority{}, s.destroyOnError(ctx, key.Name, err)
	}
	if req.Type == CATypeIssuing {
		// The CA remains usable if KMS publication is temporarily unavailable;
		// the error is persisted and the renewal worker retries it.
		_ = s.PublishCRL(ctx, req.OrgID, ca.ID)
	}
	return ca, nil
}

// destroyOnError best-effort destroys a KMS key version whose CA could not be
// completed, so failed requests don't leak billable keys. The original error
// is always returned.
func (s Service) destroyOnError(ctx context.Context, keyVersion string, cause error) error {
	if err := s.provider.DestroyKeyVersion(ctx, keyVersion); err != nil {
		return fmt.Errorf("%w (KMS key %s could not be cleaned up: %v)", cause, keyVersion, err)
	}
	return cause
}

// checkEndpointBindings refuses an operation that would strand an enrollment
// endpoint. Both protocols bind a CA at endpoint creation and cannot be
// rebound, so deleting or rotating the CA under a live endpoint would leave it
// answering requests it can no longer fulfil.
//
// Each protocol is counted separately so the message names the one the
// administrator has to go and deal with.
func (s Service) checkEndpointBindings(ctx context.Context, orgID, caID, verb string) error {
	scepCount, err := s.repo.EnabledSCEPEndpointCount(ctx, orgID, caID)
	if err != nil {
		return err
	}
	if scepCount > 0 {
		return fmt.Errorf("disable or rebind SCEP endpoints before %s this CA", verb)
	}
	acmeCount, err := s.repo.EnabledACMEEndpointCount(ctx, orgID, caID)
	if err != nil {
		return err
	}
	if acmeCount > 0 {
		return fmt.Errorf("disable or rebind ACME endpoints before %s this CA", verb)
	}
	estCount, err := s.repo.EnabledESTEndpointCount(ctx, orgID, caID)
	if err != nil {
		return err
	}
	if estCount > 0 {
		return fmt.Errorf("disable or rebind EST endpoints before %s this CA", verb)
	}
	return nil
}

// RotateIssuingCA replaces an issuing CA with a fresh key and certificate
// carrying the same subject, algorithm, and EKU profile, then retires the old
// CA. It is a one-for-one replacement rather than an additional issuer.
func (s Service) RotateIssuingCA(ctx context.Context, orgID, userID, caID string) (CertificateAuthority, error) {
	if err := s.checkEndpointBindings(ctx, orgID, caID, "rotating"); err != nil {
		return CertificateAuthority{}, err
	}
	ca, err := s.repo.CA(ctx, orgID, caID)
	if err != nil {
		return CertificateAuthority{}, err
	}
	if ca.Type != CATypeIssuing || ca.ParentID == "" {
		return CertificateAuthority{}, fmt.Errorf("issuing CA required")
	}
	cert, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return CertificateAuthority{}, err
	}
	rotated, err := s.CreateCA(ctx, CreateCARequest{
		OrgID:    orgID,
		UserID:   userID,
		Name:     ca.Name + " rotation " + time.Now().UTC().Format("20060102"),
		Type:     CATypeIssuing,
		ParentID: ca.ParentID,
		// The replacement gets the CA's original validity span, not the time
		// it had left — rotating a near-expired CA must not produce an
		// already-expired one.
		Days:        int(ca.NotAfter.Sub(ca.NotBefore).Hours() / 24),
		Algorithm:   ca.Algorithm,
		Protection:  protectionFromExportPosture(ca.ExportPosture),
		EKUs:        strings.Split(ca.IssuanceEKUs, ","),
		subjectName: &cert.Subject,
	})
	if err != nil {
		return CertificateAuthority{}, err
	}
	if err := s.repo.UpdateCAStatus(ctx, orgID, ca.ID, CAStatusRetired); err != nil {
		return CertificateAuthority{}, err
	}
	// Recorded against the CA being replaced, not the replacement: CreateCA has
	// already logged the new CA's own creation, and what a reader needs from this
	// row is that this key stopped being used and which key took over.
	if err := s.repo.RecordCAEvent(ctx, orgID, ca.ID, userID, ca.KMSKeyVersion, PurposeRotatedCA); err != nil {
		return CertificateAuthority{}, err
	}
	return rotated, nil
}

// SetCAStatus changes a CA's status and records it.
//
// The status change and its audit row are written together rather than left to
// the handler, for the same reason DeleteCA pairs them: taking a CA out of
// service is a production-affecting act, and a caller that forgot the second
// call would leave no trace of it. The handler keeps the checks that decide
// whether the change is allowed at all — endpoint bindings, and retirement
// being terminal — since those are about the request, not the record.
func (s Service) SetCAStatus(ctx context.Context, orgID, userID, caID, status string) error {
	ca, err := s.repo.CA(ctx, orgID, caID)
	if err != nil {
		return err
	}
	if err := s.repo.UpdateCAStatus(ctx, orgID, ca.ID, status); err != nil {
		return err
	}
	return s.repo.RecordCAEvent(ctx, orgID, ca.ID, userID, ca.KMSKeyVersion, caStatusPurpose(status))
}

// caStatusPurpose names a status change in the signing audit's vocabulary.
func caStatusPurpose(status string) string {
	switch status {
	case CAStatusActive:
		return PurposeActivatedCA
	case CAStatusInactive:
		return PurposeDeactivatedCA
	case CAStatusRetired:
		return PurposeRetiredCA
	}
	return PurposeOtherCA
}

// DeleteCA asks the configured provider to destroy the CA key and then hides
// the CA from the app. Recovery and retention follow that provider's key
// deletion policy; the local fake destroys immediately. A CA with live
// subordinates cannot be deleted first.
func (s Service) DeleteCA(ctx context.Context, orgID, userID, caID string) error {
	if err := s.checkEndpointBindings(ctx, orgID, caID, "deleting"); err != nil {
		return err
	}
	ca, err := s.repo.CA(ctx, orgID, caID)
	if err != nil {
		return err
	}
	children, err := s.repo.ActiveChildCount(ctx, orgID, ca.ID)
	if err != nil {
		return err
	}
	if children > 0 {
		return fmt.Errorf("delete its issuing CAs before deleting this CA")
	}
	if err := s.provider.DestroyKeyVersion(ctx, ca.KMSKeyVersion); err != nil {
		return err
	}
	if err := s.repo.MarkCADeleted(ctx, orgID, ca.ID); err != nil {
		return err
	}
	return s.repo.RecordCAEvent(ctx, orgID, ca.ID, userID, ca.KMSKeyVersion, PurposeDeletedCA)
}

func (s Service) Issue(ctx context.Context, req IssueRequest) (Certificate, error) {
	ca, err := s.activeIssuingCA(ctx, req.OrgID, req.CAID)
	if err != nil {
		return Certificate{}, err
	}
	if err := rejectPrivateKeyMaterial(req.CSRPEM); err != nil {
		return Certificate{}, err
	}
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil {
		return Certificate{}, fmt.Errorf("invalid csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return Certificate{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return Certificate{}, err
	}
	ekus, err := ekuSelection(req.EKUs, ca.IssuanceEKUs, "")
	if err != nil {
		return Certificate{}, err
	}
	days, err := leafValidityDays(req.Days)
	if err != nil {
		return Certificate{}, err
	}
	profile := req.Profile
	if profile == "" {
		profile = CertProfileCSR
	}
	hash := sha256.Sum256(block.Bytes)
	return s.signLeaf(ctx, ca, csr.PublicKey, req.UserID, leafSpec{
		subject:    csr.Subject,
		dns:        csr.DNSNames,
		ips:        csr.IPAddresses,
		emails:     csr.EmailAddresses,
		uris:       csr.URIs,
		rawSubject: csr.RawSubject,
		rawSANs:    SubjectAltName(csr),
		ekus:       ekus,
		days:       days,
		profile:    profile,
		csrDigest:  hex.EncodeToString(hash[:]),
		purpose:    req.Purpose,
	})
}

// IssueGenerated creates the leaf keypair server-side and returns the private
// key PEM alongside the stored certificate. The key exists only in this return
// value — it is never persisted, logged, or retrievable again.
func (s Service) IssueGenerated(ctx context.Context, req IssueGeneratedRequest) (Certificate, string, error) {
	var required string
	switch req.Profile {
	case CertProfileServer:
		required = EKUServerAuth
	case CertProfileClient:
		required = EKUClientAuth
	default:
		return Certificate{}, "", fmt.Errorf("invalid certificate profile")
	}
	ca, err := s.activeIssuingCA(ctx, req.OrgID, req.CAID)
	if err != nil {
		return Certificate{}, "", err
	}
	subject, err := BuildSubject(req.Subject)
	if err != nil {
		return Certificate{}, "", err
	}
	var ips []net.IP
	for _, raw := range req.IPs {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			return Certificate{}, "", fmt.Errorf("invalid IP address %q", raw)
		}
		ips = append(ips, ip)
	}
	for _, d := range req.DNSNames {
		if d == "" || strings.ContainsAny(d, " \t") {
			return Certificate{}, "", fmt.Errorf("invalid DNS name %q", d)
		}
	}
	for _, e := range req.Emails {
		if !strings.Contains(e, "@") {
			return Certificate{}, "", fmt.Errorf("invalid email address %q", e)
		}
	}
	ekus, err := ekuSelection(req.EKUs, ca.IssuanceEKUs, required)
	if err != nil {
		return Certificate{}, "", err
	}
	days, err := leafValidityDays(req.Days)
	if err != nil {
		return Certificate{}, "", err
	}
	algorithm, err := ValidateLeafAlgorithm(req.Algorithm)
	if err != nil {
		return Certificate{}, "", err
	}
	key, keyPEM, err := GenerateLeafKey(algorithm)
	if err != nil {
		return Certificate{}, "", err
	}
	cert, err := s.signLeaf(ctx, ca, key.Public(), req.UserID, leafSpec{
		subject: subject,
		dns:     req.DNSNames,
		ips:     ips,
		emails:  req.Emails,
		ekus:    ekus,
		days:    days,
		profile: req.Profile,
		purpose: req.Profile,
	})
	if err != nil {
		return Certificate{}, "", err
	}
	return cert, keyPEM, nil
}

// Revoke marks an issued certificate revoked, records the reason, and writes
// an audit event. Already-revoked certificates return sql.ErrNoRows.
func (s Service) Revoke(ctx context.Context, req RevokeRequest) error {
	if !slices.Contains(RevocationReasons, req.Reason) {
		return fmt.Errorf("invalid revocation reason")
	}
	cert, err := s.repo.Certificate(ctx, req.OrgID, req.CertificateID)
	if err != nil {
		return err
	}
	if err := s.repo.RevokeCertificate(ctx, req.OrgID, cert.ID, req.Reason); err != nil {
		return err
	}
	if err := s.repo.RecordCAEvent(ctx, req.OrgID, cert.CAID, req.UserID, "", "revoked_certificate"); err != nil {
		return err
	}
	// Revocation is permanent even when KMS publication is temporarily down;
	// PublishCRL records the error and the renewal worker retries it.
	_ = s.PublishCRL(ctx, req.OrgID, cert.CAID)
	return nil
}

func (s Service) activeIssuingCA(ctx context.Context, orgID, caID string) (CertificateAuthority, error) {
	ca, err := s.repo.CA(ctx, orgID, caID)
	if err != nil {
		return CertificateAuthority{}, err
	}
	if ca.Type != CATypeIssuing || ca.Status != CAStatusActive {
		return CertificateAuthority{}, fmt.Errorf("active issuing CA required")
	}
	return ca, nil
}

// leafSpec carries everything signLeaf needs beyond the CA and public key.
type leafSpec struct {
	subject pkix.Name
	dns     []string
	ips     []net.IP
	emails  []string
	uris    []*url.URL
	// rawSubject and rawSANs carry a request's DER through untouched. Rebuilding
	// either from Go's parsed structs drops every attribute x509 does not model,
	// which for Intune means the emailAddress RDN and the UPN otherName.
	rawSubject []byte
	rawSANs    *pkix.Extension
	ekus       []string
	days       int
	profile    string
	csrDigest  string
	purpose    string
}

// signLeaf signs an end-entity certificate with the CA's KMS key, persists it,
// and records the signing audit row.
func (s Service) signLeaf(ctx context.Context, ca CertificateAuthority, pub crypto.PublicKey, userID string, spec leafSpec) (Certificate, error) {
	issuer, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return Certificate{}, err
	}
	// The last line of defence on key strength. The device protocols each apply
	// their own, narrower check, but Issue is also reachable from the
	// administrator's CSR form, which passes through none of them.
	if err := ValidatePublicKey(pub); err != nil {
		return Certificate{}, err
	}
	key, err := s.provider.KeyInfo(ctx, ca.KMSKeyVersion)
	if err != nil {
		return Certificate{}, err
	}
	notBefore, notAfter := DaysFromNow(spec.days)
	// Signing under a CA that is expired or not yet valid produces a certificate
	// every client rejects, and — once notAfter is clamped below — one whose
	// notAfter precedes its notBefore. Refusing says so plainly instead.
	if now := time.Now().UTC(); now.Before(issuer.NotBefore) || now.After(issuer.NotAfter) {
		return Certificate{}, fmt.Errorf("certificate authority %q is not valid at this time (valid %s to %s)",
			ca.Name, issuer.NotBefore.Format(time.RFC3339), issuer.NotAfter.Format(time.RFC3339))
	}
	// A leaf must not outlive its issuing CA.
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	if !notAfter.After(notBefore) {
		return Certificate{}, fmt.Errorf("certificate authority %q expires too soon to issue against", ca.Name)
	}
	serial, err := randomSerial()
	if err != nil {
		return Certificate{}, err
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return Certificate{}, err
	}
	ekuCSV := strings.Join(spec.ekus, ",")
	usages, customOIDs := ekuUsages(ekuCSV)
	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        spec.subject,
		DNSNames:       spec.dns,
		IPAddresses:    spec.ips,
		EmailAddresses: spec.emails,
		URIs:           spec.uris,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		// Emits a critical basicConstraints with cA=FALSE. Without this Go omits
		// the extension entirely, leaving a verifier to infer that a subscriber
		// certificate is not a CA rather than read it stated.
		BasicConstraintsValid: true,
		// Go derives SubjectKeyId on its own only for CA certificates. The
		// authorityKeyIdentifier of a leaf is filled from the issuer's SKI
		// automatically, so only this side needs saying.
		SubjectKeyId:          ski,
		KeyUsage:              leafKeyUsage(pub, spec.ekus),
		ExtKeyUsage:           usages,
		UnknownExtKeyUsage:    customOIDs,
		CRLDistributionPoints: []string{s.PublicEndpoint(ca.OrganizationID, ca.ID, "crl")},
		OCSPServer:            []string{s.PublicEndpoint(ca.OrganizationID, ca.ID, "ocsp")},
		IssuingCertificateURL: []string{s.PublicEndpoint(ca.OrganizationID, ca.ID, "issuer")},
	}
	// RawSubject and an ExtraExtensions subjectAltName both take precedence over
	// the parsed fields above, which is the point: the requester's DER is issued
	// as asked rather than as much of it as Go happens to model.
	if len(spec.rawSubject) > 0 {
		template.RawSubject = spec.rawSubject
	}
	if spec.rawSANs != nil {
		template.ExtraExtensions = append(template.ExtraExtensions, *spec.rawSANs)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, NewKMSSigner(ctx, s.provider, key))
	if err != nil {
		return Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	var sans []string
	sans = append(sans, spec.dns...)
	for _, ip := range spec.ips {
		sans = append(sans, ip.String())
	}
	sans = append(sans, spec.emails...)
	for _, uri := range spec.uris {
		sans = append(sans, uri.String())
	}
	// otherName forms are in the issued certificate either way; listing them
	// keeps the stored record an honest description of it.
	sans = append(sans, UnparsedSANs(spec.rawSANs)...)
	// The issued subject is spec.rawSubject when set, so describe that rather
	// than the parsed name, which omits attributes such as emailAddress.
	subject := RenderSubject(spec.rawSubject, spec.subject)
	cert := Certificate{
		OrganizationID: ca.OrganizationID,
		CAID:           ca.ID,
		CAName:         ca.Name,
		Serial:         serial.Text(16),
		Subject:        subject,
		SANs:           strings.Join(sans, ","),
		Status:         CertStatusIssued,
		Profile:        spec.profile,
		EKUs:           ekuCSV,
		CSRDigest:      spec.csrDigest,
		CertificatePEM: string(certPEM),
		ChainPEM:       ca.CertificatePEM + ca.ChainPEM,
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      notAfter,
	}
	cert.ID, err = s.repo.RecordCertificate(ctx, cert)
	if err != nil {
		return Certificate{}, err
	}
	return cert, s.repo.RecordSigning(ctx, ca.OrganizationID, ca.ID, userID, ca.KMSKeyVersion, cert.CSRDigest, cert.Serial, spec.purpose)
}

// caTemplate builds the certificate for a CA. issuerURL is where this CA's own
// issuer can be fetched, and is empty for a self-signed root.
//
// No CRLDistributionPoints, deliberately. The CRL is built from
// certificate_revocation and the responder resolves serials through
// CertificateBySerial, both of which describe leaves — neither can answer a
// question about a subordinate CA's own serial. Publishing a distribution point
// that returns nothing useful is worse than publishing none: a client
// configured to hard-fail on revocation checking rejects the whole chain.
// Adding it needs the revocation model to cover CAs first.
func caTemplate(name pkix.Name, pathLen int, pub crypto.PublicKey, notBefore, notAfter time.Time, issuerURL string) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               name,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		SubjectKeyId:          ski,
	}
	if issuerURL != "" {
		template.IssuingCertificateURL = []string{issuerURL}
	}
	return template, nil
}

// subjectKeyID derives the SKI from the SubjectPublicKeyInfo per RFC 7093:
// the leftmost 160 bits of its SHA-256 hash.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)
	return sum[:20], nil
}

func parseCertificate(raw string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
