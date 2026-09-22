package pki

import (
	"crypto/x509/pkix"
	"time"
)

const (
	AlgorithmECDSAP256SHA256 = "EC_SIGN_P256_SHA256"
	AlgorithmECDSAP384SHA384 = "EC_SIGN_P384_SHA384"
	AlgorithmRSA3072SHA256   = "RSA_SIGN_PKCS1_3072_SHA256"
	AlgorithmRSA4096SHA256   = "RSA_SIGN_PKCS1_4096_SHA256"

	CATypeRoot    = "root"
	CATypeIssuing = "issuing"

	CAStatusActive   = "active"
	CAStatusInactive = "inactive"
	CAStatusRetired  = "retired"
	CAStatusDeleted  = "deleted"

	// Purposes recorded in certificate_signing_audit for CA lifecycle events, as
	// distinct from the issuance purposes ("server", "scep", …) written by
	// signLeaf. The column is unconstrained VARCHAR, so adding one needs no
	// migration — but audit.signingAction must learn it, or it reads as "other"
	// and the reader cannot filter for it.
	PurposeActivatedCA   = "activated_ca"
	PurposeDeactivatedCA = "deactivated_ca"
	PurposeRetiredCA     = "retired_ca"
	PurposeRotatedCA     = "rotated_ca"
	PurposeDeletedCA     = "deleted_ca"
	PurposeOtherCA       = "other_ca"

	ExportPostureNonExportableHSM      = "non_exportable_hsm"
	ExportPostureImportedHSM           = "imported_hsm"
	ExportPostureNonExportableSoftware = "non_exportable_software"
	ExportPostureImportedSoftware      = "imported_software"

	EKUClientAuth      = "client_auth"
	EKUServerAuth      = "server_auth"
	EKUCodeSigning     = "code_signing"
	EKUEmailProtection = "email_protection"
	EKUIPSECEndSystem  = "ipsec_end_system"
	EKUIPSECTunnel     = "ipsec_tunnel"
	EKUIPSECUser       = "ipsec_user"
	EKUTimeStamping    = "time_stamping"
	EKUOCSPSigning     = "ocsp_signing"
	EKUSmartcardLogon  = "smartcard_logon"
	EKUMacAddress      = "mac_address"

	DefaultRootDays    = 3650
	DefaultIssuingDays = 1825
	MaxValidityDays    = 10950

	CertProfileServer = "server"
	CertProfileClient = "client"
	CertProfileCSR    = "csr"
	CertProfileSCEP   = "scep"
	CertProfileACME   = "acme"
	CertProfileEST    = "est"
	// CertProfileInfrastructure marks a certificate SimpleSCEP issued for its
	// own machinery rather than an enrolled device — today, a SCEP endpoint's
	// registration authority certificate. These are excluded from identity metrics.
	CertProfileInfrastructure = "infrastructure"

	// Leaf key algorithm tokens for server-generated certificates. These are
	// distinct from the KMS Algorithm* constants: leaf keys are generated with
	// stdlib crypto, and RSA-2048 has no KMS equivalent.
	LeafRSA2048 = "RSA_2048"
	LeafRSA3072 = "RSA_3072"
	LeafRSA4096 = "RSA_4096"
	LeafECP256  = "EC_P256"
	LeafECP384  = "EC_P384"

	MaxLeafValidityDays = 3650

	CertStatusIssued  = "issued"
	CertStatusRevoked = "revoked"
)

// EnrollmentProfiles are the profiles a certificate can reach a customer
// through — every CertProfile except CertProfileInfrastructure, which
// SimpleSCEP issues to itself and nobody enrolled.
//
// It exists so that anything reporting on enrollment can be held to covering
// all of them: the overview's graph plots one line per entry, and a profile
// added above and not here is a line that silently never appears.
var EnrollmentProfiles = []string{
	CertProfileCSR, CertProfileServer, CertProfileClient,
	CertProfileSCEP, CertProfileACME, CertProfileEST,
}

// RevocationReasons are the accepted values for a revocation's reason field.
var RevocationReasons = []string{
	"unspecified",
	"key_compromise",
	"superseded",
	"cessation_of_operation",
	"affiliation_changed",
}

type CertificateAuthority struct {
	ID             string
	OrganizationID string
	ParentID       string
	Name           string
	Type           string
	Status         string
	Subject        string
	Algorithm      string
	KMSKeyVersion  string
	CertificatePEM string
	ChainPEM       string
	ExportPosture  string
	IssuanceEKUs   string
	NotBefore      time.Time
	NotAfter       time.Time
	IssuedCount    int64
	LastSignedAt   *time.Time
	CreatedAt      time.Time
}

type Certificate struct {
	ID             string
	OrganizationID string
	CAID           string
	// CAName is scan-only, filled by the list query's join.
	CAName         string
	Serial         string
	Subject        string
	SANs           string
	Status         string
	Profile        string
	EKUs           string
	CSRDigest      string
	CertificatePEM string
	ChainPEM       string
	IssuedAt       time.Time
	RevokedAt      *time.Time
	ExpiresAt      time.Time
}

type Revocation struct {
	Certificate
	Reason string
}

type CRLPublication struct {
	OrganizationID string
	CAID           string
	DER            []byte
	Number         int64
	ThisUpdate     *time.Time
	NextUpdate     *time.Time
	PublishedAt    *time.Time
	LastAttemptAt  *time.Time
	LastError      string
}

type OCSPCacheEntry struct {
	DER        []byte
	Status     string
	ThisUpdate time.Time
	NextUpdate time.Time
}

type SubjectInput struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
}

type CreateCARequest struct {
	OrgID     string
	UserID    string
	Name      string
	Type      string
	ParentID  string
	Subject   SubjectInput
	Days      int
	Algorithm string
	// Protection selects software- or HSM-backed key storage for this CA.
	Protection string
	EKUs       []string
	// MaxPathLen applies to roots only: 0..4, nil → 1. Explicit 0 means no
	// subordinate CAs may be created under it.
	MaxPathLen *int
	// subjectName, when set, overrides Subject with an already-parsed name;
	// rotation uses it to carry the old certificate's subject verbatim.
	subjectName *pkix.Name
}

type CAImportJob struct {
	ID                     string
	OrganizationID         string
	CreatedBy              string
	CAName                 string
	CAType                 string
	Algorithm              string
	CertificatePEM         string
	ChainPEM               string
	KMSImportJob           string
	KMSCryptoKey           string
	KMSKeyVersion          string
	WrappingMethod         string
	WrappingPublicKeyPEM   string
	State                  string
	FailureReason          string
	CertificateAuthorityID string
	ExpiresAt              *time.Time
	CreatedAt              time.Time
}

const (
	ImportStatePreparing   = "preparing"
	ImportStateReadyToWrap = "ready_to_wrap"
	ImportStateImporting   = "importing"
	ImportStateCompleted   = "completed"
	ImportStateFailed      = "failed"
	ImportStateExpired     = "expired"
	ImportStateCancelled   = "cancelled"
)

type IssueRequest struct {
	OrgID  string
	UserID string
	CAID   string
	CSRPEM string
	Days   int
	// EKUs selects a subset of the CA's issuance profile; empty applies the
	// whole profile.
	EKUs    []string
	Purpose string
	// Profile is what the certificate is recorded as; empty means
	// CertProfileCSR, which is what a signed CSR ordinarily is. SimpleSCEP's
	// own registration authority certificates set CertProfileInfrastructure so
	// they are excluded from identity counts.
	Profile string
}

type IssueGeneratedRequest struct {
	OrgID  string
	UserID string
	CAID   string
	// Profile is CertProfileServer or CertProfileClient; it determines the EKU
	// the issuing CA must allow (server_auth / client_auth), which is always
	// included in the leaf.
	Profile   string
	Subject   SubjectInput
	DNSNames  []string
	IPs       []string
	Emails    []string
	Days      int
	Algorithm string // Leaf* token
	EKUs      []string
}

type RevokeRequest struct {
	OrgID         string
	UserID        string
	CertificateID string
	Reason        string
}
