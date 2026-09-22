package scep

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/smallstep/pkcs7"
	protocol "github.com/smallstep/scep"
)

// IntuneValidator is the seam over Microsoft's SCEP challenge validation service.
// *IntuneClient is the real implementation; tests substitute their own.
type IntuneValidator interface {
	Validate(context.Context, Integration, string, []byte) error
	NotifySuccess(context.Context, Integration, string, []byte, appPKI.Certificate) error
	NotifyFailure(context.Context, Integration, string, []byte, string) error
	CheckTenant(context.Context, Integration) error
}

// store is the persistence seam the service depends on, so authorization can be
// exercised without a database. Repository satisfies it structurally.
type store interface {
	Endpoints(ctx context.Context, orgID string) ([]Endpoint, error)
	EndpointByID(ctx context.Context, orgID, id string) (Endpoint, error)
	EndpointCount(ctx context.Context, orgID string) (int, error)
	InsertEndpoint(ctx context.Context, e Endpoint) error
	DeleteEndpoint(ctx context.Context, orgID, id string) error
	LiveCertificateCount(ctx context.Context, endpointID string) (int, error)
	SeedAuthMethods(ctx context.Context, e Endpoint) error
	AuthMethods(ctx context.Context, endpointID string) ([]AuthMethod, error)
	AuthMethod(ctx context.Context, endpointID, method string) (AuthMethod, error)
	SetMethodEnabled(ctx context.Context, endpointID, method string, enabled bool) error
	UpsertStaticSecret(ctx context.Context, e Endpoint, hash string) error
	IntuneConnection(ctx context.Context, orgID string) (IntuneConnection, error)
	IntuneConnected(ctx context.Context, orgID string) (bool, error)
	ConnectIntuneTenant(ctx context.Context, orgID, tenantID string) error
	DisconnectIntuneTenant(ctx context.Context, orgID string) error
	UpsertJamf(ctx context.Context, e Endpoint, username, passwordHash string) error
	CreateChallenge(ctx context.Context, c Challenge, lookup []byte) error
	ChallengeForUpdate(ctx context.Context, endpointID string, lookup []byte) (Challenge, error)
	UseChallenge(ctx context.Context, id string) error
	Transaction(ctx context.Context, endpointID, transactionID string) (Transaction, error)
	CreateTransaction(ctx context.Context, orgID string, t Transaction) error
	CertificateIssuedByEndpoint(ctx context.Context, endpointID, certificateID string) (bool, error)
	CertificateIssuedByEndpoints(ctx context.Context, endpointIDs []string, certificateID string) (bool, error)
	LockOrganization(ctx context.Context, orgID string) error
}

// issuer is the signing seam the service depends on, so endpoint creation can
// be exercised without a KMS. appPKI.Service satisfies it structurally.
type issuer interface {
	Issue(ctx context.Context, req appPKI.IssueRequest) (appPKI.Certificate, error)
}

type Service struct {
	repo      store
	pki       issuer
	pkiRepo   appPKI.Repository
	keys      appPKI.KeyProvider
	intune    IntuneValidator
	intuneApp IntuneApp
}

func init() {
	// The upstream CMS package defaults to obsolete DES/SHA-1 for historical
	// compatibility. RFC 8894 requires AES-128-CBC and SHA-256.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
	if err := pkcs7.SetDefaultDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256); err != nil {
		panic(err)
	}
}

func NewService(repo store, db *sql.DB, keys appPKI.KeyProvider, publicURL string, intune IntuneValidator, intuneApp IntuneApp) Service {
	pkiRepo := appPKI.NewRepository(db)
	return Service{repo: repo, pki: appPKI.NewServiceWithURL(pkiRepo, keys, publicURL), pkiRepo: pkiRepo,
		keys: keys, intune: intune, intuneApp: intuneApp}
}

// CreateEndpointRequest describes a new SCEP endpoint.
type CreateEndpointRequest struct {
	OrgID, UserID, CAID, Name string
}

// CreateEndpoint mints a SCEP endpoint with its own registration authority
// keypair. Unlike the singleton it replaces this is not idempotent — every call
// that reaches the issuance below burns a KMS signing operation — so the name,
// the CA, and the name collision are all settled first.
func (s Service) CreateEndpoint(ctx context.Context, req CreateEndpointRequest) (Endpoint, error) {
	name, err := validEndpointName(req.Name)
	if err != nil {
		return Endpoint{}, err
	}
	caID := strings.TrimSpace(req.CAID)
	if caID == "" {
		return Endpoint{}, fmt.Errorf("select an issuing certificate authority")
	}
	existing, err := s.repo.Endpoints(ctx, req.OrgID)
	if err != nil {
		return Endpoint{}, err
	}
	// Checked here as well as by the unique index so the common collision never
	// reaches the issuance below; the index is the backstop for a race.
	for _, e := range existing {
		if strings.EqualFold(e.Name, name) {
			return Endpoint{}, fmt.Errorf("an endpoint called %q already exists; pick another name", name)
		}
	}
	orgID, userID := req.OrgID, req.UserID
	id := uuid.NewString()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return Endpoint{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "SimpleSCEP RA " + id}}, key)
	if err != nil {
		return Endpoint{}, err
	}
	// The RA certificate is SimpleSCEP's own: it is recorded as infrastructure so
	// it is excluded from identity metrics and enrolled device certificates.
	cert, err := s.pki.Issue(ctx, appPKI.IssueRequest{OrgID: orgID, UserID: userID, CAID: caID,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), Days: 825,
		EKUs: []string{appPKI.EKUClientAuth}, Purpose: "scep_ra", Profile: appPKI.CertProfileInfrastructure})
	if err != nil {
		return Endpoint{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Endpoint{}, err
	}
	ciphertext, err := s.keys.Protect(ctx, raPurpose(id), der)
	if err != nil {
		return Endpoint{}, err
	}
	// SANPattern starts permissive rather than at its zero value, for the same
	// reason SubjectPattern already does: an empty SAN pattern permits no
	// subject alternative names at all (see NamePolicy), which is the right
	// default for an endpoint an administrator has deliberately locked down, but
	// the wrong one for one that was just created and has not been configured
	// either way.
	e := Endpoint{ID: id, OrganizationID: orgID, CAID: caID, Name: name, ValidityDays: DefaultValidityDays,
		AllowedEKUs: appPKI.EKUClientAuth, RenewalWindowDays: DefaultRenewalWindowDays, SubjectPattern: `.+`,
		SANPattern:       ".*",
		RACertificatePEM: cert.CertificatePEM, RAPrivateKeyCiphertext: ciphertext}
	if err := s.repo.InsertEndpoint(ctx, e); err != nil {
		return Endpoint{}, err
	}
	return e, s.repo.SeedAuthMethods(ctx, e)
}

// DeleteEndpoint removes an endpoint and everything scoped to it: its
// authentication methods, outstanding challenges, and enrollment history.
//
// Certificates it issued are not touched — they live on the certificate authority
// and stay valid and trusted until they expire or are revoked. What they lose is
// the URL they renew through, and the enrollment records that tie them back to
// this endpoint, which is what the Intune revocation worker matches a serial
// against. The consequences are the caller's to present; see the delete dialog
// on the endpoint page, which enumerates them and requires the name to be typed.
func (s Service) DeleteEndpoint(ctx context.Context, orgID, id string) error {
	return s.repo.DeleteEndpoint(ctx, orgID, id)
}

// validEndpointName normalizes an administrator-supplied endpoint name. The name
// is a link label and a page title, never part of a URL or a query, so beyond
// length and control characters it is left alone.
func validEndpointName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("name the endpoint")
	}
	if len([]rune(name)) > 64 {
		return "", fmt.Errorf("the endpoint name must be 64 characters or fewer")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("the endpoint name contains invalid characters")
		}
	}
	return name, nil
}

func (s Service) CreateChallenge(ctx context.Context, endpoint Endpoint, spec ChallengeSpec) (string, error) {
	ttl := spec.TTL
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 15 * time.Minute
	}
	// A challenge may only narrow the endpoint's allow list, never widen it, so
	// minting one can never become a way around the issuance policy.
	expectedEKUs, err := narrowEKUs(endpoint.AllowedEKUs, spec.ExpectedEKUs)
	if err != nil {
		return "", err
	}
	secret, err := enroll.RandomSecret()
	if err != nil {
		return "", err
	}
	hash, err := enroll.HashSecret(secret)
	if err != nil {
		return "", err
	}
	lookup := sha256.Sum256([]byte(secret))
	c := Challenge{ID: uuid.NewString(), OrganizationID: endpoint.OrganizationID, EndpointID: endpoint.ID, SecretHash: hash,
		ExpectedSubject: spec.ExpectedSubject, ExpectedSANs: spec.ExpectedSANs, ExpectedEKUs: strings.Join(expectedEKUs, ","),
		ExternalID: spec.ExternalID, ExpiresAt: time.Now().UTC().Add(ttl)}
	if err := s.repo.CreateChallenge(ctx, c, lookup[:]); err != nil {
		return "", err
	}
	return secret, nil
}

func (s Service) RotateStaticSecret(ctx context.Context, endpoint Endpoint) (string, error) {
	secret, err := enroll.RandomSecret()
	if err != nil {
		return "", err
	}
	hash, err := enroll.HashSecret(secret)
	if err != nil {
		return "", err
	}
	return secret, s.repo.UpsertStaticSecret(ctx, endpoint, hash)
}

func (s Service) AuthMethods(ctx context.Context, endpoint Endpoint) ([]AuthMethod, error) {
	stored, err := s.repo.AuthMethods(ctx, endpoint.ID)
	if err != nil {
		return nil, err
	}
	// Stored rows carry the organization's Entra connection from the query, but
	// the synthesized rows below have no row to carry it, so read it once here
	// or an unseeded intune method reports itself unconfigured for a connected
	// organization.
	connected, err := s.repo.IntuneConnected(ctx, endpoint.OrganizationID)
	if err != nil {
		return nil, err
	}
	byName := map[string]AuthMethod{}
	for _, m := range stored {
		byName[m.Method] = m
	}
	// Render every method in a stable order even if a row has not been seeded.
	out := make([]AuthMethod, 0, len(Methods))
	for _, name := range Methods {
		m, ok := byName[name]
		if !ok {
			m = AuthMethod{OrganizationID: endpoint.OrganizationID, EndpointID: endpoint.ID, Method: name,
				IntuneConnected: connected}
		}
		out = append(out, m)
	}
	return out, nil
}

// SetMethodEnabled turns one authentication method on or off, refusing to enable
// anything that is not yet usable so the failure is explained here rather than at
// enrollment time.
func (s Service) SetMethodEnabled(ctx context.Context, endpoint Endpoint, method string, enabled bool) error {
	if !slices.Contains(Methods, method) {
		return fmt.Errorf("unknown authentication method")
	}
	if enabled {
		stored, err := s.repo.AuthMethod(ctx, endpoint.ID, method)
		if err != nil {
			return fmt.Errorf("configure %s before turning it on", methodLabel(method))
		}
		if !stored.Configured() {
			return fmt.Errorf("configure %s before turning it on", methodLabel(method))
		}
		if method == AuthJamf {
			// Jamf's webhook mints one-time challenges, so that method must accept them.
			oneTime, err := s.repo.AuthMethod(ctx, endpoint.ID, AuthOneTime)
			if err != nil || !oneTime.Enabled {
				return fmt.Errorf("turn on one-time challenges before enabling Jamf Pro")
			}
		}
	}
	if method == AuthOneTime && !enabled {
		if jamf, err := s.repo.AuthMethod(ctx, endpoint.ID, AuthJamf); err == nil && jamf.Enabled {
			return fmt.Errorf("turn off Jamf Pro before disabling one-time challenges")
		}
	}
	return s.repo.SetMethodEnabled(ctx, endpoint.ID, method, enabled)
}

func methodLabel(method string) string {
	switch method {
	case AuthOneTime:
		return "one-time challenges"
	case AuthStatic:
		return "the shared secret"
	case AuthIntune:
		return "Microsoft Intune"
	case AuthJamf:
		return "Jamf Pro"
	}
	return method
}

func (s Service) CACertificates(ctx context.Context, e Endpoint) ([]byte, error) {
	ra, err := parseCertificate(e.RACertificatePEM)
	if err != nil {
		return nil, err
	}
	ca, err := s.pkiRepo.CA(ctx, e.OrganizationID, e.CAID)
	if err != nil {
		return nil, err
	}
	certs := []*x509.Certificate{ra}
	for _, raw := range []string{ca.CertificatePEM, ca.ChainPEM} {
		for {
			block, rest := pem.Decode([]byte(raw))
			if block == nil {
				break
			}
			raw = string(rest)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return protocol.DegenerateCertificates(certs)
}

// CACertificatePEM returns the endpoint's CA certificate and chain as PEM,
// for a plain manual download. Unlike CACertificates, it excludes the RA
// operational certificate: that one exists to sign SCEP protocol messages,
// not to be trusted as an issuer, and has no place in a certificate someone
// installs by hand.
func (s Service) CACertificatePEM(ctx context.Context, e Endpoint) (certPEM, chainPEM string, err error) {
	ca, err := s.pkiRepo.CA(ctx, e.OrganizationID, e.CAID)
	if err != nil {
		return "", "", err
	}
	return ca.CertificatePEM, ca.ChainPEM, nil
}

// Failure describes a rejected enrollment so the caller can log it after the
// request transaction has been rolled back.
type Failure struct{ TransactionID, MessageType, Reason string }

func (s Service) PKIOperation(ctx context.Context, e Endpoint, raw []byte) ([]byte, *Failure, error) {
	if err := cryptoPolicy(raw, e.AllowLegacyCrypto); err != nil {
		return nil, nil, err
	}
	key, cert, err := s.raMaterial(ctx, e)
	if err != nil {
		return nil, nil, err
	}
	msg, err := protocol.ParsePKIMessage(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse pki message: %w", err)
	}
	outer, err := pkcs7.Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CMS signer: %w", err)
	}
	msg.SignerCert = outer.GetOnlySigner()
	if err := msg.DecryptPKIEnvelope(cert, key); err != nil {
		return nil, nil, fmt.Errorf("decrypt pki message: %w", err)
	}
	fail := func(info protocol.FailInfo, cause error) ([]byte, *Failure, error) {
		record := &Failure{TransactionID: string(msg.TransactionID), MessageType: string(msg.MessageType), Reason: cause.Error()}
		rep, repErr := msg.Fail(cert, key, info)
		if repErr != nil {
			return nil, record, repErr
		}
		return rep.Raw, record, cause
	}
	if msg.CSRReqMessage == nil || (msg.MessageType != protocol.PKCSReq && msg.MessageType != protocol.RenewalReq) {
		return fail(protocol.BadRequest, fmt.Errorf("unsupported SCEP message type"))
	}
	csr := msg.CSR
	if err := csr.CheckSignature(); err != nil {
		return fail(protocol.BadMessageCheck, fmt.Errorf("invalid CSR signature"))
	}
	// RFC 8894 3.2.1 says a PKCSReq is signed by a self-signed certificate
	// carrying the same key as the CSR. Windows does not comply: it mints a
	// throwaway "CN=SCEP Protocol Certificate" keypair per attempt and signs
	// with that, so enforcing the rule rejects every Intune enrollment.
	//
	// Requiring it is not what proves possession anyway. A PKCS#10 request is
	// self-signed by the very key being certified, so csr.CheckSignature above
	// already establishes that the requester holds the private key, and a
	// certificate issued for a key the submitter does not hold is useless to
	// them. Renewal is unaffected: it authenticates its signer against a
	// certificate this endpoint issued rather than against the CSR.
	if msg.MessageType == protocol.PKCSReq && msg.SignerCert == nil {
		return fail(protocol.BadMessageCheck, fmt.Errorf("request carries no signer certificate"))
	}
	if err := enroll.ValidatePublicKey(csr.PublicKey); err != nil {
		return fail(protocol.BadAlg, err)
	}
	if err := validateNames(e, csr); err != nil {
		return fail(protocol.BadRequest, err)
	}
	requested, err := RequestedEKUs(csr)
	if err != nil {
		return fail(protocol.BadRequest, err)
	}
	ekus, err := ResolveEKUs(e.AllowedEKUs, requested)
	if err != nil {
		return fail(protocol.BadRequest, err)
	}
	csrSum := sha256.Sum256(csr.Raw)
	csrDigest := hex.EncodeToString(csrSum[:])
	// Serialize the replay check with issuance so concurrent retries cannot
	// both sign before the transaction uniqueness constraint is reached.
	if err := s.repo.LockOrganization(ctx, e.OrganizationID); err != nil {
		return nil, nil, err
	}
	signerDigest := signerKeyDigest(msg.SignerCert)
	if existing, err := s.repo.Transaction(ctx, e.ID, string(msg.TransactionID)); err == nil && existing.Status == "issued" {
		if existing.CSRDigest != csrDigest {
			return fail(protocol.BadRequest, fmt.Errorf("transaction ID conflict"))
		}
		// This branch answers a repeat with the certificate already issued, and it
		// runs before authorize — deliberately, because that is what lets a device
		// whose response was lost retry after its one-time challenge password has
		// been spent.
		//
		// Matching on the CSR alone made that an unauthenticated read. A CSR is not
		// a secret, and a SCEP transaction id is conventionally derived from the
		// public key inside it, so anyone who saw an enrollment could rebuild both
		// and collect the certificate without presenting a credential. Nothing new
		// is signed on this path, but for a private PKI the subject and SANs are
		// the sensitive part.
		//
		// Requiring the same signing key closes it without costing the retry: the
		// device signs with the key it used the first time, and an observer has the
		// CSR but not that private key. Rows written before the column existed
		// carry no digest and keep the old behaviour, so a deploy does not strand a
		// device mid-enrolment.
		if existing.SignerKeyDigest != "" && !hmac.Equal([]byte(existing.SignerKeyDigest), []byte(signerDigest)) {
			return fail(protocol.BadRequest, fmt.Errorf("transaction ID conflict"))
		}
		stored, err := s.pkiRepo.Certificate(ctx, e.OrganizationID, existing.CertificateID)
		if err != nil {
			return nil, nil, err
		}
		leaf, err := parseCertificate(stored.CertificatePEM)
		if err != nil {
			return nil, nil, err
		}
		rep, err := msg.Success(cert, key, leaf)
		if err != nil {
			return nil, nil, err
		}
		return rep.Raw, nil, nil
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}

	authorization, err := s.authorize(ctx, e, msg, csr, ekus)
	if err != nil {
		body, record, _ := fail(protocol.BadRequest, err)
		return body, record, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	issued, err := s.pki.Issue(ctx, appPKI.IssueRequest{OrgID: e.OrganizationID, CAID: e.CAID, CSRPEM: string(csrPEM), Days: e.ValidityDays,
		EKUs: ekus, Purpose: "scep", Profile: appPKI.CertProfileSCEP})
	if err != nil {
		// Intune already authorized this request, so report the failure or the
		// administrator sees only a device that silently never enrolls.
		if authorization == AuthIntune {
			if integration, intErr := s.intuneIntegration(ctx, e.OrganizationID); intErr == nil {
				_ = s.intune.NotifyFailure(ctx, integration, string(msg.TransactionID), csr.Raw, err.Error())
			}
		}
		body, record, _ := fail(protocol.BadRequest, err)
		return body, record, err
	}
	if authorization == AuthIntune {
		integration, err := s.intuneIntegration(ctx, e.OrganizationID)
		if err != nil {
			return nil, nil, err
		}
		if err := s.intune.NotifySuccess(ctx, integration, string(msg.TransactionID), csr.Raw, issued); err != nil {
			return nil, nil, err
		}
	}
	t := Transaction{EndpointID: e.ID, TransactionID: string(msg.TransactionID), CSRDigest: csrDigest, CertificateID: issued.ID,
		Status: "issued", MessageType: string(msg.MessageType), AuthorizationSource: authorization,
		SignerKeyDigest: signerDigest}
	if err := s.repo.CreateTransaction(ctx, e.OrganizationID, t); err != nil {
		return nil, nil, err
	}
	leaf, err := parseCertificate(issued.CertificatePEM)
	if err != nil {
		return nil, nil, err
	}
	rep, err := msg.Success(cert, key, leaf)
	if err != nil {
		return nil, nil, err
	}
	return rep.Raw, nil, nil
}

// authorize resolves which enabled method accepts the request. ekus is what the
// enrollment would be issued with, so a one-time challenge can be pinned to it.
func (s Service) authorize(ctx context.Context, e Endpoint, msg *protocol.PKIMessage, csr *x509.CertificateRequest, ekus []string) (string, error) {
	if msg.MessageType == protocol.RenewalReq {
		if msg.SignerCert == nil {
			return "", fmt.Errorf("renewal signer certificate required")
		}
		stored, err := s.pkiRepo.CertificateBySerial(ctx, e.OrganizationID, e.CAID, msg.SignerCert.SerialNumber.Text(16))
		if err != nil {
			return "", err
		}
		old, err := parseCertificate(stored.CertificatePEM)
		if err != nil {
			return "", err
		}
		if stored.Status != appPKI.CertStatusIssued || !old.Equal(msg.SignerCert) || time.Now().After(old.NotAfter) {
			return "", fmt.Errorf("renewal certificate is not valid")
		}
		issuedHere, err := s.repo.CertificateIssuedByEndpoint(ctx, e.ID, stored.ID)
		if err != nil || !issuedHere {
			return "", fmt.Errorf("renewal certificate was not issued by this endpoint")
		}
		if time.Until(old.NotAfter) > time.Duration(e.RenewalWindowDays)*24*time.Hour {
			return "", fmt.Errorf("renewal is not yet allowed")
		}
		if err := sameNames(old, csr); err != nil {
			return "", err
		}
		return "renewal", nil
	}
	// One endpoint serves every enrollment source, so the presented challenge
	// password decides which configured method applies. Local checks run before
	// the Intune round trip, and only a full one-time match consumes a
	// challenge, so a miss can never burn one.
	methods, err := s.repo.AuthMethods(ctx, e.ID)
	if err != nil {
		return "", err
	}
	enabled := map[string]AuthMethod{}
	for _, m := range methods {
		if m.Enabled {
			enabled[m.Method] = m
		}
	}
	if len(enabled) == 0 {
		return "", fmt.Errorf("no enrollment authentication method is enabled")
	}
	if _, ok := enabled[AuthOneTime]; ok {
		lookup := sha256.Sum256([]byte(msg.ChallengePassword))
		challenge, err := s.repo.ChallengeForUpdate(ctx, e.ID, lookup[:])
		if err == nil {
			if challenge.UsedAt != nil {
				return "", fmt.Errorf("challenge has already been used")
			}
			if time.Now().After(challenge.ExpiresAt) {
				return "", fmt.Errorf("challenge has expired")
			}
			if !enroll.VerifySecret(challenge.SecretHash, msg.ChallengePassword) {
				return "", fmt.Errorf("invalid challenge")
			}
			if challenge.ExpectedSubject != "" && challenge.ExpectedSubject != csr.Subject.String() {
				return "", fmt.Errorf("CSR subject does not match challenge")
			}
			if challenge.ExpectedSANs != "" && challenge.ExpectedSANs != CSRSANs(csr) {
				return "", fmt.Errorf("CSR SANs do not match challenge")
			}
			if challenge.ExpectedEKUs != "" && !sameEKUSet(enroll.SplitCSV(challenge.ExpectedEKUs), ekus) {
				return "", fmt.Errorf("requested extended key usages do not match challenge")
			}
			if err := s.repo.UseChallenge(ctx, challenge.ID); err != nil {
				return "", fmt.Errorf("challenge has already been used")
			}
			return AuthOneTime, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	}
	if m, ok := enabled[AuthStatic]; ok && m.SecretHash != "" && enroll.VerifySecret(m.SecretHash, msg.ChallengePassword) {
		return AuthStatic, nil
	}
	if _, ok := enabled[AuthIntune]; ok {
		integration, err := s.intuneIntegration(ctx, e.OrganizationID)
		if err != nil {
			return "", err
		}
		if err := s.intune.Validate(ctx, integration, string(msg.TransactionID), csr.Raw); err != nil {
			return "", err
		}
		return AuthIntune, nil
	}
	return "", fmt.Errorf("challenge password was not accepted by any enabled authentication method")
}

// How long VerifyIntuneTenant waits out Entra's propagation delay. A variable so
// tests do not have to sleep through it; the whole check still runs inside the
// request that stores the result, so it has to stay well under the write timeout.
var (
	consentVerifyAttempts = 4
	consentVerifyDelay    = 1500 * time.Millisecond
)

// VerifyIntuneTenant proves that a tenant's admin consent is live before it is
// stored. Entra creates the service principal and applies its role assignments
// asynchronously, so a first attempt failing seconds after consent is normal
// rather than a misconfiguration; retry briefly before believing it. The whole
// check is bounded so it cannot outlive the request writing it.
func (s Service) VerifyIntuneTenant(ctx context.Context, tenantID string) error {
	if s.intune == nil || !s.intuneApp.Deployed() {
		return fmt.Errorf("the Intune connector is not deployed")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	integration := s.intuneApp.integration(tenantID)
	var err error
	for attempt := 0; attempt < consentVerifyAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return err
			case <-time.After(consentVerifyDelay):
			}
		}
		if err = s.intune.CheckTenant(ctx, integration); err == nil {
			return nil
		}
	}
	return err
}

// ConnectIntune records the Entra tenant that granted admin consent to the
// SimpleSCEP application. It binds the organization rather than any one
// endpoint, because a directory serves every endpoint the organization runs.
// The caller must already have proved the consent; see consent.go.
func (s Service) ConnectIntune(ctx context.Context, orgID, tenantID string) error {
	if _, err := uuid.Parse(strings.TrimSpace(tenantID)); err != nil {
		return fmt.Errorf("Microsoft did not return a usable directory (tenant) ID")
	}
	return s.repo.ConnectIntuneTenant(ctx, orgID, strings.TrimSpace(tenantID))
}

// DisconnectIntune unbinds the tenant so it can be connected elsewhere, and
// switches the method off on every endpoint that was using it. Consent itself
// lives in the customer's directory; they remove it by deleting the SimpleSCEP
// enterprise application there.
func (s Service) DisconnectIntune(ctx context.Context, orgID string) error {
	return s.repo.DisconnectIntuneTenant(ctx, orgID)
}

func (s Service) ConfigureJamf(ctx context.Context, e Endpoint, username string) (string, error) {
	if strings.TrimSpace(username) == "" {
		username = "simplescep"
	}
	password, err := enroll.RandomSecret()
	if err != nil {
		return "", err
	}
	hash, err := enroll.HashSecret(password)
	if err != nil {
		return "", err
	}
	return password, s.repo.UpsertJamf(ctx, e, strings.TrimSpace(username), hash)
}

// JamfCredentials returns the webhook basic-auth pair, and whether Jamf is on.
func (s Service) JamfCredentials(ctx context.Context, e Endpoint) (string, string, bool, error) {
	m, err := s.repo.AuthMethod(ctx, e.ID, AuthJamf)
	if err != nil {
		return "", "", false, err
	}
	return m.Username, m.PasswordHash, m.Enabled && m.Configured(), nil
}

// intuneIntegration pairs the organization's connected tenant with the
// SimpleSCEP application's own credentials. Whether a given endpoint may use it
// is decided by that endpoint's enabled flag, which every caller has already
// checked.
func (s Service) intuneIntegration(ctx context.Context, orgID string) (Integration, error) {
	if s.intune == nil || !s.intuneApp.Deployed() {
		return Integration{}, fmt.Errorf("the Intune connector is not deployed")
	}
	conn, err := s.repo.IntuneConnection(ctx, orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return Integration{}, fmt.Errorf("no Microsoft Entra tenant is connected")
	}
	if err != nil {
		return Integration{}, err
	}
	return s.intuneApp.integration(conn.TenantID), nil
}

// RecordFailure writes a failed enrollment on its own transaction, because the
// public handler rolls its request transaction back before replying.
func (s Service) RecordFailure(ctx context.Context, db *sql.DB, e Endpoint, transactionID, messageType, reason string) {
	if transactionID == "" {
		return
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	txctx := database.WithTx(ctx, tx)
	if err := database.SetLocal(txctx, "app.organization_id", e.OrganizationID); err != nil {
		return
	}
	t := Transaction{EndpointID: e.ID, TransactionID: transactionID, Status: "failed", MessageType: messageType,
		AuthorizationSource: "", FailureReason: truncate(reason, 500)}
	if err := s.repo.CreateTransaction(txctx, e.OrganizationID, t); err != nil {
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

func (s Service) raMaterial(ctx context.Context, e Endpoint) (*rsa.PrivateKey, *x509.Certificate, error) {
	der, err := s.keys.Unprotect(ctx, raPurpose(e.ID), e.RAPrivateKeyCiphertext)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("SCEP RA key is not RSA")
	}
	cert, err := parseCertificate(e.RACertificatePEM)
	return key, cert, err
}

func validateNames(e Endpoint, csr *x509.CertificateRequest) error {
	policy := appPKI.NamePolicy{Subject: e.SubjectPattern, SAN: e.SANPattern}
	err := policy.Check(appPKI.RenderSubject(csr.RawSubject, csr.Subject), CSRSANNames(csr))
	switch {
	case errors.Is(err, appPKI.ErrPolicyInvalid):
		// A corrupted row, not the device's doing. The detail stays in the log
		// rather than the response: a SCEP client renders nothing but a failInfo,
		// so there is nowhere useful for it to go.
		log.Printf("scep endpoint=%s issuance policy is invalid: %v", e.ID, err)
		return fmt.Errorf("invalid endpoint policy")
	case err != nil:
		// Deliberately generic. A device is not the party who can fix a policy
		// refusal, and naming which of the two rules refused it, or which name
		// tripped it, tells an unauthenticated caller what the policy is.
		return fmt.Errorf("CSR does not match endpoint policy")
	}
	return nil
}

// sameNames reports whether a renewal request asks for the identity it is
// renewing.
//
// Nothing else on the renewal path checks this. authorize proves the signer
// certificate is live, unexpired, issued by this endpoint and inside its renewal
// window — and then, before this existed, issued whatever the CSR asked for. No
// challenge password is required on that path, so a key extracted from one
// enrolled device was a credential for every identity the CA vouches for: sign a
// RenewalReq with it, put CN=ceo@corp.example.com and a userPrincipalName
// otherName naming a domain admin in the CSR, and the endpoint signed it. Where
// these certificates feed 802.1X, VPN or smartcard logon — which is what the
// product is for — that is lateral movement, not a misconfiguration.
//
// The endpoint's own policy is not a backstop for it: a new endpoint's default
// subject pattern is ".+" and its SAN pattern is empty.
//
// The subject must be identical. The subject is the identity being renewed, and
// "renewal" means the same one.
//
// Subject alternative names may be dropped but not added. A device that stops
// claiming a name gives up authority; one that gains a name acquires it, and
// acquiring it is what this refuses. EST reaches the same place from the other
// direction, by resolving the renewable certificate by subject in the first
// place (see est.Service.Reenroll).
func sameNames(old *x509.Certificate, csr *x509.CertificateRequest) error {
	want := appPKI.RenderSubject(old.RawSubject, old.Subject)
	if got := appPKI.RenderSubject(csr.RawSubject, csr.Subject); got != want {
		return fmt.Errorf("renewal subject does not match the certificate being renewed")
	}
	held := map[string]bool{}
	for _, name := range certSANNames(old) {
		held[strings.ToLower(name)] = true
	}
	for _, name := range CSRSANNames(csr) {
		if !held[strings.ToLower(name)] {
			return fmt.Errorf("renewal asks for a subject alternative name the certificate being renewed does not hold")
		}
	}
	return nil
}

// certSANNames enumerates an issued certificate's subjectAltNames in the same
// form CSRSANNames renders a request's, so the two are comparable. It must stay
// in step with CSRSANNames: a form enumerated on one side and not the other reads
// as a name being added or dropped when it is neither.
func certSANNames(cert *x509.Certificate) []string {
	var out []string
	out = append(out, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	out = append(out, appPKI.UnparsedSANs(appPKI.SubjectAltNameFrom(cert.Extensions))...)
	return out
}

// CSRSANs renders the subject alternative names a request asks for, in the form
// the endpoint's SAN policy and a one-time challenge's expected-SANs are matched
// against. It must enumerate every name that will reach the issued certificate:
// otherName forms are copied through verbatim, so leaving them out here would
// let a client put a UPN naming somebody else past a configured SAN policy.
func CSRSANs(csr *x509.CertificateRequest) string {
	return strings.Join(CSRSANNames(csr), ",")
}

// CSRSANNames enumerates every subjectAltName a CSR asks for, including the
// otherName forms Go's x509 does not model — Microsoft's userPrincipalName
// above all. Callers matching a request against a policy must use this rather
// than reading csr.DNSNames and csr.IPAddresses directly: pki issues the
// requested SAN DER verbatim, so a name left out here is a name nothing checks.
func CSRSANNames(csr *x509.CertificateRequest) []string {
	var out []string
	out = append(out, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, csr.EmailAddresses...)
	for _, u := range csr.URIs {
		out = append(out, u.String())
	}
	out = append(out, appPKI.UnparsedSANs(appPKI.SubjectAltName(csr))...)
	return out
}

var algorithmOIDs = map[string]asn1.ObjectIdentifier{
	"md5": {1, 2, 840, 113549, 2, 5}, "des": {1, 3, 14, 3, 2, 7}, "sha1": {1, 3, 14, 3, 2, 26}, "3des": {1, 2, 840, 113549, 3, 7},
}

func cryptoPolicy(raw []byte, legacy bool) error {
	for name, oid := range algorithmOIDs {
		der, _ := asn1.Marshal(oid)
		if strings.Contains(string(raw), string(der)) && (name == "md5" || name == "des" || !legacy) {
			return fmt.Errorf("disallowed SCEP algorithm %s", name)
		}
	}
	return nil
}

func parseCertificate(raw string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
func raPurpose(id string) string { return "scep-ra/" + id }

// signerKeyDigest identifies the key a PKIMessage was signed by.
//
// Over the SubjectPublicKeyInfo rather than the whole certificate: the signer is
// a throwaway self-signed wrapper, and a client that rebuilds it around the same
// key between retries is the same client. Possession of the private key is what
// the comparison is for, and that is what SPKI names.
//
// Returns "" when there is no single signer, which ParsePKIMessage has already
// refused by the time this is reached — the empty string then simply fails to
// match any recorded digest.
func signerKeyDigest(signer *x509.Certificate) string {
	if signer == nil {
		return ""
	}
	sum := sha256.Sum256(signer.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
