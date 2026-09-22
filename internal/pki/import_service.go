package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	maxCertificatePEMBytes = 64 << 10
	maxChainPEMBytes       = 128 << 10
	maxChainCerts          = 8
	maxWrappedKeyBytes     = 16 << 10
	minWrappedKeyBytes     = 100
)

type StartCAImportRequest struct {
	OrgID          string
	UserID         string
	Name           string
	Type           string
	CertificatePEM string
	ChainPEM       string
	Protection     string
}

// StartCAImport validates the uploaded CA certificate, provisions the KMS
// import target and import job, and records the pending import. The private
// key never touches the app: the caller wraps it locally with the job's
// wrapping key and submits only the wrapped blob.
func (s Service) StartCAImport(ctx context.Context, req StartCAImportRequest) (CAImportJob, error) {
	if !s.provider.SupportsCAImport() {
		return CAImportJob{}, fmt.Errorf("this key provider does not support wrapped-key CA import")
	}
	if req.Type != CATypeRoot && req.Type != CATypeIssuing {
		return CAImportJob{}, fmt.Errorf("invalid CA type")
	}
	if strings.TrimSpace(req.Name) == "" {
		return CAImportJob{}, fmt.Errorf("CA name required")
	}
	if req.Type == CATypeRoot {
		if _, err := s.repo.RootCA(ctx, req.OrgID); err == nil {
			return CAImportJob{}, fmt.Errorf("root CA already exists")
		} else if !errors.Is(err, sql.ErrNoRows) {
			return CAImportJob{}, err
		}
	}
	if err := rejectPrivateKeyMaterial(req.CertificatePEM, req.ChainPEM); err != nil {
		return CAImportJob{}, err
	}
	cert, err := parseImportedCACert(req.CertificatePEM)
	if err != nil {
		return CAImportJob{}, err
	}
	chain, err := validateImportChain(req.Type, cert, req.ChainPEM)
	if err != nil {
		return CAImportJob{}, err
	}
	algorithm, err := algorithmForPublicKey(cert.PublicKey)
	if err != nil {
		return CAImportJob{}, err
	}
	protection := strings.TrimSpace(req.Protection)
	if protection == "" {
		protection = ProtectionHSM
		if !s.provider.SupportsHSM() {
			protection = ProtectionSoftware
		}
	} else if protection, err = ValidateProtection(protection); err != nil {
		return CAImportJob{}, err
	}
	if protection == ProtectionHSM && !s.provider.SupportsHSM() {
		return CAImportJob{}, fmt.Errorf("the configured key provider does not support HSM keys")
	}
	target, err := s.provider.CreateImportTarget(ctx, CreateKeyRequest{OrgID: req.OrgID, CAName: req.Name, CAType: req.Type, Algorithm: algorithm, Protection: protection})
	if err != nil {
		return CAImportJob{}, err
	}
	jobInfo, err := s.provider.CreateImportJob(ctx, CreateImportJobRequest{OrgID: req.OrgID, CAName: req.Name, CAType: req.Type, Protection: protection})
	if err != nil {
		return CAImportJob{}, err
	}
	job := CAImportJob{
		OrganizationID:       req.OrgID,
		CreatedBy:            req.UserID,
		CAName:               strings.TrimSpace(req.Name),
		CAType:               req.Type,
		Algorithm:            algorithm,
		CertificatePEM:       req.CertificatePEM,
		ChainPEM:             chain,
		KMSImportJob:         jobInfo.Name,
		KMSCryptoKey:         target,
		WrappingMethod:       jobInfo.Method,
		WrappingPublicKeyPEM: jobInfo.WrappingPublicKeyPEM,
		State:                ImportStatePreparing,
	}
	if !jobInfo.ExpireTime.IsZero() {
		expires := jobInfo.ExpireTime.UTC()
		job.ExpiresAt = &expires
	}
	if jobInfo.State == "ACTIVE" && jobInfo.WrappingPublicKeyPEM != "" {
		job.State = ImportStateReadyToWrap
	}
	job.ID, err = s.repo.CreateCAImportJob(ctx, job)
	if err != nil {
		return CAImportJob{}, err
	}
	return job, nil
}

// SyncCAImport advances the job's state machine by one observation of the
// provider; the status page polls it until a terminal state.
func (s Service) SyncCAImport(ctx context.Context, orgID, userID, jobID string) (CAImportJob, error) {
	job, err := s.repo.CAImportJob(ctx, orgID, jobID)
	if err != nil {
		return CAImportJob{}, err
	}
	switch job.State {
	case ImportStatePreparing:
		info, err := s.provider.ImportJob(ctx, job.KMSImportJob)
		if err != nil {
			return job, err
		}
		switch info.State {
		case "ACTIVE":
			expires := info.ExpireTime.UTC()
			if err := s.repo.SetCAImportJobWrapping(ctx, orgID, job.ID, ImportStateReadyToWrap, info.WrappingPublicKeyPEM, info.Method, expires); err != nil {
				return job, err
			}
			job.State = ImportStateReadyToWrap
			job.WrappingPublicKeyPEM = info.WrappingPublicKeyPEM
			job.WrappingMethod = info.Method
			job.ExpiresAt = &expires
		case "EXPIRED":
			return s.failImport(ctx, job, ImportStateExpired, "the KMS import job expired before the key was wrapped")
		}
	case ImportStateReadyToWrap:
		if job.ExpiresAt != nil && time.Now().After(*job.ExpiresAt) {
			return s.failImport(ctx, job, ImportStateExpired, "the KMS import job expired before the key was wrapped")
		}
	case ImportStateImporting:
		state, reason, err := s.provider.ImportedKeyState(ctx, job.KMSKeyVersion)
		if err != nil {
			return job, err
		}
		switch state {
		case "ENABLED":
			return s.finalizeImport(ctx, job, userID)
		case "IMPORT_FAILED":
			if reason == "" {
				reason = "KMS rejected the wrapped key"
			}
			return s.failImport(ctx, job, ImportStateFailed, reason)
		}
	}
	return job, nil
}

// SubmitWrappedKey accepts the RSA-OAEP-wrapped private key blob and hands it
// to KMS. Only wrapped bytes are accepted; plaintext keys are rejected before
// this point by rejectPrivateKeyMaterial on every form field.
func (s Service) SubmitWrappedKey(ctx context.Context, orgID, userID, jobID, wrappedBase64 string) (CAImportJob, error) {
	job, err := s.repo.CAImportJob(ctx, orgID, jobID)
	if err != nil {
		return CAImportJob{}, err
	}
	if job.State != ImportStateReadyToWrap {
		return job, fmt.Errorf("import job is not ready for a wrapped key (state %s)", job.State)
	}
	if job.ExpiresAt != nil && time.Now().After(*job.ExpiresAt) {
		return s.failImport(ctx, job, ImportStateExpired, "the KMS import job expired before the key was wrapped")
	}
	if err := rejectPrivateKeyMaterial(wrappedBase64); err != nil {
		return job, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(wrappedBase64), ""))
	if err != nil {
		return job, fmt.Errorf("wrapped key must be base64 encoded")
	}
	if len(wrapped) < minWrappedKeyBytes || len(wrapped) > maxWrappedKeyBytes {
		return job, fmt.Errorf("wrapped key size is outside the expected range")
	}
	version, err := s.provider.ImportWrappedKey(ctx, ImportKeyRequest{
		CryptoKey:  job.KMSCryptoKey,
		ImportJob:  job.KMSImportJob,
		Algorithm:  job.Algorithm,
		WrappedKey: wrapped,
	})
	if err != nil {
		return job, err
	}
	if err := s.repo.SetCAImportJobKeyVersion(ctx, orgID, job.ID, version); err != nil {
		return job, s.destroyOnError(ctx, version, err)
	}
	job.KMSKeyVersion = version
	job.State = ImportStateImporting
	return s.SyncCAImport(ctx, orgID, userID, job.ID)
}

func (s Service) CancelCAImport(ctx context.Context, orgID, userID, jobID string) error {
	job, err := s.repo.CAImportJob(ctx, orgID, jobID)
	if err != nil {
		return err
	}
	switch job.State {
	case ImportStatePreparing, ImportStateReadyToWrap, ImportStateImporting:
	default:
		return fmt.Errorf("import job cannot be cancelled (state %s)", job.State)
	}
	// KMS import jobs and empty crypto keys cannot be deleted; the job
	// expires on its own within ~3 days. Only an imported version needs
	// destroying.
	if job.KMSKeyVersion != "" {
		if err := s.provider.DestroyKeyVersion(ctx, job.KMSKeyVersion); err != nil {
			return err
		}
	}
	return s.repo.CancelCAImportJob(ctx, orgID, job.ID, userID)
}

// finalizeImport runs the critical security check — the imported provider key's
// public half must match the uploaded certificate's SubjectPublicKeyInfo —
// then activates the CA.
func (s Service) finalizeImport(ctx context.Context, job CAImportJob, userID string) (CAImportJob, error) {
	key, err := s.provider.KeyInfo(ctx, job.KMSKeyVersion)
	if err != nil {
		return job, err
	}
	cert, err := parseCertificate(job.CertificatePEM)
	if err != nil {
		return s.failImport(ctx, job, ImportStateFailed, "stored certificate could not be parsed")
	}
	if !publicKeysEqual(cert.PublicKey, key.PublicKey) {
		if destroyErr := s.provider.DestroyKeyVersion(ctx, job.KMSKeyVersion); destroyErr != nil {
			return job, destroyErr
		}
		return s.failImport(ctx, job, ImportStateFailed, "imported key does not match the certificate public key")
	}
	ca := CertificateAuthority{
		OrganizationID: job.OrganizationID,
		Name:           job.CAName,
		Type:           job.CAType,
		Status:         CAStatusActive,
		Subject:        cert.Subject.String(),
		Algorithm:      key.Algorithm,
		KMSKeyVersion:  key.Name,
		CertificatePEM: job.CertificatePEM,
		ChainPEM:       job.ChainPEM,
		ExportPosture:  exportPosture(key.ProtectionLevel, true),
		IssuanceEKUs:   EKUClientAuth,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
	}
	caID, err := s.repo.CreateCA(ctx, ca)
	if err != nil {
		return job, err
	}
	if err := s.repo.CompleteCAImportJob(ctx, job.OrganizationID, job.ID, caID); err != nil {
		return job, err
	}
	if err := s.repo.RecordSigning(ctx, job.OrganizationID, caID, userID, key.Name, "", cert.SerialNumber.Text(16), "imported_ca"); err != nil {
		return job, err
	}
	job.State = ImportStateCompleted
	job.CertificateAuthorityID = caID
	return job, nil
}

func (s Service) failImport(ctx context.Context, job CAImportJob, state, reason string) (CAImportJob, error) {
	if err := s.repo.UpdateCAImportJobState(ctx, job.OrganizationID, job.ID, state, reason); err != nil {
		return job, err
	}
	job.State = state
	job.FailureReason = reason
	return job, nil
}

func parseImportedCACert(raw string) (*x509.Certificate, error) {
	if len(raw) > maxCertificatePEMBytes {
		return nil, fmt.Errorf("certificate is too large")
	}
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("a single PEM certificate is required")
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		return nil, fmt.Errorf("submit exactly one certificate; put intermediates in the chain field")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate could not be parsed: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, fmt.Errorf("certificate is not a CA certificate")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("certificate key usage does not permit certificate signing")
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate has expired")
	}
	return cert, nil
}

func validateImportChain(caType string, cert *x509.Certificate, chainPEM string) (string, error) {
	chainPEM = strings.TrimSpace(chainPEM)
	if caType == CATypeRoot {
		if chainPEM != "" {
			return "", fmt.Errorf("a root CA must be self-signed; leave the chain empty")
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			return "", fmt.Errorf("root CA certificate is not self-signed")
		}
		return "", nil
	}
	if chainPEM == "" {
		return "", nil
	}
	if len(chainPEM) > maxChainPEMBytes {
		return "", fmt.Errorf("chain is too large")
	}
	var parents []*x509.Certificate
	rest := []byte(chainPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("chain must contain only certificates")
		}
		parent, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("chain certificate could not be parsed: %w", err)
		}
		parents = append(parents, parent)
		if len(parents) > maxChainCerts {
			return "", fmt.Errorf("chain has too many certificates")
		}
	}
	if len(parents) == 0 {
		return "", fmt.Errorf("chain contains no certificates")
	}
	child := cert
	for i, parent := range parents {
		if err := child.CheckSignatureFrom(parent); err != nil {
			return "", fmt.Errorf("chain certificate %d does not sign its predecessor", i+1)
		}
		child = parent
	}
	return chainPEM, nil
}

// algorithmForPublicKey derives the KMS signing algorithm from the CA
// certificate's key, rejecting anything below the policy floor (RSA-3072,
// P-256).
func algorithmForPublicKey(pub crypto.PublicKey) (string, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return AlgorithmECDSAP256SHA256, nil
		case elliptic.P384():
			return AlgorithmECDSAP384SHA384, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve; use P-256 or P-384")
		}
	case *rsa.PublicKey:
		switch bits := key.N.BitLen(); {
		case bits >= 4096:
			return AlgorithmRSA4096SHA256, nil
		case bits >= 3072:
			return AlgorithmRSA3072SHA256, nil
		default:
			return "", fmt.Errorf("RSA keys below 3072 bits are not accepted")
		}
	default:
		return "", fmt.Errorf("unsupported public key type")
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := a.(equaler)
	return ok && pub.Equal(b)
}
