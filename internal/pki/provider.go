package pki

import (
	"context"
	"crypto"
	"io"
	"time"
)

type KeyInfo struct {
	Name            string
	Algorithm       string
	ProtectionLevel string
	Purpose         string
	PublicKey       crypto.PublicKey
}

type CreateKeyRequest struct {
	OrgID      string
	CAName     string
	CAType     string
	Algorithm  string
	Protection string // software | hsm
}

type ImportJobInfo struct {
	Name                 string
	State                string // PENDING_GENERATION | ACTIVE | EXPIRED
	Method               string // e.g. RSA_OAEP_4096_SHA256_AES_256
	WrappingPublicKeyPEM string
	ExpireTime           time.Time
}

type CreateImportJobRequest struct {
	OrgID      string
	CAName     string
	CAType     string
	Protection string
}

type ImportKeyRequest struct {
	CryptoKey  string // full provider key resource name (created up front)
	ImportJob  string
	Algorithm  string // pki Algorithm* constant
	WrappedKey []byte
}

// KeyAttestation is the HSM statement and certificate chains returned for a
// key version. Example is true for providers that do not have HSM-backed key
// material (local mode and either provider's software mode).
type KeyAttestation struct {
	Format               string
	Content              []byte
	Artifacts            map[string][]byte
	CaviumCerts          []string
	GoogleCardCerts      []string
	GooglePartitionCerts []string
	Example              bool
}

type KeyProvider interface {
	SupportsCAImport() bool
	SupportsHSM() bool
	CreateSigningKey(context.Context, CreateKeyRequest) (KeyInfo, error)
	KeyInfo(context.Context, string) (KeyInfo, error)
	Attestation(context.Context, string) (KeyAttestation, error)
	Sign(context.Context, string, []byte, crypto.SignerOpts) ([]byte, error)
	HealthCheck(context.Context) error

	CreateImportJob(context.Context, CreateImportJobRequest) (ImportJobInfo, error)
	ImportJob(ctx context.Context, name string) (ImportJobInfo, error)
	// CreateImportTarget creates a CryptoKey with no initial version and
	// returns its resource name; the imported version lands under it.
	CreateImportTarget(context.Context, CreateKeyRequest) (string, error)
	// ImportWrappedKey submits the wrapped key material and returns the new
	// key version name (typically still PENDING_IMPORT).
	ImportWrappedKey(context.Context, ImportKeyRequest) (string, error)
	ImportedKeyState(ctx context.Context, versionName string) (state, failureReason string, err error)
	DestroyKeyVersion(ctx context.Context, versionName string) error
	Protect(ctx context.Context, purpose string, plaintext []byte) ([]byte, error)
	Unprotect(ctx context.Context, purpose string, ciphertext []byte) ([]byte, error)
}

type KMSSigner struct {
	ctx      context.Context
	provider KeyProvider
	key      KeyInfo
}

func NewKMSSigner(ctx context.Context, provider KeyProvider, key KeyInfo) KMSSigner {
	return KMSSigner{ctx: ctx, provider: provider, key: key}
}

func (s KMSSigner) Public() crypto.PublicKey {
	return s.key.PublicKey
}

func (s KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.provider.Sign(s.ctx, s.key.Name, digest, opts)
}
