package pki

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"
)

type fakeImportJob struct {
	info ImportJobInfo
	priv *rsa.PrivateKey
}

type FakeProvider struct {
	mu              sync.Mutex
	keys            map[string]crypto.Signer
	importJobs      map[string]fakeImportJob
	targetAlg       map[string]string
	versionState    map[string]string
	versionFailure  map[string]string
	protectionKey   []byte
	disableCAImport bool
}

func (p *FakeProvider) SupportsCAImport() bool { return !p.disableCAImport }
func (p *FakeProvider) SupportsHSM() bool      { return false }

func NewFakeProvider() *FakeProvider {
	protectionKey := make([]byte, 32)
	_, _ = rand.Read(protectionKey)
	return &FakeProvider{
		keys:           map[string]crypto.Signer{},
		importJobs:     map[string]fakeImportJob{},
		targetAlg:      map[string]string{},
		versionState:   map[string]string{},
		versionFailure: map[string]string{},
		protectionKey:  protectionKey,
	}
}

// NewLocalProvider returns the deprecated runtime development provider. Tests
// use NewFakeProvider directly, including its import simulation; the actual
// local mode does not advertise an import path that cannot persist keys.
func NewLocalProvider() *FakeProvider {
	provider := NewFakeProvider()
	provider.disableCAImport = true
	return provider
}

func (p *FakeProvider) Protect(_ context.Context, purpose string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.protectionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, []byte(purpose)), nil
}

func (p *FakeProvider) Unprotect(_ context.Context, purpose string, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.protectionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("invalid protected value")
	}
	return aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], []byte(purpose))
}

// CreateSigningKey mints an in-memory stdlib key. It reports SOFTWARE
// protection because that is what the key is: reporting HSM would stamp every
// CA created locally with export_posture = non_exportable_hsm, and
// the UI would tell a developer their throwaway key is hardware-backed. It also
// means validateKeyInfo's SOFTWARE branch is exercised locally rather than only
// against a production provider.
func (p *FakeProvider) CreateSigningKey(_ context.Context, req CreateKeyRequest) (KeyInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	protection, err := ValidateProtection(req.Protection)
	if err != nil {
		return KeyInfo{}, err
	}
	if protection != ProtectionSoftware {
		return KeyInfo{}, fmt.Errorf("the deprecated local key provider supports software keys only")
	}
	algorithm, err := ValidateAlgorithm(req.Algorithm)
	if err != nil {
		return KeyInfo{}, err
	}
	var key crypto.Signer
	switch algorithm {
	case AlgorithmECDSAP256SHA256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgorithmECDSAP384SHA384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case AlgorithmRSA3072SHA256:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case AlgorithmRSA4096SHA256:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return KeyInfo{}, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
	if err != nil {
		return KeyInfo{}, err
	}
	name := "fake-hsm/" + keyID(req)
	p.keys[name] = key
	return KeyInfo{Name: name, Algorithm: algorithm, ProtectionLevel: "SOFTWARE", Purpose: "ASYMMETRIC_SIGN", PublicKey: key.Public()}, nil
}

func (p *FakeProvider) KeyInfo(_ context.Context, name string) (KeyInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.keys[name]
	if !ok {
		return KeyInfo{}, fmt.Errorf("key %q not found", name)
	}
	return KeyInfo{Name: name, Algorithm: algorithmForKey(key), ProtectionLevel: "SOFTWARE", Purpose: "ASYMMETRIC_SIGN", PublicKey: key.Public()}, nil
}

func (p *FakeProvider) Attestation(_ context.Context, name string) (KeyAttestation, error) {
	p.mu.Lock()
	_, ok := p.keys[name]
	p.mu.Unlock()
	if !ok {
		return KeyAttestation{}, fmt.Errorf("key %q not found", name)
	}
	return exampleKeyAttestation(name, "local development"), nil
}

func (p *FakeProvider) Sign(_ context.Context, name string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	p.mu.Lock()
	key, ok := p.keys[name]
	p.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("key %q not found", name)
	}
	return key.Sign(rand.Reader, digest, opts)
}

func (p *FakeProvider) HealthCheck(context.Context) error { return nil }

// CreateImportJob mimics KMS with a direct RSA-OAEP wrapping key. The single
// OAEP step only fits EC private keys, which is enough for dev testing.
func (p *FakeProvider) CreateImportJob(_ context.Context, req CreateImportJobRequest) (ImportJobInfo, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return ImportJobInfo{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return ImportJobInfo{}, err
	}
	name := "fake-hsm/import-jobs/" + keyID(CreateKeyRequest{OrgID: req.OrgID, CAName: req.CAName, CAType: req.CAType})
	info := ImportJobInfo{
		Name:                 name,
		State:                "ACTIVE",
		Method:               "RSA_OAEP_4096_SHA256",
		WrappingPublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})),
		ExpireTime:           time.Now().UTC().Add(72 * time.Hour),
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.importJobs[name] = fakeImportJob{info: info, priv: priv}
	return info, nil
}

func (p *FakeProvider) ImportJob(_ context.Context, name string) (ImportJobInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	job, ok := p.importJobs[name]
	if !ok {
		return ImportJobInfo{}, fmt.Errorf("import job %q not found", name)
	}
	if time.Now().After(job.info.ExpireTime) {
		job.info.State = "EXPIRED"
	}
	return job.info, nil
}

func (p *FakeProvider) CreateImportTarget(_ context.Context, req CreateKeyRequest) (string, error) {
	algorithm, err := ValidateAlgorithm(req.Algorithm)
	if err != nil {
		return "", err
	}
	name := "fake-hsm/" + keyID(req)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targetAlg[name] = algorithm
	return name, nil
}

func (p *FakeProvider) ImportWrappedKey(_ context.Context, req ImportKeyRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	job, ok := p.importJobs[req.ImportJob]
	if !ok {
		return "", fmt.Errorf("import job %q not found", req.ImportJob)
	}
	if _, ok := p.targetAlg[req.CryptoKey]; !ok {
		return "", fmt.Errorf("import target %q not found", req.CryptoKey)
	}
	version := req.CryptoKey + "/cryptoKeyVersions/1"
	der, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, job.priv, req.WrappedKey, nil)
	if err != nil {
		p.versionState[version] = "IMPORT_FAILED"
		p.versionFailure[version] = "wrapped key could not be unwrapped"
		return version, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		p.versionState[version] = "IMPORT_FAILED"
		p.versionFailure[version] = "unwrapped material is not a PKCS#8 private key"
		return version, nil
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		p.versionState[version] = "IMPORT_FAILED"
		p.versionFailure[version] = "unwrapped key cannot sign"
		return version, nil
	}
	p.keys[version] = signer
	p.versionState[version] = "ENABLED"
	return version, nil
}

func (p *FakeProvider) ImportedKeyState(_ context.Context, versionName string) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state, ok := p.versionState[versionName]
	if !ok {
		return "", "", fmt.Errorf("key version %q not found", versionName)
	}
	return state, p.versionFailure[versionName], nil
}

func (p *FakeProvider) DestroyKeyVersion(_ context.Context, versionName string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.keys, versionName)
	p.versionState[versionName] = "DESTROYED"
	return nil
}

func algorithmForKey(key crypto.Signer) string {
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		if pub.Curve == elliptic.P384() {
			return AlgorithmECDSAP384SHA384
		}
		return AlgorithmECDSAP256SHA256
	case *rsa.PublicKey:
		if pub.N.BitLen() >= 4096 {
			return AlgorithmRSA4096SHA256
		}
		return AlgorithmRSA3072SHA256
	default:
		return ""
	}
}
