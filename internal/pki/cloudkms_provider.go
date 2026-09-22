package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type CloudKMSProvider struct {
	client *kms.KeyManagementClient
	// keyRing is the parent every CA signing key is created under. Those keys
	// are created by this application, one per CA, on demand.
	keyRing string
	// protectionKeyName is the symmetric key that wraps application secrets.
	// Unlike the signing keys it is configured, never created: see Protect.
	protectionKeyName string
}

func (p *CloudKMSProvider) SupportsCAImport() bool { return true }
func (p *CloudKMSProvider) SupportsHSM() bool      { return true }

func NewCloudKMSProvider(ctx context.Context, keyRing, protectionKey string) (*CloudKMSProvider, error) {
	if strings.TrimSpace(protectionKey) == "" {
		return nil, fmt.Errorf("a protection key is required")
	}
	client, err := kms.NewKeyManagementClient(ctx, credentialOptions()...)
	if err != nil {
		return nil, err
	}
	return &CloudKMSProvider{client: client, keyRing: keyRing,
		protectionKeyName: strings.TrimSpace(protectionKey)}, nil
}

func credentialOptions() []option.ClientOption {
	creds := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if strings.HasPrefix(creds, "{") {
		return []option.ClientOption{option.WithCredentialsJSON([]byte(creds))}
	}
	return nil
}

func (p *CloudKMSProvider) Close() error {
	return p.client.Close()
}

func (p *CloudKMSProvider) CreateSigningKey(ctx context.Context, req CreateKeyRequest) (KeyInfo, error) {
	protection, err := googleProtectionLevel(req.Protection)
	if err != nil {
		return KeyInfo{}, err
	}
	algorithm, err := ValidateAlgorithm(req.Algorithm)
	if err != nil {
		return KeyInfo{}, err
	}
	kmsAlg, err := kmsAlgorithm(algorithm)
	if err != nil {
		return KeyInfo{}, err
	}
	cryptoKey, err := p.client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      p.keyRing,
		CryptoKeyId: keyID(req),
		CryptoKey: &kmspb.CryptoKey{
			Labels:                   kmsLabels(req.OrgID),
			Purpose:                  kmspb.CryptoKey_ASYMMETRIC_SIGN,
			DestroyScheduledDuration: destroyScheduledDuration(protection),
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: protection,
				Algorithm:       kmsAlg,
			},
		},
	})
	if err != nil {
		return KeyInfo{}, err
	}
	version := cryptoKey.GetPrimary().GetName()
	if version == "" {
		version = cryptoKey.GetName() + "/cryptoKeyVersions/1"
	}
	return p.KeyInfo(ctx, version)
}

func (p *CloudKMSProvider) KeyInfo(ctx context.Context, name string) (KeyInfo, error) {
	version, err := p.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: name})
	if err != nil {
		return KeyInfo{}, err
	}
	pub, err := p.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		return KeyInfo{}, err
	}
	publicKey, err := parsePublicKey(pub.GetPem())
	if err != nil {
		return KeyInfo{}, err
	}
	cryptoKey, err := p.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: cryptoKeyName(name)})
	if err != nil {
		return KeyInfo{}, err
	}
	info := KeyInfo{
		Name:            version.GetName(),
		Algorithm:       version.GetAlgorithm().String(),
		ProtectionLevel: version.GetProtectionLevel().String(),
		Purpose:         cryptoKey.GetPurpose().String(),
		PublicKey:       publicKey,
	}
	return info, validateKeyInfo(info)
}

func (p *CloudKMSProvider) Attestation(ctx context.Context, name string) (KeyAttestation, error) {
	version, err := p.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: name})
	if err != nil {
		return KeyAttestation{}, err
	}
	attestation := version.GetAttestation()
	if version.GetProtectionLevel() == kmspb.ProtectionLevel_SOFTWARE {
		return exampleKeyAttestation(name, ProtectionSoftware), nil
	}
	if attestation == nil || len(attestation.GetContent()) == 0 {
		return KeyAttestation{}, fmt.Errorf("Cloud KMS returned no attestation for HSM key version %q", name)
	}
	chains := attestation.GetCertChains()
	return KeyAttestation{
		Format:               attestation.GetFormat().String(),
		Content:              append([]byte(nil), attestation.GetContent()...),
		CaviumCerts:          append([]string(nil), chains.GetCaviumCerts()...),
		GoogleCardCerts:      append([]string(nil), chains.GetGoogleCardCerts()...),
		GooglePartitionCerts: append([]string(nil), chains.GetGooglePartitionCerts()...),
	}, nil
}

func (p *CloudKMSProvider) Sign(ctx context.Context, name string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	req := &kmspb.AsymmetricSignRequest{Name: name, Digest: digestFor(opts.HashFunc(), digest)}
	checksum := crc32.Checksum(digest, crc32.MakeTable(crc32.Castagnoli))
	req.DigestCrc32C = wrapperspb.Int64(int64(checksum))
	resp, err := p.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, err
	}
	if !resp.GetVerifiedDigestCrc32C() || resp.GetName() != name {
		return nil, fmt.Errorf("kms signing integrity check failed")
	}
	if int64(crc32.Checksum(resp.GetSignature(), crc32.MakeTable(crc32.Castagnoli))) != resp.GetSignatureCrc32C().GetValue() {
		return nil, fmt.Errorf("kms signature crc check failed")
	}
	return resp.GetSignature(), nil
}

// HealthCheck proves both halves of the configuration at startup: the ring the
// signing keys are created under, and the protection key, which is no longer
// created on demand and so has to exist already. Checking it here is what turns
// a wrong key path into a refusal to boot rather than a failure on the first
// authenticator enrolment, long after deploy.
func (p *CloudKMSProvider) HealthCheck(ctx context.Context) error {
	if _, err := p.client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{Name: p.keyRing}); err != nil {
		return fmt.Errorf("key ring %s: %w", p.keyRing, err)
	}
	key, err := p.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: p.protectionKeyName})
	if err != nil {
		return fmt.Errorf("protection key %s: %w", p.protectionKeyName, err)
	}
	if key.GetPurpose() != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return fmt.Errorf("protection key %s has purpose %s; it must be ENCRYPT_DECRYPT",
			p.protectionKeyName, key.GetPurpose())
	}
	return nil
}

// The key that wraps application secrets is configured, not created here, and
// not derived from the key ring either.
//
// It used to be a constant id looked up under the ring and created on the first
// NotFound. Three things were wrong with that. Creating it implicitly means the
// running application needs cloudkms.cryptoKeys.create at all times, purely to
// cover a case that happens once — the same permission that lets a compromised
// process mint keys. It also made the key's existence a side effect of whoever
// called Protect first, so nothing failed at startup if the configuration was
// wrong; the first person to enroll an authenticator found out. And because the
// name was assembled from the ring, pointing the ring elsewhere silently
// created a *different* key, under which none of the existing ciphertext opens.
//
// Being explicit costs one environment variable and makes all three impossible:
// the key is named in full, its absence is a startup failure (see HealthCheck),
// and moving it is a deliberate act rather than a consequence of another
// setting.
//
// What it wraps is every user's TOTP secret, every SCEP RA private key and
// every ACME EAB MAC key, so replacing it without re-encrypting is equivalent
// to deleting all three.

func (p *CloudKMSProvider) Protect(ctx context.Context, purpose string, plaintext []byte) ([]byte, error) {
	resp, err := p.client.Encrypt(ctx, &kmspb.EncryptRequest{Name: p.protectionKeyName, Plaintext: plaintext, AdditionalAuthenticatedData: []byte(purpose)})
	if err != nil {
		return nil, err
	}
	return resp.GetCiphertext(), nil
}

func (p *CloudKMSProvider) Unprotect(ctx context.Context, purpose string, ciphertext []byte) ([]byte, error) {
	resp, err := p.client.Decrypt(ctx, &kmspb.DecryptRequest{Name: p.protectionKeyName, Ciphertext: ciphertext, AdditionalAuthenticatedData: []byte(purpose)})
	if err != nil {
		return nil, err
	}
	return resp.GetPlaintext(), nil
}

func (p *CloudKMSProvider) CreateImportJob(ctx context.Context, req CreateImportJobRequest) (ImportJobInfo, error) {
	protection, err := googleProtectionLevel(req.Protection)
	if err != nil {
		return ImportJobInfo{}, err
	}
	job, err := p.client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
		Parent:      p.keyRing,
		ImportJobId: importJobID(CreateKeyRequest{OrgID: req.OrgID, CAName: req.CAName, CAType: req.CAType}),
		ImportJob: &kmspb.ImportJob{
			// RSA_OAEP alone cannot wrap RSA private keys (payload too
			// large); the AES_256 hybrid method covers every supported
			// algorithm.
			ImportMethod:    kmspb.ImportJob_RSA_OAEP_4096_SHA256_AES_256,
			ProtectionLevel: protection,
		},
	})
	if err != nil {
		return ImportJobInfo{}, err
	}
	return importJobInfo(job), nil
}

func (p *CloudKMSProvider) ImportJob(ctx context.Context, name string) (ImportJobInfo, error) {
	job, err := p.client.GetImportJob(ctx, &kmspb.GetImportJobRequest{Name: name})
	if err != nil {
		return ImportJobInfo{}, err
	}
	return importJobInfo(job), nil
}

func (p *CloudKMSProvider) CreateImportTarget(ctx context.Context, req CreateKeyRequest) (string, error) {
	protection, err := googleProtectionLevel(req.Protection)
	if err != nil {
		return "", err
	}
	algorithm, err := ValidateAlgorithm(req.Algorithm)
	if err != nil {
		return "", err
	}
	kmsAlg, err := kmsAlgorithm(algorithm)
	if err != nil {
		return "", err
	}
	cryptoKey, err := p.client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      p.keyRing,
		CryptoKeyId: keyID(req),
		CryptoKey: &kmspb.CryptoKey{
			Labels:                   kmsLabels(req.OrgID),
			Purpose:                  kmspb.CryptoKey_ASYMMETRIC_SIGN,
			DestroyScheduledDuration: destroyScheduledDuration(protection),
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: protection,
				Algorithm:       kmsAlg,
			},
		},
		SkipInitialVersionCreation: true,
	})
	if err != nil {
		return "", err
	}
	return cryptoKey.GetName(), nil
}

// destroyScheduledDuration sets how long a destroyed key version stays
// recoverable: 7 days for HSM keys, 1 day for cheaper software keys.
func destroyScheduledDuration(protection kmspb.ProtectionLevel) *durationpb.Duration {
	if protection == kmspb.ProtectionLevel_SOFTWARE {
		return durationpb.New(24 * time.Hour)
	}
	return durationpb.New(7 * 24 * time.Hour)
}

func googleProtectionLevel(value string) (kmspb.ProtectionLevel, error) {
	protection, err := ValidateProtection(value)
	if err != nil {
		return kmspb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED, err
	}
	if protection == ProtectionSoftware {
		return kmspb.ProtectionLevel_SOFTWARE, nil
	}
	return kmspb.ProtectionLevel_HSM, nil
}

func (p *CloudKMSProvider) ImportWrappedKey(ctx context.Context, req ImportKeyRequest) (string, error) {
	kmsAlg, err := kmsAlgorithm(req.Algorithm)
	if err != nil {
		return "", err
	}
	version, err := p.client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
		Parent:     req.CryptoKey,
		Algorithm:  kmsAlg,
		ImportJob:  req.ImportJob,
		WrappedKey: req.WrappedKey,
	})
	if err != nil {
		return "", err
	}
	return version.GetName(), nil
}

func (p *CloudKMSProvider) ImportedKeyState(ctx context.Context, versionName string) (string, string, error) {
	version, err := p.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: versionName})
	if err != nil {
		return "", "", err
	}
	return version.GetState().String(), version.GetImportFailureReason(), nil
}

func (p *CloudKMSProvider) DestroyKeyVersion(ctx context.Context, versionName string) error {
	_, err := p.client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{Name: versionName})
	return err
}

func importJobInfo(job *kmspb.ImportJob) ImportJobInfo {
	return ImportJobInfo{
		Name:                 job.GetName(),
		State:                job.GetState().String(),
		Method:               job.GetImportMethod().String(),
		WrappingPublicKeyPEM: job.GetPublicKey().GetPem(),
		ExpireTime:           job.GetExpireTime().AsTime(),
	}
}

// Cloud KMS accepts [a-zA-Z0-9_-]{1,63} for a CryptoKey or ImportJob id, and
// rejects anything longer outright — which surfaces as a CA that could not be
// created, saying nothing about names.
const kmsIDLimit = 63

// keySuffixLen is the "-" plus the 12 hex characters randomHex(6) renders.
const keySuffixLen = 13

// importSuffix marks an import job's id apart from the key it will wrap.
const importSuffix = "-import"

// orgKeyPrefix is how much of the organization id goes into a key id: the first
// group of the uuid, which is eight hex characters.
//
// The whole uuid used to go in, and it cost 36 of the 63 characters available.
// After the type there were five left for the CA's name, so "Issuing Test"
// became "issui" — the one part of the id a person would have recognised was
// the part being truncated away. Eight characters still identify the
// organization at a glance in the KMS console, and the full id travels as a
// label (see kmsLabels) so it stays searchable there.
func orgKeyPrefix(orgID string) string {
	if i := strings.Index(orgID, "-"); i > 0 {
		return orgID[:i]
	}
	if len(orgID) > 8 {
		return orgID[:8]
	}
	return orgID
}

// kmsLabels tags a key with the organization that owns it. The key id carries
// only a prefix, so this is what makes "every key belonging to org X" an exact
// query rather than a prefix match. Label values take the same characters a
// uuid is made of.
func kmsLabels(orgID string) map[string]string {
	return map[string]string{"org": strings.ToLower(strings.TrimSpace(orgID))}
}

// keyBase builds the readable part of an id, trimmed to budget.
//
// Separator runs are collapsed and the ends trimmed. Without that a CA named
// "Test " produced "…-test--<hex>", because the trailing space became a dash
// and the suffix added its own; "Test / Prod" managed three in a row. The trim
// is applied again after truncation, since cutting at the budget can land on a
// separator and reintroduce the same pair.
func keyBase(req CreateKeyRequest, budget int) string {
	raw := strings.ToLower(orgKeyPrefix(req.OrgID) + "-" + req.CAType + "-" + req.CAName)
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == ' ', r == '_', r == '/', r == '.':
			b.WriteRune('-')
		}
	}
	base := collapseDashes(b.String())
	if len(base) > budget {
		base = strings.Trim(base[:budget], "-")
	}
	return base
}

// collapseDashes reduces runs of "-" to one and removes them from both ends.
func collapseDashes(s string) string {
	var b strings.Builder
	var lastDash bool
	for _, r := range s {
		if r == '-' {
			if lastDash {
				continue
			}
			lastDash = true
		} else {
			lastDash = false
		}
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

// keyID builds a KMS CryptoKey id from the org and CA identity plus a random
// suffix; the suffix keeps ids unique when names collide after truncation
// (e.g. rotated CAs that share a long prefix).
func keyID(req CreateKeyRequest) string {
	return keyBase(req, kmsIDLimit-keySuffixLen) + "-" + randomHex(6)
}

// importJobID budgets for its own suffix as well as the random one. It used to
// be keyID(req) + "-import", and keyID is allowed to fill all 63 characters on
// its own — so a CA with a long name produced a 70-character id that Cloud KMS
// refused, and importing an existing CA failed for reasons that named nothing
// to do with its name.
func importJobID(req CreateKeyRequest) string {
	return keyBase(req, kmsIDLimit-keySuffixLen-len(importSuffix)) + "-" + randomHex(6) + importSuffix
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(buf)
}

func cryptoKeyName(version string) string {
	if i := strings.LastIndex(version, "/cryptoKeyVersions/"); i > 0 {
		return version[:i]
	}
	return version
}

func kmsAlgorithm(algorithm string) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	switch algorithm {
	case AlgorithmECDSAP256SHA256:
		return kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil
	case AlgorithmECDSAP384SHA384:
		return kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, nil
	case AlgorithmRSA3072SHA256:
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, nil
	case AlgorithmRSA4096SHA256:
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, nil
	default:
		return kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED, fmt.Errorf("unsupported kms algorithm %q", algorithm)
	}
}

func digestFor(hash crypto.Hash, digest []byte) *kmspb.Digest {
	switch hash {
	case crypto.SHA384:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}}
	case crypto.SHA512:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha512{Sha512: digest}}
	default:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}
	}
}

func parsePublicKey(raw string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid kms public key pem")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func validateKeyInfo(info KeyInfo) error {
	switch info.ProtectionLevel {
	case "HSM":
	case "HSM_SINGLE_TENANT":
		// Single-tenant HSM keys are deliberately unsupported: they carry a
		// very large recurring cost and nothing here should ever create or
		// use one.
		return fmt.Errorf("kms key %s is single-tenant HSM, which is not supported", info.Name)
	case "SOFTWARE":
	default:
		return fmt.Errorf("kms key %s protection level must be HSM or SOFTWARE", info.Name)
	}
	if info.Purpose != "ASYMMETRIC_SIGN" {
		return fmt.Errorf("kms key %s purpose must be ASYMMETRIC_SIGN", info.Name)
	}
	switch info.Algorithm {
	case AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384, AlgorithmRSA3072SHA256, AlgorithmRSA4096SHA256:
	default:
		return fmt.Errorf("unsupported kms signing algorithm %q", info.Algorithm)
	}
	return nil
}
