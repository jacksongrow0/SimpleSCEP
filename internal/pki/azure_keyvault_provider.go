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
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// AzureKeyVaultProvider stores CA keys in an Azure Key Vault. Each create
// request selects EC/RSA software keys or EC-HSM/RSA-HSM keys.
type AzureKeyVaultProvider struct {
	client        *azkeys.Client
	vaultURL      string
	protectionKey azureKeyReference
	algorithms    sync.Map // full, versioned key ID -> SimpleSCEP algorithm
}

type azureKeyReference struct {
	ID      string
	Name    string
	Version string
}

func NewAzureKeyVaultProvider(vaultURL, protectionKey string) (*AzureKeyVaultProvider, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure credential: %w", err)
	}
	client, err := azkeys.NewClient(strings.TrimRight(strings.TrimSpace(vaultURL), "/"), credential, nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure Key Vault client: %w", err)
	}
	return newAzureKeyVaultProvider(client, vaultURL, protectionKey)
}

func newAzureKeyVaultProvider(client *azkeys.Client, vaultURL, protectionKey string) (*AzureKeyVaultProvider, error) {
	base, err := normalizedAzureVaultURL(vaultURL)
	if err != nil {
		return nil, err
	}
	ref, err := parseAzureKeyReference(base, protectionKey, true)
	if err != nil {
		return nil, fmt.Errorf("Azure protection key: %w", err)
	}
	return &AzureKeyVaultProvider{client: client, vaultURL: base, protectionKey: ref}, nil
}

func normalizedAzureVaultURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("AZURE_KEY_VAULT_URL must be an HTTPS vault base URL")
	}
	return "https://" + strings.ToLower(u.Host), nil
}

func parseAzureKeyReference(vaultURL, raw string, requireVersion bool) (azureKeyReference, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return azureKeyReference{}, fmt.Errorf("must be a full HTTPS key ID")
	}
	if !strings.EqualFold(u.Scheme+"://"+u.Host, vaultURL) {
		return azureKeyReference{}, fmt.Errorf("must belong to %s", vaultURL)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "keys" || parts[1] == "" {
		return azureKeyReference{}, fmt.Errorf("must have the form %s/keys/<name>/<version>", vaultURL)
	}
	version := ""
	if len(parts) == 3 {
		version = parts[2]
	}
	if requireVersion && version == "" {
		return azureKeyReference{}, fmt.Errorf("must name an immutable key version")
	}
	id := vaultURL + "/keys/" + parts[1]
	if version != "" {
		id += "/" + version
	}
	return azureKeyReference{ID: id, Name: parts[1], Version: version}, nil
}

func (p *AzureKeyVaultProvider) SupportsCAImport() bool { return false }
func (p *AzureKeyVaultProvider) SupportsHSM() bool      { return true }

func (p *AzureKeyVaultProvider) CreateSigningKey(ctx context.Context, req CreateKeyRequest) (KeyInfo, error) {
	protection, err := ValidateProtection(req.Protection)
	if err != nil {
		return KeyInfo{}, err
	}
	algorithm, err := ValidateAlgorithm(req.Algorithm)
	if err != nil {
		return KeyInfo{}, err
	}
	parameters, err := azureSigningKeyParameters(algorithm, protection == ProtectionHSM)
	if err != nil {
		return KeyInfo{}, err
	}
	parameters.Tags = map[string]*string{"org": to.Ptr(strings.ToLower(strings.TrimSpace(req.OrgID)))}
	created, err := p.client.CreateKey(ctx, keyID(req), parameters, nil)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("create Azure Key Vault signing key: %w", err)
	}
	if created.Key == nil || created.Key.KID == nil {
		return KeyInfo{}, fmt.Errorf("Azure Key Vault returned a signing key without an ID")
	}
	return p.keyInfoFromBundle(created.Key, created.Attributes)
}

func azureSigningKeyParameters(algorithm string, hsm bool) (azkeys.CreateKeyParameters, error) {
	sign, verify := azkeys.KeyOperationSign, azkeys.KeyOperationVerify
	params := azkeys.CreateKeyParameters{KeyOps: []*azkeys.KeyOperation{&sign, &verify}, KeyAttributes: &azkeys.KeyAttributes{Enabled: to.Ptr(true), Exportable: to.Ptr(false)}}
	switch algorithm {
	case AlgorithmECDSAP256SHA256:
		params.Kty, params.Curve = to.Ptr(azkeys.KeyTypeEC), to.Ptr(azkeys.CurveNameP256)
	case AlgorithmECDSAP384SHA384:
		params.Kty, params.Curve = to.Ptr(azkeys.KeyTypeEC), to.Ptr(azkeys.CurveNameP384)
	case AlgorithmRSA3072SHA256:
		params.Kty, params.KeySize = to.Ptr(azkeys.KeyTypeRSA), to.Ptr(int32(3072))
	case AlgorithmRSA4096SHA256:
		params.Kty, params.KeySize = to.Ptr(azkeys.KeyTypeRSA), to.Ptr(int32(4096))
	default:
		return azkeys.CreateKeyParameters{}, fmt.Errorf("unsupported Azure signing algorithm %q", algorithm)
	}
	if hsm {
		if *params.Kty == azkeys.KeyTypeEC {
			params.Kty = to.Ptr(azkeys.KeyTypeECHSM)
		} else {
			params.Kty = to.Ptr(azkeys.KeyTypeRSAHSM)
		}
	}
	return params, nil
}

func (p *AzureKeyVaultProvider) KeyInfo(ctx context.Context, rawID string) (KeyInfo, error) {
	ref, err := parseAzureKeyReference(p.vaultURL, rawID, true)
	if err != nil {
		return KeyInfo{}, err
	}
	key, err := p.client.GetKey(ctx, ref.Name, ref.Version, nil)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("get Azure Key Vault key: %w", err)
	}
	return p.keyInfoFromBundle(key.Key, key.Attributes)
}

func (p *AzureKeyVaultProvider) keyInfoFromBundle(key *azkeys.JSONWebKey, attributes *azkeys.KeyAttributes) (KeyInfo, error) {
	if key == nil || key.KID == nil || key.Kty == nil {
		return KeyInfo{}, fmt.Errorf("Azure Key Vault returned incomplete key metadata")
	}
	if attributes != nil && attributes.Enabled != nil && !*attributes.Enabled {
		return KeyInfo{}, fmt.Errorf("Azure Key Vault key %s is disabled", string(*key.KID))
	}
	publicKey, algorithm, protection, err := azurePublicKey(key)
	if err != nil {
		return KeyInfo{}, err
	}
	info := KeyInfo{Name: string(*key.KID), Algorithm: algorithm, ProtectionLevel: protection, Purpose: "ASYMMETRIC_SIGN", PublicKey: publicKey}
	if err := validateKeyInfo(info); err != nil {
		return KeyInfo{}, err
	}
	p.algorithms.Store(info.Name, info.Algorithm)
	return info, nil
}

func azurePublicKey(key *azkeys.JSONWebKey) (crypto.PublicKey, string, string, error) {
	protection := "SOFTWARE"
	switch *key.Kty {
	case azkeys.KeyTypeECHSM, azkeys.KeyTypeRSAHSM:
		protection = "HSM"
	case azkeys.KeyTypeEC, azkeys.KeyTypeRSA:
	default:
		return nil, "", "", fmt.Errorf("unsupported Azure Key Vault key type %q", *key.Kty)
	}
	switch *key.Kty {
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		if key.Crv == nil || len(key.X) == 0 || len(key.Y) == 0 {
			return nil, "", "", fmt.Errorf("Azure Key Vault returned an incomplete EC public key")
		}
		var curve elliptic.Curve
		var algorithm string
		switch *key.Crv {
		case azkeys.CurveNameP256:
			curve, algorithm = elliptic.P256(), AlgorithmECDSAP256SHA256
		case azkeys.CurveNameP384:
			curve, algorithm = elliptic.P384(), AlgorithmECDSAP384SHA384
		default:
			return nil, "", "", fmt.Errorf("unsupported Azure EC curve %q", *key.Crv)
		}
		publicKey := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(key.X), Y: new(big.Int).SetBytes(key.Y)}
		if !curve.IsOnCurve(publicKey.X, publicKey.Y) {
			return nil, "", "", fmt.Errorf("Azure Key Vault returned an invalid EC public key")
		}
		return publicKey, algorithm, protection, nil
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		if len(key.N) == 0 || len(key.E) == 0 {
			return nil, "", "", fmt.Errorf("Azure Key Vault returned an incomplete RSA public key")
		}
		e := new(big.Int).SetBytes(key.E)
		if !e.IsInt64() || e.Sign() <= 0 {
			return nil, "", "", fmt.Errorf("Azure Key Vault returned an invalid RSA exponent")
		}
		publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(key.N), E: int(e.Int64())}
		var algorithm string
		switch publicKey.N.BitLen() {
		case 3072:
			algorithm = AlgorithmRSA3072SHA256
		case 4096:
			algorithm = AlgorithmRSA4096SHA256
		default:
			return nil, "", "", fmt.Errorf("unsupported Azure RSA key size %d", publicKey.N.BitLen())
		}
		return publicKey, algorithm, protection, nil
	}
	panic("unreachable")
}

func (p *AzureKeyVaultProvider) Sign(ctx context.Context, rawID string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ref, err := parseAzureKeyReference(p.vaultURL, rawID, true)
	if err != nil {
		return nil, err
	}
	algorithm, ok := p.algorithms.Load(ref.ID)
	if !ok {
		info, err := p.KeyInfo(ctx, ref.ID)
		if err != nil {
			return nil, err
		}
		algorithm = info.Algorithm
	}
	sigAlgorithm, ecBytes, err := azureSignatureAlgorithm(algorithm.(string), opts)
	if err != nil {
		return nil, err
	}
	if hash := opts.HashFunc(); !hash.Available() || len(digest) != hash.Size() {
		return nil, fmt.Errorf("digest length %d does not match %s", len(digest), hash)
	}
	response, err := p.client.Sign(ctx, ref.Name, ref.Version, azkeys.SignParameters{Algorithm: &sigAlgorithm, Value: digest}, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault sign: %w", err)
	}
	if ecBytes == 0 {
		return response.Result, nil
	}
	if len(response.Result) != ecBytes*2 {
		return nil, fmt.Errorf("Azure Key Vault returned an invalid ECDSA signature length %d", len(response.Result))
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(response.Result[:ecBytes]), new(big.Int).SetBytes(response.Result[ecBytes:])})
}

func azureSignatureAlgorithm(algorithm string, opts crypto.SignerOpts) (azkeys.SignatureAlgorithm, int, error) {
	switch algorithm {
	case AlgorithmECDSAP256SHA256:
		if opts.HashFunc() != crypto.SHA256 {
			return "", 0, fmt.Errorf("P-256 requires SHA-256")
		}
		return azkeys.SignatureAlgorithmES256, 32, nil
	case AlgorithmECDSAP384SHA384:
		if opts.HashFunc() != crypto.SHA384 {
			return "", 0, fmt.Errorf("P-384 requires SHA-384")
		}
		return azkeys.SignatureAlgorithmES384, 48, nil
	case AlgorithmRSA3072SHA256, AlgorithmRSA4096SHA256:
		if opts.HashFunc() != crypto.SHA256 {
			return "", 0, fmt.Errorf("RSA signing keys require SHA-256")
		}
		if _, ok := opts.(*rsa.PSSOptions); ok {
			return azkeys.SignatureAlgorithmPS256, 0, nil
		}
		return azkeys.SignatureAlgorithmRS256, 0, nil
	default:
		return "", 0, fmt.Errorf("unsupported Azure signing algorithm %q", algorithm)
	}
}

func (p *AzureKeyVaultProvider) HealthCheck(ctx context.Context) error {
	key, err := p.client.GetKey(ctx, p.protectionKey.Name, p.protectionKey.Version, nil)
	if err != nil {
		return fmt.Errorf("Azure protection key %s: %w", p.protectionKey.ID, err)
	}
	if key.Key == nil || key.Key.Kty == nil {
		return fmt.Errorf("Azure protection key %s returned incomplete metadata", p.protectionKey.ID)
	}
	if *key.Key.Kty != azkeys.KeyTypeRSA && *key.Key.Kty != azkeys.KeyTypeRSAHSM {
		return fmt.Errorf("Azure protection key %s has type %s; it must be RSA or RSA-HSM", p.protectionKey.ID, *key.Key.Kty)
	}
	if len(key.Key.N) == 0 || new(big.Int).SetBytes(key.Key.N).BitLen() < 3072 {
		return fmt.Errorf("Azure protection key %s must be RSA 3072-bit or larger", p.protectionKey.ID)
	}
	if key.Attributes != nil && key.Attributes.Enabled != nil && !*key.Attributes.Enabled {
		return fmt.Errorf("Azure protection key %s is disabled", p.protectionKey.ID)
	}
	if !azureHasOperation(key.Key.KeyOps, azkeys.KeyOperationWrapKey) || !azureHasOperation(key.Key.KeyOps, azkeys.KeyOperationUnwrapKey) {
		return fmt.Errorf("Azure protection key %s must allow wrapKey and unwrapKey", p.protectionKey.ID)
	}
	return nil
}

func azureHasOperation(ops []*azkeys.KeyOperation, want azkeys.KeyOperation) bool {
	for _, op := range ops {
		if op != nil && *op == want {
			return true
		}
	}
	return false
}

type azureProtectionEnvelope struct {
	Version    int    `json:"v"`
	KeyID      string `json:"kid"`
	WrappedKey []byte `json:"wrappedKey"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func (p *AzureKeyVaultProvider) Protect(ctx context.Context, purpose string, plaintext []byte) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
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
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256
	wrapped, err := p.client.WrapKey(ctx, p.protectionKey.Name, p.protectionKey.Version, azkeys.KeyOperationParameters{Algorithm: &algorithm, Value: dek}, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault wrap protection key: %w", err)
	}
	keyID := p.protectionKey.ID
	if wrapped.KID != nil {
		keyID = string(*wrapped.KID)
	}
	ref, err := parseAzureKeyReference(p.vaultURL, keyID, true)
	if err != nil || ref.ID != p.protectionKey.ID || len(wrapped.Result) == 0 {
		return nil, fmt.Errorf("Azure Key Vault returned an invalid protection-key response")
	}
	envelope := azureProtectionEnvelope{Version: 1, KeyID: keyID, WrappedKey: wrapped.Result, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, []byte(purpose))}
	return json.Marshal(envelope)
}

func (p *AzureKeyVaultProvider) Unprotect(ctx context.Context, purpose string, ciphertext []byte) ([]byte, error) {
	var envelope azureProtectionEnvelope
	if err := json.Unmarshal(ciphertext, &envelope); err != nil || envelope.Version != 1 || len(envelope.WrappedKey) == 0 {
		return nil, fmt.Errorf("invalid Azure protection envelope")
	}
	ref, err := parseAzureKeyReference(p.vaultURL, envelope.KeyID, true)
	if err != nil {
		return nil, fmt.Errorf("Azure protection envelope key: %w", err)
	}
	if ref.ID != p.protectionKey.ID {
		return nil, fmt.Errorf("Azure protection envelope was sealed by a different configured key")
	}
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256
	unwrapped, err := p.client.UnwrapKey(ctx, ref.Name, ref.Version, azkeys.KeyOperationParameters{Algorithm: &algorithm, Value: envelope.WrappedKey}, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault unwrap protection key: %w", err)
	}
	defer clear(unwrapped.Result)
	block, err := aes.NewCipher(unwrapped.Result)
	if err != nil {
		return nil, fmt.Errorf("invalid Azure protection key material: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(envelope.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid Azure protection envelope nonce")
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, []byte(purpose))
	if err != nil {
		return nil, fmt.Errorf("open Azure protection envelope: %w", err)
	}
	return plaintext, nil
}

func (p *AzureKeyVaultProvider) Attestation(ctx context.Context, rawID string) (KeyAttestation, error) {
	info, err := p.KeyInfo(ctx, rawID)
	if err != nil {
		return KeyAttestation{}, err
	}
	if info.ProtectionLevel == "SOFTWARE" {
		return exampleKeyAttestation(rawID, ProtectionSoftware), nil
	}
	ref, _ := parseAzureKeyReference(p.vaultURL, rawID, true)
	response, err := p.client.GetKeyAttestation(ctx, ref.Name, ref.Version, nil)
	if err != nil {
		return KeyAttestation{}, fmt.Errorf("get Azure Key Vault attestation: %w", err)
	}
	if response.Attributes == nil || response.Attributes.Attestation == nil {
		return KeyAttestation{}, fmt.Errorf("Azure Key Vault returned no attestation for HSM key %s", rawID)
	}
	a := response.Attributes.Attestation
	artifacts := map[string][]byte{}
	if len(a.PrivateKeyAttestation) > 0 {
		artifacts["private-key-attestation.dat"] = append([]byte(nil), a.PrivateKeyAttestation...)
	}
	if len(a.CertificatePEMFile) > 0 {
		artifacts["attestation-certificates.pem"] = append([]byte(nil), a.CertificatePEMFile...)
	}
	return KeyAttestation{Format: "AZURE_KEY_VAULT", Content: append([]byte(nil), a.PublicKeyAttestation...), Artifacts: artifacts}, nil
}

var errAzureCAImportUnsupported = fmt.Errorf("Azure Key Vault CA import is not supported by this release; create the CA in SimpleSCEP or use Google Cloud KMS for wrapped-key import")

func (p *AzureKeyVaultProvider) CreateImportJob(context.Context, CreateImportJobRequest) (ImportJobInfo, error) {
	return ImportJobInfo{}, errAzureCAImportUnsupported
}
func (p *AzureKeyVaultProvider) ImportJob(context.Context, string) (ImportJobInfo, error) {
	return ImportJobInfo{}, errAzureCAImportUnsupported
}
func (p *AzureKeyVaultProvider) CreateImportTarget(context.Context, CreateKeyRequest) (string, error) {
	return "", errAzureCAImportUnsupported
}
func (p *AzureKeyVaultProvider) ImportWrappedKey(context.Context, ImportKeyRequest) (string, error) {
	return "", errAzureCAImportUnsupported
}
func (p *AzureKeyVaultProvider) ImportedKeyState(context.Context, string) (string, string, error) {
	return "", "", errAzureCAImportUnsupported
}

func (p *AzureKeyVaultProvider) DestroyKeyVersion(ctx context.Context, rawID string) error {
	ref, err := parseAzureKeyReference(p.vaultURL, rawID, true)
	if err != nil {
		return err
	}
	if _, err := p.client.DeleteKey(ctx, ref.Name, nil); err != nil {
		return fmt.Errorf("delete Azure Key Vault key: %w", err)
	}
	p.algorithms.Delete(ref.ID)
	return nil
}
