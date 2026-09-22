package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	azkeysfake "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys/fake"
)

const (
	testAzureVault         = "https://simple-test.vault.azure.net"
	testAzureProtectionKey = testAzureVault + "/keys/protection/version-1"
)

func azureTestProvider(t *testing.T, server azkeysfake.Server) *AzureKeyVaultProvider {
	t.Helper()
	client, err := azkeys.NewClient(testAzureVault, &azfake.TokenCredential{}, &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: azkeysfake.NewServerTransport(&server)},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newAzureKeyVaultProvider(client, testAzureVault, testAzureProtectionKey)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestAzureSigningKeyParametersSelectProtectionAndAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		algorithm string
		hsm       bool
		keyType   azkeys.KeyType
		curve     azkeys.CurveName
		size      int32
	}{
		{AlgorithmECDSAP256SHA256, false, azkeys.KeyTypeEC, azkeys.CurveNameP256, 0},
		{AlgorithmECDSAP384SHA384, true, azkeys.KeyTypeECHSM, azkeys.CurveNameP384, 0},
		{AlgorithmRSA3072SHA256, false, azkeys.KeyTypeRSA, "", 3072},
		{AlgorithmRSA4096SHA256, true, azkeys.KeyTypeRSAHSM, "", 4096},
	} {
		params, err := azureSigningKeyParameters(tc.algorithm, tc.hsm)
		if err != nil {
			t.Fatalf("%s: %v", tc.algorithm, err)
		}
		if params.Kty == nil || *params.Kty != tc.keyType {
			t.Errorf("%s: key type = %v, want %v", tc.algorithm, params.Kty, tc.keyType)
		}
		if tc.curve != "" && (params.Curve == nil || *params.Curve != tc.curve) {
			t.Errorf("%s: curve = %v, want %v", tc.algorithm, params.Curve, tc.curve)
		}
		if tc.size != 0 && (params.KeySize == nil || *params.KeySize != tc.size) {
			t.Errorf("%s: size = %v, want %d", tc.algorithm, params.KeySize, tc.size)
		}
		if params.KeyAttributes == nil || params.KeyAttributes.Exportable == nil || *params.KeyAttributes.Exportable {
			t.Errorf("%s: key was not explicitly non-exportable", tc.algorithm)
		}
	}
}

func TestAzureCreatesAndValidatesAnHSMCAPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := azkeysfake.Server{CreateKey: func(_ context.Context, name string, parameters azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (resp azfake.Responder[azkeys.CreateKeyResponse], errResp azfake.ErrorResponder) {
		if parameters.Kty == nil || *parameters.Kty != azkeys.KeyTypeECHSM {
			t.Errorf("key type = %v, want EC-HSM", parameters.Kty)
		}
		if parameters.Tags["org"] == nil || *parameters.Tags["org"] != "11111111-1111-1111-1111-111111111111" {
			t.Errorf("organization tag = %v", parameters.Tags["org"])
		}
		keyType, curve := azkeys.KeyTypeECHSM, azkeys.CurveNameP256
		keyID := azkeys.ID(testAzureVault + "/keys/" + name + "/version-3")
		resp.SetResponse(http.StatusOK, azkeys.CreateKeyResponse{KeyBundle: azkeys.KeyBundle{
			Key:        &azkeys.JSONWebKey{KID: &keyID, Kty: &keyType, Crv: &curve, X: privateKey.X.Bytes(), Y: privateKey.Y.Bytes()},
			Attributes: &azkeys.KeyAttributes{Enabled: to.Ptr(true)},
		}}, nil)
		return
	}}
	provider := azureTestProvider(t, server)
	info, err := provider.CreateSigningKey(context.Background(), CreateKeyRequest{
		OrgID: "11111111-1111-1111-1111-111111111111", CAName: "Root", CAType: CATypeRoot, Algorithm: AlgorithmECDSAP256SHA256, Protection: ProtectionHSM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.ProtectionLevel != "HSM" || info.Algorithm != AlgorithmECDSAP256SHA256 {
		t.Fatalf("key info = %#v", info)
	}
}

func TestAzureHealthCheckValidatesProtectionKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	server := azkeysfake.Server{GetKey: func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (resp azfake.Responder[azkeys.GetKeyResponse], errResp azfake.ErrorResponder) {
		keyType := azkeys.KeyTypeRSAHSM
		wrap, unwrap := azkeys.KeyOperationWrapKey, azkeys.KeyOperationUnwrapKey
		keyID := azkeys.ID(testAzureProtectionKey)
		resp.SetResponse(http.StatusOK, azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{
			Key:        &azkeys.JSONWebKey{KID: &keyID, Kty: &keyType, N: privateKey.N.Bytes(), E: big.NewInt(int64(privateKey.E)).Bytes(), KeyOps: []*azkeys.KeyOperation{&wrap, &unwrap}},
			Attributes: &azkeys.KeyAttributes{Enabled: to.Ptr(true)},
		}}, nil)
		return
	}}
	provider := azureTestProvider(t, server)
	if err := provider.HealthCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAzureProtectRoundTripBindsPurpose(t *testing.T) {
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	server := azkeysfake.Server{
		WrapKey: func(_ context.Context, name, version string, parameters azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (resp azfake.Responder[azkeys.WrapKeyResponse], errResp azfake.ErrorResponder) {
			// The SDK's generated fake transport greedily parses the version as part
			// of the name. The real request path still has separate name/version
			// segments; accept the fake's representation here.
			if name != "protection/version-1" || version != "" || parameters.Algorithm == nil || *parameters.Algorithm != azkeys.EncryptionAlgorithmRSAOAEP256 {
				gotAlgorithm := azkeys.EncryptionAlgorithm("")
				if parameters.Algorithm != nil {
					gotAlgorithm = *parameters.Algorithm
				}
				t.Errorf("unexpected wrap request: name=%q version=%q algorithm=%q", name, version, gotAlgorithm)
			}
			wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &wrappingKey.PublicKey, parameters.Value, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.SetResponse(http.StatusOK, azkeys.WrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{KID: to.Ptr(azkeys.ID(testAzureProtectionKey)), Result: wrapped}}, nil)
			return
		},
		UnwrapKey: func(_ context.Context, _, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (resp azfake.Responder[azkeys.UnwrapKeyResponse], errResp azfake.ErrorResponder) {
			unwrapped, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrappingKey, parameters.Value, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.SetResponse(http.StatusOK, azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: unwrapped}}, nil)
			return
		},
	}
	provider := azureTestProvider(t, server)
	ciphertext, err := provider.Protect(context.Background(), "totp:user-1", []byte("secret material larger than an RSA payload is allowed"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := provider.Unprotect(context.Background(), "totp:user-1", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "secret material larger than an RSA payload is allowed" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if _, err := provider.Unprotect(context.Background(), "acme:eab", ciphertext); err == nil {
		t.Fatal("ciphertext opened under a different purpose")
	}
}

func TestAzureECDSASignatureIsConvertedForCryptoSigner(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := testAzureVault + "/keys/ca/version-2"
	server := azkeysfake.Server{Sign: func(_ context.Context, name, version string, parameters azkeys.SignParameters, _ *azkeys.SignOptions) (resp azfake.Responder[azkeys.SignResponse], errResp azfake.ErrorResponder) {
		if name != "ca/version-2" || version != "" || parameters.Algorithm == nil || *parameters.Algorithm != azkeys.SignatureAlgorithmES256 {
			gotAlgorithm := azkeys.SignatureAlgorithm("")
			if parameters.Algorithm != nil {
				gotAlgorithm = *parameters.Algorithm
			}
			t.Errorf("unexpected sign request: name=%q version=%q algorithm=%q", name, version, gotAlgorithm)
		}
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, parameters.Value)
		if err != nil {
			t.Fatal(err)
		}
		raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		resp.SetResponse(http.StatusOK, azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: raw}}, nil)
		return
	}}
	provider := azureTestProvider(t, server)
	provider.algorithms.Store(keyID, AlgorithmECDSAP256SHA256)
	digest := sha256.Sum256([]byte("certificate to sign"))
	signature, err := provider.Sign(context.Background(), keyID, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&privateKey.PublicKey, digest[:], signature) {
		t.Fatal("converted Azure ECDSA signature did not verify")
	}
}

func TestAzurePublicKeyMapsHSMKeyMetadata(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	e := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
	keyType := azkeys.KeyTypeRSAHSM
	publicKey, algorithm, protection, err := azurePublicKey(&azkeys.JSONWebKey{Kty: &keyType, N: privateKey.PublicKey.N.Bytes(), E: e})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := publicKey.(*rsa.PublicKey); !ok || algorithm != AlgorithmRSA3072SHA256 || protection != "HSM" {
		t.Fatalf("mapped key = %T, %q, %q", publicKey, algorithm, protection)
	}
}

func TestAzureProtectionKeyMustBeVersionedAndInTheConfiguredVault(t *testing.T) {
	for _, raw := range []string{
		testAzureVault + "/keys/protection",
		"https://other.vault.azure.net/keys/protection/version-1",
		"protection",
	} {
		if _, err := parseAzureKeyReference(testAzureVault, raw, true); err == nil {
			t.Errorf("accepted invalid protection key reference %q", raw)
		}
	}
}
