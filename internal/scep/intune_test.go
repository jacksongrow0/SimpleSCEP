package scep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

// fakeIntune stands in for Entra ID, Microsoft Graph, and the Intune services.
// The client's absolute endpoints are redirected here by rewriting the request
// URL in a custom RoundTripper, so the production URLs stay under test.
type fakeIntune struct {
	server *httptest.Server

	tokenCalls, discoveryCalls int
	lastPath                   string
	lastBody                   map[string]any
	lastHeaders                http.Header

	scepCode   string
	uploadBody string
	failTokens bool
	omitSCEP   bool
}

func newFakeIntune(t *testing.T) *fakeIntune {
	t.Helper()
	f := &fakeIntune{scepCode: "Success", uploadBody: `{"value":"true"}`}
	mux := http.NewServeMux()
	mux.HandleFunc("/{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls++
		if f.failTokens {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret."}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token-abc", "expires_in": 3600})
	})
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, r *http.Request) {
		f.discoveryCalls++
		endpoints := []map[string]string{
			{"providerName": "PkiConnectorFEService", "uri": f.server.URL + "/pki"},
		}
		if !f.omitSCEP {
			endpoints = append(endpoints,
				map[string]string{"providerName": "ScepRequestValidationFEService", "uri": f.server.URL + "/scepsvc"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": endpoints})
	})
	mux.HandleFunc("/scepsvc/ScepActions/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": f.scepCode, "errorDescription": "challenge could not be decrypted"})
	})
	mux.HandleFunc("/pki/CertificateAuthorityRequests/downloadRevocationRequests", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{
			{"requestContext": "ctx-1", "serialNumber": "0a0b", "issuerName": "CN=Test", "caConfiguration": "ca-1"},
		}})
	})
	mux.HandleFunc("/pki/CertificateAuthorityRequests/uploadRevocationResults", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_, _ = w.Write([]byte(f.uploadBody))
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIntune) record(r *http.Request) {
	f.lastPath = r.URL.Path
	f.lastHeaders = r.Header.Clone()
	f.lastBody = map[string]any{}
	_ = json.NewDecoder(r.Body).Decode(&f.lastBody)
}

// client returns an IntuneClient whose traffic is redirected to the fake.
func (f *fakeIntune) client() *IntuneClient {
	base := strings.TrimPrefix(f.server.URL, "http://")
	return NewIntuneClient(&http.Client{Timeout: 5 * time.Second, Transport: rewriteHost(base)})
}

type rewriteTransport struct{ host string }

func rewriteHost(host string) http.RoundTripper { return rewriteTransport{host: host} }

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Only absolute Microsoft hosts are rewritten; the fake's own URLs (returned
	// by discovery) already point at the test server.
	if r.URL.Host != t.host {
		r.URL.Scheme, r.URL.Host = "http", t.host
	}
	return http.DefaultTransport.RoundTrip(r)
}

var testIntegration = Integration{Provider: AuthIntune, TenantID: "tenant-1", ApplicationID: "app-1", Secret: "s3cret"}

func TestIntuneValidateSendsReferenceShape(t *testing.T) {
	f := newFakeIntune(t)
	if err := f.client().Validate(context.Background(), testIntegration, "tx-1", []byte("csr-bytes")); err != nil {
		t.Fatal(err)
	}
	if f.lastPath != "/scepsvc/ScepActions/validateRequest" {
		t.Fatalf("unexpected path %q", f.lastPath)
	}
	if got := f.lastHeaders.Get("api-version"); got != scepServiceVersion {
		t.Fatalf("api-version = %q, want %q", got, scepServiceVersion)
	}
	if f.lastHeaders.Get("client-request-id") == "" {
		t.Fatal("client-request-id header is required for Intune support correlation")
	}
	request, ok := f.lastBody["request"].(map[string]any)
	if !ok {
		t.Fatalf("body is not wrapped in a request object: %v", f.lastBody)
	}
	if request["transactionId"] != "tx-1" {
		t.Fatalf("transactionId = %v", request["transactionId"])
	}
	// The CSR must be standard base64 of the raw DER.
	if request["certificateRequest"] != "Y3NyLWJ5dGVz" {
		t.Fatalf("certificateRequest = %v", request["certificateRequest"])
	}
	if request["callerInfo"] != intuneCallerInfo {
		t.Fatalf("callerInfo = %v", request["callerInfo"])
	}
}

// A non-Success code means the challenge is bad and no certificate may be issued.
func TestIntuneValidateRejectsNonSuccessCode(t *testing.T) {
	f := newFakeIntune(t)
	f.scepCode = "ChallengeDecryptionError"
	err := f.client().Validate(context.Background(), testIntegration, "tx-1", []byte("csr"))
	if err == nil {
		t.Fatal("a non-Success code must fail closed")
	}
	var svc ServiceError
	if !errorAs(err, &svc) {
		t.Fatalf("want ServiceError, got %T", err)
	}
	if svc.Code != "ChallengeDecryptionError" || svc.TransactionID != "tx-1" {
		t.Fatalf("unexpected ServiceError %+v", svc)
	}
	if !strings.Contains(err.Error(), "ChallengeDecryptionError") {
		t.Fatalf("error should name the code: %v", err)
	}
}

func TestIntuneCachesTokensAndDiscovery(t *testing.T) {
	f := newFakeIntune(t)
	c := f.client()
	for range 3 {
		if err := c.Validate(context.Background(), testIntegration, "tx", []byte("csr")); err != nil {
			t.Fatal(err)
		}
	}
	// One Graph token plus one Intune token, fetched once and reused.
	if f.tokenCalls != 2 {
		t.Fatalf("token requests = %d, want 2 (graph + intune, then cached)", f.tokenCalls)
	}
	if f.discoveryCalls != 1 {
		t.Fatalf("discovery requests = %d, want 1", f.discoveryCalls)
	}
}

func TestIntuneSurfacesCredentialErrors(t *testing.T) {
	f := newFakeIntune(t)
	f.failTokens = true
	err := f.client().Validate(context.Background(), testIntegration, "tx-1", []byte("csr"))
	if err == nil {
		t.Fatal("bad credentials must fail")
	}
	// The AADSTS code names the real misconfiguration, so it must reach the admin.
	if !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Fatalf("error should carry the AADSTS code: %v", err)
	}
}

func TestIntuneReportsMissingServiceEndpoint(t *testing.T) {
	f := newFakeIntune(t)
	f.omitSCEP = true
	err := f.client().Validate(context.Background(), testIntegration, "tx-1", []byte("csr"))
	if err == nil || !strings.Contains(err.Error(), "admin consent") {
		t.Fatalf("a missing endpoint should point at the app registration, got %v", err)
	}
}

func TestIntuneNotifySuccessSendsThumbprint(t *testing.T) {
	f := newFakeIntune(t)
	cert := appPKI.Certificate{CertificatePEM: testLeafPEM(t), Serial: "0a0b", CAID: "ca-1", CAName: "Test Issuing",
		ExpiresAt: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)}
	if err := f.client().NotifySuccess(context.Background(), testIntegration, "tx-1", []byte("csr"), cert); err != nil {
		t.Fatal(err)
	}
	if f.lastPath != "/scepsvc/ScepActions/successNotification" {
		t.Fatalf("unexpected path %q", f.lastPath)
	}
	notification := f.lastBody["notification"].(map[string]any)
	thumbprint, _ := notification["certificateThumbprint"].(string)
	// Intune expects an uppercase hex SHA-1 of the DER.
	if len(thumbprint) != 40 || thumbprint != strings.ToUpper(thumbprint) {
		t.Fatalf("thumbprint %q is not an uppercase SHA-1 hex string", thumbprint)
	}
	if notification["certificateSerialNumber"] != "0a0b" {
		t.Fatalf("serial = %v", notification["certificateSerialNumber"])
	}
}

func TestIntuneNotifyFailureTruncatesDescription(t *testing.T) {
	f := newFakeIntune(t)
	long := strings.Repeat("x", 400)
	if err := f.client().NotifyFailure(context.Background(), testIntegration, "tx-1", []byte("csr"), long); err != nil {
		t.Fatal(err)
	}
	notification := f.lastBody["notification"].(map[string]any)
	// Microsoft documents a 255-character maximum.
	if got := notification["errorDescription"].(string); len(got) != 255 {
		t.Fatalf("errorDescription length = %d, want 255", len(got))
	}
}

func TestIntuneRevocationRoundTrip(t *testing.T) {
	f := newFakeIntune(t)
	c := f.client()
	requests, err := c.DownloadRevocations(context.Background(), testIntegration, "tx-1", "CN=Test", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || requests[0].RequestContext != "ctx-1" || requests[0].SerialNumber != "0a0b" {
		t.Fatalf("unexpected requests %+v", requests)
	}
	params := f.lastBody["downloadParameters"].(map[string]any)
	if params["maxRequests"].(float64) != 100 || params["issuerName"] != "CN=Test" {
		t.Fatalf("unexpected download parameters %v", params)
	}

	err = c.UploadRevocations(context.Background(), testIntegration, "tx-1", []IntuneRevocationResult{
		{RequestContext: "ctx-1", Succeeded: false, ErrorCode: RevokeErrorCertificateNotFound, ErrorMessage: "missing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	results := f.lastBody["results"].([]any)
	first := results[0].(map[string]any)
	// The reference serializes the enum by name; sending 4004 would be rejected.
	if first["errorCode"] != "CertificateNotFoundError" {
		t.Fatalf("errorCode = %v, want the enum name", first["errorCode"])
	}
	if first["succeeded"] != false {
		t.Fatalf("succeeded = %v", first["succeeded"])
	}
}

// A success result carries no error fields, matching the reference's own guard.
func TestIntuneRevocationSuccessOmitsErrorFields(t *testing.T) {
	f := newFakeIntune(t)
	err := f.client().UploadRevocations(context.Background(), testIntegration, "tx-1",
		[]IntuneRevocationResult{{RequestContext: "ctx-1", Succeeded: true}})
	if err != nil {
		t.Fatal(err)
	}
	first := f.lastBody["results"].([]any)[0].(map[string]any)
	if _, ok := first["errorCode"]; ok {
		t.Fatalf("a successful result must not carry an errorCode: %v", first)
	}
}

func TestIntuneUploadRejectsUnrecordedResults(t *testing.T) {
	f := newFakeIntune(t)
	f.uploadBody = `{"value":"false"}`
	err := f.client().UploadRevocations(context.Background(), testIntegration, "tx-1",
		[]IntuneRevocationResult{{RequestContext: "ctx-1", Succeeded: true}})
	if err == nil {
		t.Fatal("a false result value must be treated as a failure")
	}
}

// errorAs is a local errors.As to keep the import list of this file minimal.
func errorAs(err error, target *ServiceError) bool {
	svc, ok := err.(ServiceError)
	if ok {
		*target = svc
	}
	return ok
}

// testLeafPEM mints a throwaway self-signed leaf, only used to exercise
// thumbprint computation.
func testLeafPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2571), Subject: pkix.Name{CommonName: "device-1"},
		Issuer: pkix.Name{CommonName: "Test Issuing"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
