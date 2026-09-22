package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

func testCtx() context.Context { return context.Background() }

func endpointOf(t *testing.T, repo *fakeStore) Endpoint {
	t.Helper()
	e, err := repo.Endpoint(testCtx(), testEndpoint)
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	return e
}

// mintCredential creates a credential through the service, so the MAC key comes
// back the way an administrator would receive it.
func mintCredential(t *testing.T, svc Service, repo *fakeStore, spec CredentialSpec) (EABCredential, []byte) {
	t.Helper()
	c, encoded, err := svc.CreateCredential(testCtx(), endpointOf(t, repo), spec)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode mac key: %v", err)
	}
	return c, key
}

// registerAccount runs a full newAccount through Authenticate, which is how the
// handler reaches it, so the nonce and signature paths are exercised too.
func registerAccount(t *testing.T, svc Service, repo *fakeStore, key testKey,
	credential EABCredential, macKey []byte) (Account, error) {
	t.Helper()
	e := endpointOf(t, repo)
	url := testURL + "/acme/" + testEndpoint + "/new-account"

	nonce, err := svc.NewNonce(testCtx(), e)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	eab := signHMAC(t, macKey, map[string]any{"alg": "HS256", "kid": credential.KID, "url": url}, key.jwk)
	payload, err := json.Marshal(map[string]any{
		"contact": []string{"mailto:ops@example.test"}, "termsOfServiceAgreed": true,
		"externalAccountBinding": json.RawMessage(eab),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := signJWS(t, key, map[string]any{
		"alg": "ES256", "nonce": nonce, "url": url, "jwk": json.RawMessage(key.jwk),
	}, string(payload))

	req, err := svc.Authenticate(testCtx(), e, body, url, false)
	if err != nil {
		return Account{}, err
	}
	account, _, err := svc.NewAccount(testCtx(), e, req, url)
	return account, err
}

// TestRegistrationRequiresExternalAccountBinding is the authorization model in
// one test: without a credential there is no way in at all.
func TestRegistrationRequiresExternalAccountBinding(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := endpointOf(t, repo)
	key := newTestKey(t)
	url := testURL + "/acme/" + testEndpoint + "/new-account"

	nonce, err := svc.NewNonce(testCtx(), e)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	body := signJWS(t, key, map[string]any{
		"alg": "ES256", "nonce": nonce, "url": url, "jwk": json.RawMessage(key.jwk),
	}, `{"termsOfServiceAgreed":true}`)

	req, err := svc.Authenticate(testCtx(), e, body, url, false)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	_, _, err = svc.NewAccount(testCtx(), e, req, url)
	if got := problemType(t, err); got != ProblemExternalAccountRequired {
		t.Errorf("got %s, want externalAccountRequired", got)
	}
	if len(repo.accounts) != 0 {
		t.Errorf("an account was created without a binding")
	}
}

// TestTamperedBindingDoesNotSpendCredential is why the credential is spent after
// verification rather than before: a wrong guess must leave a single-use
// credential still usable by whoever legitimately holds it.
func TestTamperedBindingDoesNotSpendCredential(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	credential, macKey := mintCredential(t, svc, repo, CredentialSpec{SingleUse: true})

	wrongKey := append([]byte(nil), macKey...)
	wrongKey[0] ^= 0xff

	_, err := registerAccount(t, svc, repo, newTestKey(t), credential, wrongKey)
	if got := problemType(t, err); got != ProblemUnauthorized {
		t.Errorf("got %s, want unauthorized", got)
	}
	if len(repo.usedCredentialIDs) != 0 {
		t.Errorf("a rejected binding spent the credential: %v", repo.usedCredentialIDs)
	}
	if len(repo.accounts) != 0 {
		t.Errorf("an account was created from a tampered binding")
	}

	// The credential still works for the client that actually holds the key.
	if _, err := registerAccount(t, svc, repo, newTestKey(t), credential, macKey); err != nil {
		t.Fatalf("legitimate registration after a rejected one: %v", err)
	}
}

// TestBindingIsBoundToItsAccountKey covers the replay this check exists for: a
// binding captured from one registration must not register a different key.
func TestBindingIsBoundToItsAccountKey(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	credential, macKey := mintCredential(t, svc, repo, CredentialSpec{})
	e := endpointOf(t, repo)
	url := testURL + "/acme/" + testEndpoint + "/new-account"

	victim, attacker := newTestKey(t), newTestKey(t)
	// A binding signed over the victim's key, presented in a request signed by
	// the attacker's.
	eab := signHMAC(t, macKey, map[string]any{"alg": "HS256", "kid": credential.KID, "url": url}, victim.jwk)
	payload, _ := json.Marshal(map[string]any{"externalAccountBinding": json.RawMessage(eab)})

	nonce, err := svc.NewNonce(testCtx(), e)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	body := signJWS(t, attacker, map[string]any{
		"alg": "ES256", "nonce": nonce, "url": url, "jwk": json.RawMessage(attacker.jwk),
	}, string(payload))

	req, err := svc.Authenticate(testCtx(), e, body, url, false)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	_, _, err = svc.NewAccount(testCtx(), e, req, url)
	if got := problemType(t, err); got != ProblemUnauthorized {
		t.Errorf("got %s, want unauthorized", got)
	}
}

func TestSingleUseCredentialBindsOnce(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	credential, macKey := mintCredential(t, svc, repo, CredentialSpec{SingleUse: true})

	if _, err := registerAccount(t, svc, repo, newTestKey(t), credential, macKey); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	_, err := registerAccount(t, svc, repo, newTestKey(t), credential, macKey)
	if got := problemType(t, err); got != ProblemUnauthorized {
		t.Errorf("second registration: got %s, want unauthorized", got)
	}
}

// TestNonceIsSpentExactlyOnce is the replay check. A second request presenting
// the same nonce must fail even though everything else about it is valid.
func TestNonceIsSpentExactlyOnce(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := endpointOf(t, repo)
	key := newTestKey(t)
	url := testURL + "/acme/" + testEndpoint + "/new-account"

	nonce, err := svc.NewNonce(testCtx(), e)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	body := signJWS(t, key, map[string]any{
		"alg": "ES256", "nonce": nonce, "url": url, "jwk": json.RawMessage(key.jwk),
	}, `{}`)

	if _, err := svc.Authenticate(testCtx(), e, body, url, false); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err = svc.Authenticate(testCtx(), e, body, url, false)
	if got := problemType(t, err); got != ProblemBadNonce {
		t.Errorf("replay: got %s, want badNonce", got)
	}
	if len(repo.consumedNonces) != 1 {
		t.Errorf("nonce consumed %d times, want 1", len(repo.consumedNonces))
	}
}

// ---------------------------------------------------------------------------
// Orders and finalize
// ---------------------------------------------------------------------------

func testAccount(t *testing.T, svc Service, repo *fakeStore, pin ...string) Account {
	t.Helper()
	credential, macKey := mintCredential(t, svc, repo, CredentialSpec{Identifiers: pin})
	account, err := registerAccount(t, svc, repo, newTestKey(t), credential, macKey)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return account
}

func newOrder(t *testing.T, svc Service, repo *fakeStore, account Account, names ...string) (Order, error) {
	t.Helper()
	identifiers := make([]Identifier, 0, len(names))
	for _, n := range names {
		kind := IdentifierDNS
		if net.ParseIP(n) != nil {
			kind = IdentifierIP
		}
		identifiers = append(identifiers, Identifier{Type: kind, Value: n})
	}
	payload, err := json.Marshal(map[string]any{"identifiers": identifiers})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	order, _, err := svc.NewOrder(testCtx(), endpointOf(t, repo), account, payload)
	return order, err
}

// makeCSR builds a CSR asking for exactly the given names, which is what
// finalize compares against the order.
func makeCSR(t *testing.T, commonName string, names ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, n)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func finalizePayload(t *testing.T, csr string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"csr": csr})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return payload
}

// TestFinalizeRejectsCSRSupersetOfOrder is the most important test in the
// package. pki.Service.Issue reads names out of the CSR DER verbatim, so a CSR
// covering more than the order authorized would otherwise be signed as-is.
func TestFinalizeRejectsCSRSupersetOfOrder(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	account := testAccount(t, svc, repo)

	order, err := newOrder(t, svc, repo, account, "a.internal")
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	csr := makeCSR(t, "a.internal", "a.internal", "b.internal")

	_, err = svc.Finalize(testCtx(), endpointOf(t, repo), account, order.ID, finalizePayload(t, csr))
	if got := problemType(t, err); got != ProblemUnauthorized {
		t.Errorf("got %s, want unauthorized", got)
	}
	if issuer.issued != 0 {
		t.Errorf("a rejected CSR reached the issuer %d times", issuer.issued)
	}
}

func TestFinalizeRejectsCSRSubsetOfOrder(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	account := testAccount(t, svc, repo)

	order, err := newOrder(t, svc, repo, account, "a.internal", "b.internal")
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	csr := makeCSR(t, "a.internal", "a.internal")

	_, err = svc.Finalize(testCtx(), endpointOf(t, repo), account, order.ID, finalizePayload(t, csr))
	if got := problemType(t, err); got != ProblemBadCSR {
		t.Errorf("got %s, want badCSR", got)
	}
	if issuer.issued != 0 {
		t.Errorf("a rejected CSR reached the issuer")
	}
}

func TestFinalizeRejectsCommonNameOutsideOrder(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	account := testAccount(t, svc, repo)

	order, err := newOrder(t, svc, repo, account, "a.internal")
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	// The SAN set matches; only the subject names something else. Without the
	// common-name check this would be signed with an unauthorized subject.
	csr := makeCSR(t, "evil.internal", "a.internal")

	_, err = svc.Finalize(testCtx(), endpointOf(t, repo), account, order.ID, finalizePayload(t, csr))
	if got := problemType(t, err); got != ProblemUnauthorized {
		t.Errorf("got %s, want unauthorized", got)
	}
	if issuer.issued != 0 {
		t.Errorf("a rejected CSR reached the issuer")
	}
}

func TestFinalizeIssuesMatchingCSR(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	account := testAccount(t, svc, repo)

	order, err := newOrder(t, svc, repo, account, "a.internal", "10.0.0.5")
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	csr := makeCSR(t, "a.internal", "a.internal", "10.0.0.5")

	done, err := svc.Finalize(testCtx(), endpointOf(t, repo), account, order.ID, finalizePayload(t, csr))
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if done.Status != StatusValid || done.CertificateID == "" {
		t.Errorf("order not completed: %+v", done)
	}
	if issuer.issued != 1 {
		t.Errorf("issued %d times, want 1", issuer.issued)
	}
	if issuer.lastReq.Profile != appPKI.CertProfileACME || issuer.lastReq.Purpose != "acme" {
		t.Errorf("wrong profile/purpose: %q/%q", issuer.lastReq.Profile, issuer.lastReq.Purpose)
	}
	if issuer.lastReq.Days != DefaultValidityDays {
		t.Errorf("validity %d, want %d", issuer.lastReq.Days, DefaultValidityDays)
	}
}

// TestFinalizeIsIdempotent covers the retry a client makes after a dropped
// connection: it must get the certificate it already received rather than a
// second issuance.
func TestFinalizeIsIdempotent(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	account := testAccount(t, svc, repo)

	order, err := newOrder(t, svc, repo, account, "a.internal")
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	payload := finalizePayload(t, makeCSR(t, "a.internal", "a.internal"))

	first, err := svc.Finalize(testCtx(), endpointOf(t, repo), account, order.ID, payload)
	if err != nil {
		t.Fatalf("first finalize: %v", err)
	}
	second, err := svc.Finalize(testCtx(), endpointOf(t, repo), account, order.ID, payload)
	if err != nil {
		t.Fatalf("second finalize: %v", err)
	}
	if first.CertificateID != second.CertificateID {
		t.Errorf("second finalize produced a different certificate: %s vs %s",
			first.CertificateID, second.CertificateID)
	}
	if issuer.issued != 1 {
		t.Errorf("issued %d times, want 1", issuer.issued)
	}
}

// TestFinalizeRefusesAnotherAccountsOrder confirms an order is scoped to the
// account that placed it, not merely to the endpoint.
func TestFinalizeRefusesAnotherAccountsOrder(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	owner := testAccount(t, svc, repo)
	intruder := testAccount(t, svc, repo)

	order, err := newOrder(t, svc, repo, owner, "a.internal")
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	payload := finalizePayload(t, makeCSR(t, "a.internal", "a.internal"))

	_, err = svc.Finalize(testCtx(), endpointOf(t, repo), intruder, order.ID, payload)
	if err == nil {
		t.Fatal("another account finalized the order")
	}
	if issuer.issued != 0 {
		t.Errorf("a refused finalize reached the issuer")
	}
}

// ---------------------------------------------------------------------------
// Identifier policy
// ---------------------------------------------------------------------------

func TestCredentialIdentifierPinIsEnforced(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	account := testAccount(t, svc, repo, "pinned.internal")

	if _, err := newOrder(t, svc, repo, account, "pinned.internal"); err != nil {
		t.Fatalf("pinned name refused: %v", err)
	}
	_, err := newOrder(t, svc, repo, account, "other.internal")
	if got := problemType(t, err); got != ProblemRejectedIdentifier {
		t.Errorf("got %s, want rejectedIdentifier", got)
	}
}

func TestSANPolicyIsEnforcedAtOrderTime(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	e := endpointOf(t, repo)
	e.SANPattern = `\.internal$`
	repo.endpoints[testEndpoint] = e
	account := testAccount(t, svc, repo)

	if _, err := newOrder(t, svc, repo, account, "ok.internal"); err != nil {
		t.Fatalf("permitted name refused: %v", err)
	}
	_, err := newOrder(t, svc, repo, account, "nope.example.com")
	if got := problemType(t, err); got != ProblemRejectedIdentifier {
		t.Errorf("got %s, want rejectedIdentifier", got)
	}
}

// TestNewOrderRefusesEveryIdentifierWhenNoSANPatternIsSet pins the closed
// default at the point it bites hardest. An ACME order is a list of identifiers
// that become the certificate's SANs, so an endpoint with no SAN rule issues
// nothing at all — and that has to be a clear rejectedIdentifier the client can
// read, not a server error or a silently empty order.
func TestNewOrderRefusesEveryIdentifierWhenNoSANPatternIsSet(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	e := endpointOf(t, repo)
	e.SANPattern = ""
	repo.endpoints[testEndpoint] = e
	account := testAccount(t, svc, repo)

	_, err := newOrder(t, svc, repo, account, "anything.internal")
	if got := problemType(t, err); got != ProblemRejectedIdentifier {
		t.Errorf("got %s, want rejectedIdentifier", got)
	}
	if issuer.issued != 0 {
		t.Errorf("an endpoint with no SAN policy reached the issuer %d times", issuer.issued)
	}
}

// TestWildcardIdentifiersAreRefused: a wildcard can only be proven by dns-01,
// which this server does not run, so issuing one would be issuing on no evidence.
func TestWildcardIdentifiersAreRefused(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	account := testAccount(t, svc, repo)

	_, err := newOrder(t, svc, repo, account, "*.internal")
	if got := problemType(t, err); got != ProblemRejectedIdentifier {
		t.Errorf("got %s, want rejectedIdentifier", got)
	}
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// TestRevocationReasonMapping pins every mapped code to the reason the product
// records. A code that changed meaning silently would revoke certificates for
// the wrong stated cause.
func TestRevocationReasonMapping(t *testing.T) {
	want := map[int]string{
		0: "unspecified", 1: "key_compromise", 3: "affiliation_changed",
		4: "superseded", 5: "cessation_of_operation",
	}
	for code, reason := range want {
		if RevocationReasons[code] != reason {
			t.Errorf("code %d maps to %q, want %q", code, RevocationReasons[code], reason)
		}
		if !slices.Contains(appPKI.RevocationReasons, reason) {
			t.Errorf("code %d maps to %q, which the PKI does not accept", code, reason)
		}
	}
	if len(RevocationReasons) != len(want) {
		t.Errorf("the mapping has %d entries, want %d", len(RevocationReasons), len(want))
	}
	// Codes with no equivalent must be absent so they are refused rather than
	// flattened onto "unspecified".
	for _, code := range []int{2, 6, 7, 8, 9, 10, 11} {
		if _, ok := RevocationReasons[code]; ok {
			t.Errorf("code %d unexpectedly has a mapping", code)
		}
	}
}

// TestRevokeRefusesUnmappableReason drives a real certificate through Revoke so
// the request gets past parsing and actually reaches the reason check.
func TestRevokeRefusesUnmappableReason(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	der := selfSignedDER(t)

	payload, err := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(der), "reason": 6,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	err = svc.Revoke(testCtx(), endpointOf(t, repo), &request{jws: &jws{payload: payload}})
	if got := problemType(t, err); got != ProblemBadRevocationReason {
		t.Errorf("got %s, want badRevocationReason", got)
	}
	if len(issuer.revoked) != 0 {
		t.Errorf("a refused reason still reached the PKI")
	}
}

// TestRevokeRefusesAnotherAccountsCertificate: holding an account on this
// endpoint is not authority over a certificate somebody else ordered.
func TestRevokeRefusesAnotherAccountsCertificate(t *testing.T) {
	repo := newFakeStore()
	svc, issuer := newTestService(repo)
	der := selfSignedDER(t)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// A certificate the PKI knows about, ordered by nobody in this store.
	certs := fakeCertificates{
		bySerial: map[string]appPKI.Certificate{
			strings.ToLower(parsed.SerialNumber.Text(16)): {ID: "cert-9", Status: appPKI.CertStatusIssued},
		},
		byID: map[string]appPKI.Certificate{},
	}
	svc.pkiRepo = certs
	intruder := testAccount(t, svc, repo)

	payload, err := json.Marshal(map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(der)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	err = svc.Revoke(testCtx(), endpointOf(t, repo), &request{jws: &jws{payload: payload}, account: intruder})
	if got := problemType(t, err); got != ProblemUnauthorized {
		t.Errorf("got %s, want unauthorized", got)
	}
	if len(issuer.revoked) != 0 {
		t.Errorf("an unauthorized revocation reached the PKI")
	}
}

// selfSignedDER makes a certificate that only needs to parse and carry a serial.
func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x5eed),
		Subject:      pkix.Name{CommonName: "a.internal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return der
}

// ---------------------------------------------------------------------------
// Endpoint administration
// ---------------------------------------------------------------------------

// Modern ACME clients commonly send SAN-only CSRs with an empty subject. A new
// endpoint must accept those by default; administrators can still opt into a
// subject restriction through the issuance policy.
func TestCreateEndpointHasNoDefaultSubjectRestriction(t *testing.T) {
	repo := newFakeStore()
	delete(repo.endpoints, testEndpoint)
	svc, _ := newTestService(repo)

	e, err := svc.CreateEndpoint(testCtx(), CreateEndpointRequest{
		OrgID: testOrg, CAID: testCA, Name: "New"})
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	if e.SubjectPattern != "" {
		t.Errorf("subject pattern = %q, want no default restriction", e.SubjectPattern)
	}
}

func TestCreateEndpointRefusesDuplicateNameCaseInsensitively(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)

	_, err := svc.CreateEndpoint(testCtx(), CreateEndpointRequest{
		OrgID: testOrg, CAID: testCA, Name: "test"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("got %v, want a duplicate-name refusal", err)
	}
}

func TestCredentialSealingRoundTrips(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	credential, macKey := mintCredential(t, svc, repo, CredentialSpec{Label: "test"})

	if string(credential.MACKeyCiphertext) == string(macKey) {
		t.Fatal("the MAC key was stored in the clear")
	}
	// Registration is the real round trip: it unseals under
	// credentialPurpose(id) and verifies an HMAC with the result, so a purpose
	// string that did not match what CreateCredential sealed with would fail
	// here rather than silently.
	if _, err := registerAccount(t, svc, repo, newTestKey(t), credential, macKey); err != nil {
		t.Fatalf("registration through the sealed key failed: %v", err)
	}
}

func TestCredentialExpiryIsHonoured(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	credential, macKey := mintCredential(t, svc, repo, CredentialSpec{TTL: time.Hour})

	// Wind the stored credential back past its expiry.
	stored := repo.credentials[credential.ID]
	past := time.Now().Add(-time.Minute)
	stored.ExpiresAt = &past
	repo.credentials[credential.ID] = stored

	_, err := registerAccount(t, svc, repo, newTestKey(t), credential, macKey)
	if got := problemType(t, err); got != ProblemUnauthorized {
		t.Errorf("got %s, want unauthorized", got)
	}
}
