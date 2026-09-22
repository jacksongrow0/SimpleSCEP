package scep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

// csrRequestingEKUs builds a CSR carrying an extendedKeyUsage extension request,
// which is how an MDM tells the endpoint what the certificate is for.
func csrRequestingEKUs(t *testing.T, oids ...asn1.ObjectIdentifier) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}
	if len(oids) > 0 {
		value, err := asn1.Marshal(oids)
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = []pkix.Extension{{Id: oidExtKeyUsage, Value: value}}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// endpointFromPath must refuse a malformed endpoint ID before it reaches the
// database. Without the guard Postgres raises 22P02 on the uuid comparison and
// the administrator sees a 500 rather than a refusal.
//
// Scoping to the session's organization is enforced by the query predicate in
// EndpointByID, so a well-formed ID belonging to another customer only fails to
// resolve against a real database; that case is covered by the manual
// verification steps rather than here.
func TestEndpointFromPathRefusesMalformedIDsBeforeQuerying(t *testing.T) {
	// A zero Repository has no database handle, so reaching one would panic —
	// which is exactly the assertion: none of these get that far.
	h := Handler{repo: Repository{}}
	for name, id := range map[string]string{
		"malformed":      "not-a-uuid",
		"empty":          "",
		"path traversal": "../../etc/passwd",
		"sql fragment":   "' OR 1=1 --",
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/scep/endpoints/x/enabled", nil)
			r.SetPathValue("endpointID", id)
			w := httptest.NewRecorder()
			if _, ok := h.endpointFromPath(w, r, auth.Session{OrgID: "org-1"}); ok {
				t.Fatalf("endpoint %q was resolved", id)
			}
			if w.Code >= 500 {
				t.Fatalf("a bad endpoint ID must not 500, got %d", w.Code)
			}
		})
	}
}

// The delete dialog disables its submit until the endpoint's name is typed, but
// a disabled button is a courtesy rather than a control. Deletion is
// irreversible and silently breaks renewal for every device the endpoint
// enrolled, so the confirmation has to hold when the form is posted directly.
func TestDeleteEndpointRequiresTheNameToBeTyped(t *testing.T) {
	name := "Corporate Wi-Fi"
	for label, tc := range map[string]struct {
		confirm string
		want    bool
	}{
		"exact":              {name, true},
		"different case":     {"corporate wi-fi", true},
		"surrounding spaces": {"  Corporate Wi-Fi  ", true},
		"absent":             {"", false},
		"partial":            {"Corporate", false},
		"another endpoint":   {"Guest Wi-Fi", false},
		"whitespace only":    {"   ", false},
	} {
		t.Run(label, func(t *testing.T) {
			if got := enroll.ConfirmsEndpointName(tc.confirm, name); got != tc.want {
				t.Fatalf("confirm %q accepted=%t, want %t", tc.confirm, got, tc.want)
			}
		})
	}
}

// The store scopes by organization, so one customer's ID does not resolve for
// another. This covers the seam; the SQL predicate itself needs a database.
func TestEndpointLookupIsScopedToTheOrganization(t *testing.T) {
	f := newFakeStore()
	mine, err := createEndpoint(t, f, "Mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.EndpointByID(context.Background(), "org-1", mine.ID); err != nil {
		t.Fatalf("the organization's own endpoint should resolve: %v", err)
	}
	if _, err := f.EndpointByID(context.Background(), "org-1", uuid.NewString()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("an unknown endpoint should be not found, got %v", err)
	}
}

func oidFor(t *testing.T, token string) asn1.ObjectIdentifier {
	t.Helper()
	for _, candidate := range []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 3, 6, 1, 5, 5, 7, 3, 2}, {1, 3, 6, 1, 5, 5, 7, 3, 3},
		{1, 3, 6, 1, 5, 5, 7, 3, 4}, {1, 3, 6, 1, 5, 5, 7, 3, 9}, {1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
	} {
		if appPKI.EKUToken(candidate) == token {
			return candidate
		}
	}
	t.Fatalf("no OID for %q", token)
	return nil
}

func TestRequestedEKUsReadsExtensionRequest(t *testing.T) {
	csr := csrRequestingEKUs(t, oidFor(t, appPKI.EKUEmailProtection), oidFor(t, appPKI.EKUClientAuth))
	got, err := RequestedEKUs(csr)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{appPKI.EKUEmailProtection, appPKI.EKUClientAuth}
	if !slices.Equal(got, want) {
		t.Fatalf("requested = %v, want %v", got, want)
	}
}

// A request that carries no extendedKeyUsage must read as "no preference", not
// as "none": that is the shape most SCEP clients send.
func TestRequestedEKUsAbsentIsNoPreference(t *testing.T) {
	got, err := RequestedEKUs(csrRequestingEKUs(t))
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("requested = %v, want nil", got)
	}
}

func TestResolveEKUs(t *testing.T) {
	const allowed = "client_auth,email_protection"
	// A request stating no usage gets client auth alone. Permitting S/MIME on
	// the endpoint must never hand emailProtection to a device that asked for
	// nothing.
	got, err := ResolveEKUs(allowed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{appPKI.EKUClientAuth}) {
		t.Fatalf("empty request resolved to %v, want client auth alone", got)
	}
	// A subset is issued as exactly that subset, so an S/MIME profile does not
	// also collect client auth and a Wi-Fi profile does not collect S/MIME.
	got, err = ResolveEKUs(allowed, []string{appPKI.EKUEmailProtection})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{appPKI.EKUEmailProtection}) {
		t.Fatalf("subset resolved to %v", got)
	}
	// Anything outside the allow list is refused rather than silently dropped.
	if _, err := ResolveEKUs(allowed, []string{appPKI.EKUClientAuth, appPKI.EKUCodeSigning}); err == nil {
		t.Fatal("a usage outside the allow list must be refused")
	}
	// An endpoint stored with no allow list still issues something usable.
	got, err = ResolveEKUs("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{appPKI.EKUClientAuth}) {
		t.Fatalf("empty allow list resolved to %v", got)
	}
}

// An endpoint that does not permit client auth has no safe default to fall back
// on, so a request stating no usage is refused rather than issued something the
// policy never allowed.
func TestResolveEKUsRefusesDefaultOutsideAllowList(t *testing.T) {
	if _, err := ResolveEKUs("email_protection", nil); err == nil {
		t.Fatal("a request stating no usage must be refused when client auth is not permitted")
	}
	got, err := ResolveEKUs("email_protection", []string{appPKI.EKUEmailProtection})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{appPKI.EKUEmailProtection}) {
		t.Fatalf("resolved = %v", got)
	}
}

func TestResolveEKUsDeduplicates(t *testing.T) {
	got, err := ResolveEKUs("client_auth", []string{appPKI.EKUClientAuth, appPKI.EKUClientAuth})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{appPKI.EKUClientAuth}) {
		t.Fatalf("resolved = %v", got)
	}
}

// A device must never be able to obtain an OCSP signing certificate: RFC 6960
// would make it a delegated responder for the issuing CA, letting it sign
// "good" for certificates that CA has revoked.
func TestOCSPSigningIsNotOfferable(t *testing.T) {
	if slices.Contains(EKUChoices, appPKI.EKUOCSPSigning) {
		t.Fatal("ocsp_signing must not be offerable on a SCEP endpoint")
	}
	if _, err := ResolveEKUs(strings.Join(EKUChoices, ","), []string{appPKI.EKUOCSPSigning}); err == nil {
		t.Fatal("ocsp_signing must be refused even with every choice allowed")
	}
}

// A challenge may pin its enrollment to a subset of what the endpoint permits,
// but never to something outside it, or minting one would be a way around the
// issuance policy.
func TestNarrowEKUsCannotWidenEndpointPolicy(t *testing.T) {
	got, err := narrowEKUs("client_auth,email_protection", []string{appPKI.EKUEmailProtection})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{appPKI.EKUEmailProtection}) {
		t.Fatalf("narrowed = %v", got)
	}
	if _, err := narrowEKUs("client_auth", []string{appPKI.EKUCodeSigning}); err == nil {
		t.Fatal("a challenge must not pin a usage the endpoint does not permit")
	}
	// Pinning nothing is how every existing challenge behaves.
	got, err = narrowEKUs("client_auth", nil)
	if err != nil || got != nil {
		t.Fatalf("empty pin = %v, %v", got, err)
	}
}

// Extended key usages are a set in the certificate, so a pin must not depend on
// the order the client serialized them in.
func TestSameEKUSetIgnoresOrder(t *testing.T) {
	if !sameEKUSet([]string{"client_auth", "email_protection"}, []string{"email_protection", "client_auth"}) {
		t.Fatal("order must not matter")
	}
	if sameEKUSet([]string{"client_auth"}, []string{"client_auth", "email_protection"}) {
		t.Fatal("a superset must not match")
	}
	if sameEKUSet([]string{"client_auth", "code_signing"}, []string{"client_auth", "email_protection"}) {
		t.Fatal("differing sets of equal size must not match")
	}
}

// anyExtendedKeyUsage is a wildcard that constrains nothing, so it must not
// survive validation even though it is a well-formed dotted OID.
func TestAnyPurposeEKUIsRejected(t *testing.T) {
	if _, err := appPKI.ValidateEKUs([]string{appPKI.EKUAnyPurpose}); err == nil {
		t.Fatal("anyExtendedKeyUsage must be rejected")
	}
	if _, err := appPKI.ValidateEKUs([]string{"client_auth", "2.5.29.37.0"}); err == nil {
		t.Fatal("anyExtendedKeyUsage must be rejected alongside other usages")
	}
	// A neighbouring OID must still be accepted, so the check is not a prefix
	// match over the arc.
	if _, err := appPKI.ValidateEKUs([]string{"2.5.29.37.1"}); err != nil {
		t.Fatalf("unrelated OID rejected: %v", err)
	}
}
