package est

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/smallstep/pkcs7"
)

// parseCertsOnly reads a response body back the way a client would: strip the
// base64, parse the PKCS#7, take its certificates.
func parseCertsOnly(t *testing.T, body []byte) []*x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(body), "\n", ""))
	if err != nil {
		t.Fatalf("the body is not base64: %v", err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatalf("the body is not a PKCS#7: %v", err)
	}
	return p7.Certificates
}

// TestCertsOnlyWrapsAtSixtyFourColumns pins the line width. libest and older
// Cisco IOS parsers reject a single unwrapped line, and nothing else in the
// system would notice it had changed.
func TestCertsOnlyWrapsAtSixtyFourColumns(t *testing.T) {
	body, err := certsOnly([]*x509.Certificate{testMaterial().caCert})
	if err != nil {
		t.Fatalf("certsOnly: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("the body is %d line(s); a certificate does not fit in one at 64 columns", len(lines))
	}
	for i, line := range lines {
		if len(line) > base64LineWidth {
			t.Fatalf("line %d is %d characters, want at most %d", i, len(line), base64LineWidth)
		}
	}
	if !strings.HasSuffix(string(body), "\n") {
		t.Error("the body does not end in a newline")
	}
}

func TestCertsOnlyRoundTrips(t *testing.T) {
	mat := testMaterial()
	body, err := certsOnly([]*x509.Certificate{mat.caCert, mat.rootCert})
	if err != nil {
		t.Fatalf("certsOnly: %v", err)
	}
	certs := parseCertsOnly(t, body)
	if len(certs) != 2 {
		t.Fatalf("got %d certificates back, want 2", len(certs))
	}
}

func TestCertsOnlyRefusesAnEmptyChain(t *testing.T) {
	if _, err := certsOnly(nil); err == nil {
		t.Fatal("an empty certs-only response was produced; a client would read it as a CA with no certificate")
	}
}

// TestParseCSRAcceptsEveryEncodingClientsSend is the tolerance the RFC does not
// require but real clients do.
func TestParseCSRAcceptsEveryEncodingClientsSend(t *testing.T) {
	csr := testCSR(t, csrOptions{})
	der := csr.Raw
	std := base64.StdEncoding.EncodeToString(der)

	bodies := map[string][]byte{
		"raw DER":       der,
		"base64":        []byte(std),
		"wrapped":       wrapBase64(der),
		"PEM":           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		"plus as space": []byte(strings.ReplaceAll(std, "+", " ")),
		"raw url":       []byte(base64.RawURLEncoding.EncodeToString(der)),
	}
	for name, body := range bodies {
		got, err := parseCSR(body)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.Subject.CommonName != csr.Subject.CommonName {
			t.Errorf("%s: common name = %q, want %q", name, got.Subject.CommonName, csr.Subject.CommonName)
		}
	}
}

func TestParseCSRRejectsAnEmptyBody(t *testing.T) {
	if _, err := parseCSR(nil); err == nil {
		t.Fatal("an empty body parsed as a certificate request")
	}
}

func TestParseCSRRejectsRubbish(t *testing.T) {
	if _, err := parseCSR([]byte("this is not a certificate request")); err == nil {
		t.Fatal("arbitrary text parsed as a certificate request")
	}
}

// TestParseCSRRejectsABrokenSignature is proof of possession. Without it anyone
// who can read a CSR off the wire could enroll its subject with their own key.
func TestParseCSRRejectsABrokenSignature(t *testing.T) {
	csr := testCSR(t, csrOptions{})
	tampered := make([]byte, len(csr.Raw))
	copy(tampered, csr.Raw)
	// Flip a bit in the signature, which is at the end of the structure.
	tampered[len(tampered)-1] ^= 0x01

	if _, err := parseCSR(tampered); err == nil {
		t.Fatal("a certificate request with an invalid signature was accepted")
	}
}

func TestCSRAttributesAdvertisesTheECCurve(t *testing.T) {
	// The issuing CA is P-256, so a client that would otherwise default to
	// RSA-2048 is steered onto the curve the rest of the deployment uses.
	body, ok, err := csrAttributes(testMaterial().caCert, []string{"client_auth"})
	if err != nil || !ok {
		t.Fatalf("csrAttributes: ok=%v err=%v", ok, err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(body), "\n", ""))
	if err != nil {
		t.Fatalf("the body is not base64: %v", err)
	}
	// It must be a well-formed SEQUENCE, since that is all a client parses
	// before deciding whether to trust the rest.
	if len(der) == 0 || der[0] != 0x30 {
		t.Fatalf("CsrAttrs is not a SEQUENCE: % x", der)
	}
}

func TestCSRAttributesHandlesAnRSACA(t *testing.T) {
	body, ok, err := csrAttributes(testMaterial().rsaCA, nil)
	if err != nil || !ok {
		t.Fatalf("csrAttributes: ok=%v err=%v", ok, err)
	}
	if len(body) == 0 {
		t.Error("an RSA CA advertised nothing")
	}
}

func TestParseChainSkipsNonCertificateBlocks(t *testing.T) {
	mat := testMaterial()
	// A bundle that also carries a key block, which some operators paste in.
	bundle := "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n" + mat.caPEM
	certs, err := parseChain(bundle)
	if err != nil {
		t.Fatalf("parseChain: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1", len(certs))
	}
}
