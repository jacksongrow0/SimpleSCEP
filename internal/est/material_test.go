package est

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// Real certificates and real CSRs, generated once per test binary. Fixed PEM
// blobs would be shorter, but every check that matters here — the signature on a
// CSR, the DER a PKCS#7 carries, the key policy — is only meaningful against
// material a parser will actually accept.
type material struct {
	rootPEM, caPEM, leafPEM string
	rootCert, caCert        *x509.Certificate
	rsaCA                   *x509.Certificate
}

var (
	materialOnce sync.Once
	sharedMat    material
)

func testMaterial() material {
	materialOnce.Do(func() { sharedMat = buildMaterial() })
	return sharedMat
}

func buildMaterial() material {
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, rootCert, &caKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "gw-01.example.internal"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	rsaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "RSA CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rsaDER, err := x509.CreateCertificate(rand.Reader, rsaTmpl, rsaTmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		panic(err)
	}
	rsaCA, _ := x509.ParseCertificate(rsaDER)

	return material{
		rootPEM: encodeCert(rootDER), caPEM: encodeCert(caDER), leafPEM: encodeCert(leafDER),
		rootCert: rootCert, caCert: caCert, rsaCA: rsaCA,
	}
}

func encodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// csrOptions is what a test varies about a request. The zero value is a
// well-formed P-256 request for gw-01.example.internal.
type csrOptions struct {
	commonName string
	dnsNames   []string
	ipAddress  string
	ekus       []asn1.ObjectIdentifier
	rsaBits    int
	curve      elliptic.Curve
}

func testCSR(t *testing.T, opts csrOptions) *x509.CertificateRequest {
	t.Helper()
	if opts.commonName == "" {
		opts.commonName = "gw-01.example.internal"
	}
	var key any
	var err error
	switch {
	case opts.rsaBits > 0:
		key, err = rsa.GenerateKey(rand.Reader, opts.rsaBits)
	case opts.curve != nil:
		key, err = ecdsa.GenerateKey(opts.curve, rand.Reader)
	default:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: opts.commonName},
		DNSNames: opts.dnsNames,
	}
	if opts.ipAddress != "" {
		tmpl.IPAddresses = []net.IP{net.ParseIP(opts.ipAddress)}
	}
	if len(opts.ekus) > 0 {
		value, err := asn1.Marshal(opts.ekus)
		if err != nil {
			t.Fatalf("marshal ekus: %v", err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidExtendedKeyUsageID, Value: value}}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	return csr
}
