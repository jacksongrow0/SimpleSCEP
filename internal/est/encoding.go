package est

// This file is the protocol boundary — everything that turns bytes on the wire
// into values the service can reason about, and back. It occupies the place
// jws.go does in the ACME package, and the same rule applies: nothing here
// consults policy, and nothing outside it touches DER or base64.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"

	protocol "github.com/smallstep/scep"
)

// base64LineWidth is where the response body wraps. RFC 7030 §3.2.4 sends
// certificates as base64 with a Content-Transfer-Encoding of base64, and MIME
// base64 is line-oriented: libest and older Cisco IOS parsers reject a single
// unwrapped line.
const base64LineWidth = 64

// parseCSR turns a request body into a verified certificate request.
//
// RFC 7030 specifies base64-encoded DER, but real clients are looser than the
// specification: some post raw DER, some post PEM, and some send base64 through
// a path that has already turned '+' into ' '. All four are accepted, in the
// same spirit as scep.decodeMessage — being strict here rejects working clients
// without making anything safer, since the signature check below is what
// actually matters.
func parseCSR(body []byte) (*x509.CertificateRequest, error) {
	der, err := decodeCSRBody(body)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errorf(http.StatusBadRequest, "the request body is not a PKCS#10 certificate request")
	}
	// Proof of possession: without this anyone who can read a CSR off the wire
	// could enroll its subject with a key they hold instead.
	if err := csr.CheckSignature(); err != nil {
		return nil, errorf(http.StatusBadRequest, "the certificate request signature does not verify")
	}
	return csr, nil
}

func decodeCSRBody(body []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, errorf(http.StatusBadRequest, "the request body is empty")
	}
	if block, _ := pem.Decode(body); block != nil {
		return block.Bytes, nil
	}
	// Wire base64 arrives wrapped; both the newlines and any '+' that survived
	// as a space have to go before it will decode.
	compact := strings.NewReplacer("\r", "", "\n", "", " ", "+").Replace(trimmed)
	if der, err := base64.StdEncoding.DecodeString(compact); err == nil {
		return der, nil
	}
	if der, err := base64.RawURLEncoding.DecodeString(compact); err == nil {
		return der, nil
	}
	// Raw DER, tried last: a PKCS#10 always starts with a SEQUENCE, so this is
	// a cheap check that avoids handing arbitrary bytes to the parser.
	if len(body) > 0 && body[0] == 0x30 {
		return body, nil
	}
	return nil, errorf(http.StatusBadRequest, "the request body is not a base64 or DER certificate request")
}

// certsOnly builds the degenerate PKCS#7 that /cacerts and the enrollment
// responses carry: a signed-data structure with no signers, holding only
// certificates. It is the same encoding SCEP's GetCACert returns, so the helper
// is the same one.
func certsOnly(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificates to return")
	}
	der, err := protocol.DegenerateCertificates(certs)
	if err != nil {
		return nil, err
	}
	return wrapBase64(der), nil
}

func wrapBase64(der []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(der)
	var out strings.Builder
	for len(encoded) > base64LineWidth {
		out.WriteString(encoded[:base64LineWidth])
		out.WriteString("\n")
		encoded = encoded[base64LineWidth:]
	}
	out.WriteString(encoded)
	out.WriteString("\n")
	return []byte(out.String())
}

// parseChain reads every certificate out of one or more PEM bundles, in order.
func parseChain(bundles ...string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, raw := range bundles {
		rest := []byte(raw)
		for {
			block, remainder := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = remainder
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// Object identifiers csrAttributes advertises. RFC 7030 §4.5.2 describes the
// response as a sequence of attributes and bare OIDs telling the client what to
// put in its request; these are the ones that change what a client generates.
var (
	oidRSAEncryption      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECPublicKey        = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidPrimeField256V1    = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidSECP384R1          = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidExtensionRequest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidExtendedKeyUsageID = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// csrAttrAttribute is one Attribute of a CsrAttrs sequence: an OID and the set
// of values that qualify it.
type csrAttrAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.ObjectIdentifier `asn1:"set"`
}

// csrAttributes builds the CsrAttrs body for an endpoint, describing what its
// policy will accept so a client can generate a request that passes the first
// time rather than learning by rejection.
//
// It reports false when the endpoint's CA narrows nothing worth saying, which
// the handler answers with the 204 §4.5 asks for: "if the CA does not desire to
// provide additional descriptive information, it MUST return an HTTP 204".
func csrAttributes(ca *x509.Certificate, allowedEKUs []string) ([]byte, bool, error) {
	var elements []any
	switch pub := ca.PublicKey.(type) {
	case *ecdsa.PublicKey:
		// The leaf need not use the CA's algorithm, but advertising it is what
		// steers a client that would otherwise default to RSA-2048 towards the
		// curve the rest of the deployment uses.
		curve := oidPrimeField256V1
		sigAlg := oidECDSAWithSHA256
		if pub.Curve == elliptic.P384() {
			curve, sigAlg = oidSECP384R1, oidECDSAWithSHA384
		}
		elements = append(elements, csrAttrAttribute{Type: oidECPublicKey, Values: []asn1.ObjectIdentifier{curve}})
		elements = append(elements, sigAlg)
	case *rsa.PublicKey:
		elements = append(elements, oidRSAEncryption, oidSHA256WithRSA)
	default:
		return nil, false, nil
	}
	// Asking for an extensionRequest tells the client its EKUs are read from the
	// request rather than assumed, which is the one thing about this endpoint's
	// policy a client can act on before it sends anything.
	if len(allowedEKUs) > 0 {
		elements = append(elements, csrAttrAttribute{
			Type:   oidExtensionRequest,
			Values: []asn1.ObjectIdentifier{oidExtendedKeyUsageID},
		})
	}
	der, err := marshalCsrAttrs(elements)
	if err != nil {
		return nil, false, err
	}
	return wrapBase64(der), true, nil
}

// marshalCsrAttrs encodes CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID.
// AttrOrOID is a CHOICE of an OID and an Attribute, which encoding/asn1 cannot
// express directly, so the members are marshalled individually and the SEQUENCE
// header is written around them.
func marshalCsrAttrs(elements []any) ([]byte, error) {
	var body []byte
	for _, element := range elements {
		der, err := asn1.Marshal(element)
		if err != nil {
			return nil, err
		}
		body = append(body, der...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

// basicAuth reads the credentials from a request. The realm on the challenge is
// the endpoint name, because a device operator configuring several endpoints
// sees it in the prompt and in the client's logs.
func basicAuth(r *http.Request) (username, password string, ok bool) {
	return r.BasicAuth()
}

func challengeBasic(w http.ResponseWriter, endpointName string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+strings.ReplaceAll(endpointName, `"`, ``)+`"`)
}
