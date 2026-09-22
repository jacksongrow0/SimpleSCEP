package acme

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"

	// crypto.Hash.New panics on a hash whose implementation has not registered
	// itself, and hashFor returns SHA-384 and SHA-512. Importing for the side
	// effect is how the crypto package expects that dependency to be declared.
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"slices"
	"strings"
)

// This file is the security boundary. Everything an ACME client sends arrives
// here as a JWS it signed itself, and what this code decides about that
// signature is the only thing standing between a client and another customer's
// certificates. RFC 8555 §6 is the specification; the comments below record why
// each check is not optional.

// minRSABits refuses keys that are too small to be worth signing anything with.
// 2048 is the floor every current guideline agrees on.
const minRSABits = 2048

// flatJWS is the wire form RFC 8555 §6.2 requires: the flattened JSON
// serialization, one signature, no unprotected header. Accepting the general
// serialization would mean accepting multiple signatures, and then having to
// decide which one authorized the request.
type flatJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	// Header is the unprotected header. RFC 8555 §6.2 forbids it, and it is
	// decoded only so its presence can be refused: values there are not covered
	// by the signature, so honouring any of them would let an attacker rewrite
	// the parts of a request the client thought it had signed.
	Header json.RawMessage `json:"header"`
}

type jwsHeader struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	KID   string          `json:"kid"`
	JWK   json.RawMessage `json:"jwk"`
	Crit  []string        `json:"crit"`
}

// jws is a parsed, not yet verified, request signature.
type jws struct {
	header jwsHeader
	// payload is the decoded body. POSTAsGET distinguishes the empty string,
	// which RFC 8555 §6.3 defines as a read, from "{}", which is an empty
	// object and means something else entirely on newAccount.
	payload   []byte
	postAsGet bool
	// signing is the exact byte sequence the signature covers: the protected
	// header and payload as the client encoded them. Re-encoding either would
	// let a difference in JSON serialization break a valid signature, or worse,
	// verify one over bytes other than the ones acted on.
	signing   []byte
	signature []byte
}

func decodeSegment(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// parseJWS decodes a flattened JWS and applies every check that does not need a
// key. It deliberately does not verify the signature — the key to verify with
// comes from the header this parses.
func parseJWS(body []byte) (*jws, error) {
	var flat flatJWS
	if err := json.Unmarshal(body, &flat); err != nil {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed, "the request body is not a JSON object")
	}
	if len(flat.Header) > 0 {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed,
			"the request carries an unprotected header, which this protocol does not allow")
	}
	if flat.Protected == "" || flat.Signature == "" {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed,
			"the request is not a flattened JWS with a protected header and a signature")
	}

	protected, err := decodeSegment(flat.Protected)
	if err != nil {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed, "the protected header is not base64url")
	}
	var header jwsHeader
	if err := json.Unmarshal(protected, &header); err != nil {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed, "the protected header is not JSON")
	}
	// "crit" names extensions the recipient must understand or reject. We
	// understand none, so any value here is a refusal rather than something to
	// skip past.
	if len(header.Crit) > 0 {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed,
			"the protected header requires extensions this server does not implement")
	}

	payload, err := decodeSegment(flat.Payload)
	if err != nil {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed, "the payload is not base64url")
	}
	signature, err := decodeSegment(flat.Signature)
	if err != nil {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed, "the signature is not base64url")
	}

	return &jws{
		header:    header,
		payload:   payload,
		postAsGet: flat.Payload == "",
		signing:   []byte(flat.Protected + "." + flat.Payload),
		signature: signature,
	}, nil
}

// checkOuter applies the rules that hold for every request-level JWS: a
// signature algorithm we accept, exactly one key identification, and a url that
// matches where the request actually arrived.
func (j *jws) checkOuter(requestURL string) error {
	// The allowlist is the defence against two separate attacks. "none" needs no
	// key. Every HS* algorithm is a MAC, and a newAccount JWS carries its own
	// verification key in the jwk header — so accepting HS256 there would let a
	// client sign with a key it also supplied, and anyone could register as
	// anyone. HMAC is verified in exactly one place, verifyHMAC, against a key
	// that came out of the database.
	if !slices.Contains(SignatureAlgorithms, j.header.Alg) {
		return problemf(http.StatusBadRequest, ProblemBadSignatureAlgorithm,
			"%q is not a signature algorithm this server accepts", j.header.Alg)
	}
	hasJWK, hasKID := len(j.header.JWK) > 0, j.header.KID != ""
	if hasJWK == hasKID {
		return problemf(http.StatusBadRequest, ProblemMalformed,
			"the protected header must carry exactly one of jwk and kid")
	}
	// §6.4. Without this a request signed for one resource could be replayed
	// against another — a deactivate signed for one account URL replayed at
	// another's, say. The signature says nothing about intent unless the target
	// is inside it.
	if j.header.URL != requestURL {
		return problemf(http.StatusBadRequest, ProblemUnauthorized,
			"the signed url does not match the address this request was sent to")
	}
	return nil
}

// verify checks the signature against a public key. It is the only thing that
// turns a parsed request into an authorized one.
func (j *jws) verify(key crypto.PublicKey) error {
	hash, err := hashFor(j.header.Alg)
	if err != nil {
		return err
	}
	digest := hash.New()
	digest.Write(j.signing)
	sum := digest.Sum(nil)

	unauthorized := problemf(http.StatusUnauthorized, ProblemUnauthorized,
		"the request signature does not verify against the account key")

	switch pub := key.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSABits {
			return problemf(http.StatusBadRequest, ProblemBadPublicKey,
				"an RSA key of at least %d bits is required", minRSABits)
		}
		if strings.HasPrefix(j.header.Alg, "PS") {
			// PSS with the salt length equal to the digest length, which is what
			// RFC 7518 §3.5 specifies and what every client produces.
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}
			if err := rsa.VerifyPSS(pub, hash, sum, j.signature, opts); err != nil {
				return unauthorized
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, sum, j.signature); err != nil {
			return unauthorized
		}
		return nil

	case *ecdsa.PublicKey:
		if !strings.HasPrefix(j.header.Alg, "ES") {
			return problemf(http.StatusBadRequest, ProblemBadSignatureAlgorithm,
				"%q cannot be used with an elliptic curve key", j.header.Alg)
		}
		// JWS carries an ECDSA signature as the fixed-width concatenation of r
		// and s (RFC 7518 §3.4), not as the ASN.1 sequence x509 uses, so this
		// cannot go through ecdsa.VerifyASN1.
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(j.signature) != 2*size {
			return unauthorized
		}
		r := new(big.Int).SetBytes(j.signature[:size])
		s := new(big.Int).SetBytes(j.signature[size:])
		if !ecdsa.Verify(pub, sum, r, s) {
			return unauthorized
		}
		return nil
	}
	return problemf(http.StatusBadRequest, ProblemBadPublicKey, "unsupported account key type")
}

// verifyHMAC checks a MAC-signed JWS. This exists for one caller: the External
// Account Binding inner JWS, whose key is the credential an administrator minted
// and which this server read out of its own database. It is never reachable from
// a key the client supplied.
func (j *jws) verifyHMAC(key []byte) error {
	var hash crypto.Hash
	switch j.header.Alg {
	case "HS256":
		hash = crypto.SHA256
	case "HS384":
		hash = crypto.SHA384
	case "HS512":
		hash = crypto.SHA512
	default:
		return problemf(http.StatusBadRequest, ProblemBadSignatureAlgorithm,
			"the external account binding must be signed with HS256, HS384, or HS512")
	}
	mac := hmac.New(hash.New, key)
	mac.Write(j.signing)
	if !hmac.Equal(mac.Sum(nil), j.signature) {
		return problemf(http.StatusUnauthorized, ProblemUnauthorized,
			"the external account binding does not verify against that key")
	}
	return nil
}

func hashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "ES256", "PS256":
		return crypto.SHA256, nil
	case "RS384", "ES384", "PS384":
		return crypto.SHA384, nil
	case "RS512", "ES512", "PS512":
		return crypto.SHA512, nil
	}
	return 0, problemf(http.StatusBadRequest, ProblemBadSignatureAlgorithm,
		"%q is not a signature algorithm this server accepts", alg)
}

// jsonWebKey is the subset of RFC 7517 this server reads. Anything outside these
// fields is ignored, which is safe because the thumbprint below is computed from
// exactly the required members and so cannot be influenced by extras.
type jsonWebKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWK turns a JWK into a public key. Only RSA and EC are accepted: those
// are what every ACME client offers, and admitting more key types would widen
// the verification surface for no one's benefit.
func parseJWK(raw []byte) (crypto.PublicKey, error) {
	badKey := func(detail string) error {
		return problemf(http.StatusBadRequest, ProblemBadPublicKey, "%s", detail)
	}
	var k jsonWebKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, badKey("the account key is not a JSON web key")
	}
	switch k.Kty {
	case "RSA":
		n, err := decodeSegment(k.N)
		if err != nil {
			return nil, badKey("the RSA modulus is not base64url")
		}
		e, err := decodeSegment(k.E)
		if err != nil {
			return nil, badKey("the RSA exponent is not base64url")
		}
		if len(e) == 0 || len(e) > 4 {
			return nil, badKey("the RSA exponent is out of range")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < minRSABits {
			return nil, badKey("an RSA account key must be at least 2048 bits")
		}
		// A public exponent must be odd and greater than one. crypto/rsa checks
		// this on use, but rejecting it here names the problem.
		if pub.E < 3 || pub.E%2 == 0 {
			return nil, badKey("the RSA public exponent is not usable")
		}
		return pub, nil

	case "EC":
		var curve elliptic.Curve
		var check ecdh.Curve
		switch k.Crv {
		case "P-256":
			curve, check = elliptic.P256(), ecdh.P256()
		case "P-384":
			curve, check = elliptic.P384(), ecdh.P384()
		case "P-521":
			curve, check = elliptic.P521(), ecdh.P521()
		default:
			return nil, badKey("only the P-256, P-384, and P-521 curves are accepted")
		}
		x, err := decodeSegment(k.X)
		if err != nil {
			return nil, badKey("the EC x coordinate is not base64url")
		}
		y, err := decodeSegment(k.Y)
		if err != nil {
			return nil, badKey("the EC y coordinate is not base64url")
		}
		// RFC 7518 §6.2.1 fixes each coordinate at the field width, and the
		// on-curve check below reads them positionally, so a short encoding has
		// to be refused rather than left-padded into something that would verify
		// as a different point.
		size := (curve.Params().BitSize + 7) / 8
		if len(x) != size || len(y) != size {
			return nil, badKey("the EC coordinates are not the width their curve requires")
		}
		// A point that is not on its curve is not a key: ecdsa.Verify against one
		// is undefined rather than merely false. crypto/ecdh's NewPublicKey is
		// the supported way to make that check — elliptic.IsOnCurve is
		// deprecated — and it takes the same uncompressed encoding assembled
		// here. Its result is discarded; the check is the whole reason to call.
		point := append([]byte{4}, append(x, y...)...)
		if _, err := check.NewPublicKey(point); err != nil {
			return nil, badKey("the EC account key is not a valid point on its curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	}
	return nil, badKey("only RSA and EC account keys are accepted")
}

// jwkThumbprint computes the RFC 7638 thumbprint: SHA-256 over a canonical JSON
// object holding only the key's required members, in lexicographic order, with
// no whitespace. It is the account's stable identity — the same key always
// produces the same thumbprint regardless of how a client happened to serialize
// it, which is what makes it safe as a lookup key.
func jwkThumbprint(raw []byte) (string, error) {
	var k jsonWebKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", problemf(http.StatusBadRequest, ProblemBadPublicKey, "the account key is not a JSON web key")
	}
	// Built by hand rather than by marshalling a map: encoding/json escapes and
	// orders in ways that are not the canonical form, and the canonical form is
	// the whole point of the construction.
	var canonical string
	switch k.Kty {
	case "RSA":
		canonical = `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	case "EC":
		canonical = `{"crv":"` + k.Crv + `","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	default:
		return "", problemf(http.StatusBadRequest, ProblemBadPublicKey, "only RSA and EC account keys are accepted")
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
