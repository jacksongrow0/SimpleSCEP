package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// The helpers below build JWS values the way a client would, because the checks
// under test are all about what a real signature does and does not cover. A
// mock that returned "valid" would test nothing.

type testKey struct {
	priv *ecdsa.PrivateKey
	jwk  string
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pad := func(i *big.Int) string {
		b := i.Bytes()
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(out)
	}
	jwk := `{"crv":"P-256","kty":"EC","x":"` + pad(priv.X) + `","y":"` + pad(priv.Y) + `"}`
	return testKey{priv: priv, jwk: jwk}
}

func b64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }

// signJWS produces a flattened JWS the way an ACME client does: ES256 over
// "protected.payload", with the signature as the fixed-width concatenation of r
// and s rather than the ASN.1 form x509 uses.
func signJWS(t *testing.T, key testKey, header map[string]any, payload string) []byte {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	protected := b64(headerJSON)
	encodedPayload := ""
	if payload != "" {
		encodedPayload = b64([]byte(payload))
	}
	signing := protected + "." + encodedPayload
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key.priv, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	body, err := json.Marshal(map[string]string{
		"protected": protected, "payload": encodedPayload, "signature": b64(sig),
	})
	if err != nil {
		t.Fatalf("marshal jws: %v", err)
	}
	return body
}

// signHMAC produces the inner JWS of an External Account Binding.
func signHMAC(t *testing.T, macKey []byte, header map[string]any, payload string) json.RawMessage {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	protected := b64(headerJSON)
	encodedPayload := b64([]byte(payload))
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(protected + "." + encodedPayload))
	body, err := json.Marshal(map[string]string{
		"protected": protected, "payload": encodedPayload, "signature": b64(mac.Sum(nil)),
	})
	if err != nil {
		t.Fatalf("marshal eab: %v", err)
	}
	return body
}

func problemType(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got none")
	}
	p, ok := err.(Problem)
	if !ok {
		t.Fatalf("expected a Problem, got %T: %v", err, err)
	}
	return p.Type
}

// TestOuterJWSRejectsMACAndNone covers the reason SignatureAlgorithms is an
// allowlist rather than a denylist. An outer JWS carries its own verification
// key for newAccount, so a MAC algorithm there would let a client sign with a
// key it also chose.
func TestOuterJWSRejectsMACAndNone(t *testing.T) {
	key := newTestKey(t)
	for _, alg := range []string{"none", "HS256", "HS512"} {
		body := signJWS(t, key, map[string]any{
			"alg": alg, "nonce": "n", "url": testURL, "jwk": json.RawMessage(key.jwk),
		}, `{}`)
		j, err := parseJWS(body)
		if err != nil {
			t.Fatalf("alg=%s parse: %v", alg, err)
		}
		if got := problemType(t, j.checkOuter(testURL)); got != ProblemBadSignatureAlgorithm {
			t.Errorf("alg=%s: got %s, want badSignatureAlgorithm", alg, got)
		}
	}
}

func TestOuterJWSRequiresExactlyOneKeyIdentification(t *testing.T) {
	key := newTestKey(t)
	both := signJWS(t, key, map[string]any{
		"alg": "ES256", "nonce": "n", "url": testURL, "jwk": json.RawMessage(key.jwk), "kid": "x",
	}, `{}`)
	j, err := parseJWS(both)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := problemType(t, j.checkOuter(testURL)); got != ProblemMalformed {
		t.Errorf("jwk and kid: got %s, want malformed", got)
	}

	neither := signJWS(t, key, map[string]any{"alg": "ES256", "nonce": "n", "url": testURL}, `{}`)
	j, err = parseJWS(neither)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := problemType(t, j.checkOuter(testURL)); got != ProblemMalformed {
		t.Errorf("neither: got %s, want malformed", got)
	}
}

// TestSignedURLMustMatchRequest is the check that stops a request signed for one
// resource being replayed against another.
func TestSignedURLMustMatchRequest(t *testing.T) {
	key := newTestKey(t)
	body := signJWS(t, key, map[string]any{
		"alg": "ES256", "nonce": "n", "url": testURL + "/acme/x/new-order", "jwk": json.RawMessage(key.jwk),
	}, `{}`)
	j, err := parseJWS(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := problemType(t, j.checkOuter(testURL+"/acme/x/revoke-cert")); got != ProblemUnauthorized {
		t.Errorf("got %s, want unauthorized", got)
	}
}

func TestUnprotectedHeaderIsRefused(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"protected": b64([]byte(`{"alg":"ES256"}`)), "payload": "", "signature": b64([]byte("x")),
		"header": map[string]string{"kid": "attacker"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := problemType(t, func() error { _, e := parseJWS(body); return e }()); got != ProblemMalformed {
		t.Errorf("got %s, want malformed", got)
	}
}

// TestTamperedSignatureFails confirms the signature is actually verified rather
// than merely parsed.
func TestTamperedSignatureFails(t *testing.T) {
	key := newTestKey(t)
	body := signJWS(t, key, map[string]any{
		"alg": "ES256", "nonce": "n", "url": testURL, "jwk": json.RawMessage(key.jwk),
	}, `{"contact":["mailto:a@b.test"]}`)
	// Flip a bit in the payload without re-signing.
	tampered := []byte(strings.Replace(string(body),
		b64([]byte(`{"contact":["mailto:a@b.test"]}`)),
		b64([]byte(`{"contact":["mailto:z@b.test"]}`)), 1))
	j, err := parseJWS(tampered)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pub, err := parseJWK([]byte(key.jwk))
	if err != nil {
		t.Fatalf("parse jwk: %v", err)
	}
	if got := problemType(t, j.verify(pub)); got != ProblemUnauthorized {
		t.Errorf("got %s, want unauthorized", got)
	}
}

// TestThumbprintIsStableAcrossSerializations is what makes the thumbprint safe
// as an account lookup key: two clients encoding the same key differently must
// still resolve to one account.
func TestThumbprintIsStableAcrossSerializations(t *testing.T) {
	key := newTestKey(t)
	var fields map[string]string
	if err := json.Unmarshal([]byte(key.jwk), &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Same members, different order, plus an extra the thumbprint must ignore.
	reordered := `{"y":"` + fields["y"] + `","kty":"EC","use":"sig","x":"` + fields["x"] +
		`","crv":"` + fields["crv"] + `"}`

	a, err := jwkThumbprint([]byte(key.jwk))
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	b, err := jwkThumbprint([]byte(reordered))
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if a != b {
		t.Errorf("thumbprint changed with serialization: %s != %s", a, b)
	}
}

func TestJWKRejectsOffCurvePoint(t *testing.T) {
	key := newTestKey(t)
	var fields map[string]string
	if err := json.Unmarshal([]byte(key.jwk), &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// A valid x with a y that does not satisfy the curve equation.
	bogus := `{"crv":"P-256","kty":"EC","x":"` + fields["x"] + `","y":"` +
		b64(make([]byte, 32)) + `"}`
	if got := problemType(t, func() error { _, e := parseJWK([]byte(bogus)); return e }()); got != ProblemBadPublicKey {
		t.Errorf("got %s, want badPublicKey", got)
	}
}

func TestJWKRejectsSmallRSAKey(t *testing.T) {
	small := `{"kty":"RSA","e":"AQAB","n":"` + b64(make([]byte, 128)) + `"}`
	if got := problemType(t, func() error { _, e := parseJWK([]byte(small)); return e }()); got != ProblemBadPublicKey {
		t.Errorf("got %s, want badPublicKey", got)
	}
}
