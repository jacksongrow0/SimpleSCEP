// Package enroll holds what the SCEP, ACME and EST endpoints share.
//
// The three enrolment protocols differ in their wire formats and in nothing
// else an administrator sees: they are configured from the same pages, deleted
// behind the same typed confirmation, and authenticate their clients against
// secrets of the same shape. Those pieces live here so the three packages
// cannot drift apart on questions that have one right answer.
package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	homeview "github.com/jacksongrow0/SimpleSCEP/view/home"

	"golang.org/x/crypto/argon2"
)

// FormError reports a validation failure. htmx 2 ignores non-2xx swaps, so the
// message is returned 200 with the fragment the dialog renders; a plain form
// post gets a regular 400.
func FormError(w http.ResponseWriter, r *http.Request, err error) {
	if r.Header.Get("HX-Request") == "true" {
		_ = homeview.ProtocolError(err.Error()).Render(r.Context(), w)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// ConfirmsEndpointName decides whether a delete request carried its
// confirmation. The dialog disables its submit until the name is typed, but a
// disabled button is a courtesy rather than a control, so the same question is
// asked here where a direct post cannot skip it.
//
// Matching is case-insensitive and ignores surrounding whitespace: the point is
// to prove the administrator identified the right endpoint deliberately, not to
// test their typing.
func ConfirmsEndpointName(confirm, name string) bool {
	confirm = strings.TrimSpace(confirm)
	return confirm != "" && strings.EqualFold(confirm, strings.TrimSpace(name))
}

// SplitCSV reads the comma-separated lists the endpoint forms post, dropping
// blanks so a trailing comma or a stray space does not become an empty entry.
func SplitCSV(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ValidatePublicKey rejects a request whose key is too weak to certify,
// whatever protocol carried it. The floor is deliberately the same everywhere:
// a device that cannot meet it under one protocol must not be able to enroll by
// switching to another.
func ValidatePublicKey(pub any) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("RSA keys smaller than 2048 bits are not allowed")
		}
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() {
			return fmt.Errorf("unsupported EC curve")
		}
	default:
		return fmt.Errorf("unsupported public key algorithm")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Secrets
//
// One argon2id parameter set and one encoding for every protocol's client
// secrets: SCEP challenges, EST passwords and ACME external-account keys are
// the same kind of thing and are stored the same way. Sharing them is what
// keeps a parameter change from having to be remembered in three places.
// ---------------------------------------------------------------------------

const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// RandomSecret mints 32 bytes of entropy in the form a client pastes into a
// configuration file. base64url survives every place an operator might carry
// it — a URL, a YAML file, a mobileconfig.
func RandomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSecret encodes a salted argon2id digest as "salt.digest". The salt is
// stored beside the digest because it is not a secret; its job is to stop one
// precomputed table from covering every stored credential at once.
func HashSecret(secret string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return base64.RawStdEncoding.EncodeToString(salt) + "." + base64.RawStdEncoding.EncodeToString(sum), nil
}

// VerifySecret checks a secret against a stored hash in constant time. A
// malformed or undecodable stored value fails closed rather than erroring, so a
// corrupt row cannot be made to authenticate anything.
func VerifySecret(encoded, secret string) bool {
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[0])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[1])
	if e1 != nil || e2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}
