package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Recovery codes are the only way back into an account whose authenticator is
// gone. There is no administrator reset and no reset by email — email is
// already the first factor, so a reset over it would collapse two factors into
// one — which puts a lot of weight on these ten strings.
const (
	// recoveryCodeCount is how many are issued at once. Ten is enough that
	// losing a couple to a bad transcription is survivable, and few enough that
	// a person will actually store them.
	recoveryCodeCount = 10
	// A code is a selector followed by a verifier, presented as one string.
	//
	// The split is what keeps a wrong guess cheap. The selector locates exactly
	// one row, so verifying a submitted code costs one argon2id computation.
	// Storing an argon2 hash of the whole code instead would mean trying all ten
	// on every attempt: 640MB of memory and roughly two seconds of work, for an
	// unauthenticated caller, on an endpoint anyone can reach. That is a denial
	// of service, not a defence.
	//
	// The selector is not secret and is stored in the clear — it is a row
	// locator. The 50 bits of verifier are what an attacker would have to guess,
	// and 50 bits behind argon2id at 64MB is not reachable offline, let alone
	// online. Deliberately not a truncated fast hash of the whole code: that
	// would be a cheap hash of the secret itself sitting in the same row as the
	// expensive one, and the cheap one would be the one an attacker attacked.
	recoverySelectorLen = 6
	recoveryVerifierLen = 10
	recoveryCodeLen     = recoverySelectorLen + recoveryVerifierLen
)

// recoveryAlphabet is Crockford base32: the digits and uppercase letters with
// I, L, O and U removed. I/L/O are dropped because they are indistinguishable
// from 1 and 0 in most fonts, and these codes are transcribed by hand from
// wherever the user stored them, under the stress of having just lost their
// phone. U is dropped by the same standard to avoid accidental profanity.
const recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var errMalformedRecoveryCode = errors.New("recovery code is not the right shape")

// RecoveryCode is one code as it is stored: never the code itself.
type RecoveryCode struct {
	Selector     string
	VerifierHash string
}

// newRecoveryCodes mints a fresh set, returning both the strings to show the
// user exactly once and the rows to store. The two are deliberately different
// types so that a caller cannot store the display form by accident.
func newRecoveryCodes() (display []string, rows []RecoveryCode, err error) {
	seen := make(map[string]bool, recoveryCodeCount)
	for len(rows) < recoveryCodeCount {
		code, err := randomRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		selector, verifier := code[:recoverySelectorLen], code[recoverySelectorLen:]
		// The selector is UNIQUE across the whole table, so a collision would
		// fail the insert. At 30 bits it will not happen; drawing again costs
		// nothing and means it cannot.
		if seen[selector] {
			continue
		}
		seen[selector] = true

		hash, err := hashRecoveryVerifier(verifier)
		if err != nil {
			return nil, nil, err
		}
		display = append(display, formatRecoveryCode(code))
		rows = append(rows, RecoveryCode{Selector: selector, VerifierHash: hash})
	}
	return display, rows, nil
}

// randomRecoveryCode draws recoveryCodeLen characters uniformly from the
// alphabet. len(recoveryAlphabet) is 32, an exact divisor of 256, so masking the
// low five bits of a random byte is uniform — there is no modulo bias to reject
// against, which is why this can be a single pass.
func randomRecoveryCode() (string, error) {
	b := make([]byte, recoveryCodeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, recoveryCodeLen)
	for i, v := range b {
		out[i] = recoveryAlphabet[v&31]
	}
	return string(out), nil
}

// formatRecoveryCode groups a code for display and transcription. The dashes
// are cosmetic — parseRecoveryCode strips them — but a sixteen-character run
// with no landmarks is transcribed wrongly far more often.
func formatRecoveryCode(code string) string {
	var b strings.Builder
	for i, c := range code {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// parseRecoveryCode normalises whatever the user typed into a selector and a
// verifier.
//
// It is forgiving on purpose. Someone entering a recovery code has just lost
// their authenticator, is reading from a screenshot or a printout, and is
// unlikely to reproduce the dashes or the case exactly. The characters excluded
// from the alphabet are mapped to the ones they are mistaken for rather than
// rejected, so a code written down as "O" instead of "0" still works. None of
// this weakens anything: the alphabet has no member that any of these map away
// from, so the mapping is unambiguous.
func parseRecoveryCode(input string) (selector, verifier string, err error) {
	var b strings.Builder
	for _, c := range strings.ToUpper(strings.TrimSpace(input)) {
		switch c {
		case 'I', 'L':
			b.WriteByte('1')
		case 'O':
			b.WriteByte('0')
		case 'U':
			b.WriteByte('V')
		default:
			if strings.ContainsRune(recoveryAlphabet, c) {
				b.WriteRune(c)
			}
			// Anything else — dashes, spaces, punctuation — is dropped.
		}
	}
	normalised := b.String()
	if len(normalised) != recoveryCodeLen {
		return "", "", errMalformedRecoveryCode
	}
	return normalised[:recoverySelectorLen], normalised[recoverySelectorLen:], nil
}

// hashRecoveryVerifier and verifyRecoveryVerifier use the same argon2id
// parameters and the same encoding as est_credential.secret_hash
// (internal/est/service.go). They are duplicated rather than shared because the
// two packages have no dependency on one another and the parameters are a
// deliberate per-use decision, not a global constant: if EST's cost is ever
// retuned for its own reasons, this must not silently follow.
func hashRecoveryVerifier(verifier string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(verifier), salt, 2, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + "." + base64.RawStdEncoding.EncodeToString(sum), nil
}

func verifyRecoveryVerifier(encoded, verifier string) bool {
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[0])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[1])
	if e1 != nil || e2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(verifier), salt, 2, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
