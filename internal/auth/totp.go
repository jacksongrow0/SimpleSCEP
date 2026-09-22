package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"image/png"
	"io"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Protector seals a secret that has to be recovered later, as opposed to one
// that is only ever checked against a guess. pki.KeyProvider satisfies it; it is
// declared here rather than imported because pki depends on this package for
// auth.Session, so importing it back would be a cycle. Same reason as
// CustomerUpdater and Limiter in handler.go.
type Protector interface {
	Protect(ctx context.Context, purpose string, plaintext []byte) ([]byte, error)
	Unprotect(ctx context.Context, purpose string, ciphertext []byte) ([]byte, error)
}

// errNoProtector is what a Handler built without a key provider returns. It is
// an error rather than a panic, and rather than a silent plaintext fallback,
// because the only correct response to "we cannot seal this secret" is to
// refuse the enrolment.
var errNoProtector = errors.New("no key provider configured; cannot seal a second-factor secret")

// TOTP parameters. These are not tuning knobs: they are what every authenticator
// application assumes when it scans a QR code, and an app that disagrees simply
// shows the user a code the server will reject.
//
// SHA1 is not a security decision here and should not be "upgraded". HMAC-SHA1
// is unbroken as a message authentication code, which is all RFC 6238 asks of
// it; the collision attacks that retired SHA1 for signatures do not apply. It is
// also the only algorithm every authenticator supports — several popular ones
// silently derive the wrong code from an otpauth:// URI advertising SHA256,
// which presents to the user as "the app is broken" with no way to diagnose it.
const (
	totpPeriod = 30
	totpDigits = otp.DigitsSix
	totpAlgo   = otp.AlgorithmSHA1
	// totpSkew is how many steps either side of now are accepted, so one step of
	// clock drift or of a user typing slowly does not fail. Combined with the
	// replay guard below, a wider window costs nothing in reuse: a code accepted
	// at step t makes every step at or below t permanently unusable.
	totpSkew = 1
)

// mfaIssuer is the label an authenticator shows beside the code.
//
// Constant, and unconfigurable for a reason beyond tidiness: it is baked into
// the credential at the moment it is scanned, so changing it renames nothing
// already enrolled. A variable here could only ever produce an account list
// where the same service appears under two names.
func mfaIssuer() string {
	return "SimpleSCEP"
}

// newTOTPKey mints an unenrolled credential for one user. The returned key
// carries the secret and renders both the otpauth:// URI and the QR image.
func newTOTPKey(email string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      mfaIssuer(),
		AccountName: email,
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   totpAlgo,
		// 20 bytes is the RFC 4226 recommendation and what every authenticator
		// expects; the library's default is smaller.
		SecretSize: 20,
	})
}

// keyFromSecret rebuilds a key from a stored base32 secret so the QR and URI can
// be re-rendered for an enrolment still in progress, without minting a new
// secret each time the page is loaded — which would mean the code the user just
// scanned no longer matched.
func keyFromSecret(email, secret string) (*otp.Key, error) {
	return otp.NewKeyFromURL(fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=%d",
		urlEscape(mfaIssuer()), urlEscape(email), secret, urlEscape(mfaIssuer()), totpPeriod))
}

// writeQR renders the key as a PNG. Server-side rather than as a JavaScript
// widget because there is no JavaScript to add under this application's
// self-hosted-asset rule, and as its own response rather than as a data: URI
// because a data: URI would put the shared secret into the HTML body — into
// view-source, into any intermediary that buffers HTML, and into htmx's swap
// history. The response that carries it is marked no-store.
func writeQR(w io.Writer, key *otp.Key) error {
	img, err := key.Image(240, 240)
	if err != nil {
		return err
	}
	return png.Encode(w, img)
}

// verifyTOTP reports which RFC 6238 time step a code matched.
//
// It exists instead of totp.Validate, which answers only yes or no, because the
// step is what makes replay prevention possible: the caller advances the stored
// last_step to the returned value, and a code from that step or any earlier one
// is refused from then on — even while it is still inside its own validity
// window. Without this, a code read over a shoulder or captured by a phishing
// proxy stays usable for the rest of its thirty seconds, which is exactly the
// window such an attack operates in.
//
// Steps at or below lastStep are skipped rather than compared, so a replayed
// code costs no HMAC work at all.
func verifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	current := now.Unix() / totpPeriod
	opts := totp.ValidateOpts{Period: totpPeriod, Digits: totpDigits, Algorithm: totpAlgo}

	for offset := int64(-totpSkew); offset <= totpSkew; offset++ {
		step := current + offset
		if step <= lastStep {
			continue
		}
		at := time.Unix(step*totpPeriod, 0)
		expected, err := totp.GenerateCodeCustom(secret, at, opts)
		if err != nil {
			return 0, false
		}
		// Constant-time despite the value being public knowledge for thirty
		// seconds: the comparison runs against an attacker-supplied string, and a
		// byte-at-a-time early exit is a well-trodden way to turn a 10^6 search
		// into a 6*10 one.
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// firstTOTPLabel names the authenticator registered during sign-in enrolment.
//
// That page does not ask for a name and should not start to: it is the one
// moment a user cannot skip, under a thirty-second clock, and a field there buys
// a nicer list entry at the cost of friction in the only mandatory step in the
// product. Anything registered afterwards is named from the settings panel,
// where naming it is the point.
const firstTOTPLabel = "Authenticator app"

// totpLabel cleans up the name a user gives an authenticator. Display only and
// never used to look one up, exactly like passkeyLabel.
func totpLabel(raw string) string {
	label := strings.TrimSpace(raw)
	if label == "" {
		return firstTOTPLabel
	}
	if len(label) > 64 {
		label = label[:64]
	}
	return label
}

// matchTOTP finds which of a user's authenticators produced a code, and at which
// RFC 6238 time step.
//
// A user holds a set, so a code has to be offered to each of them in turn: the
// person typing knows which device they read it from and the server does not.
// The cost is one HMAC per credential per accepted step, which is nothing beside
// the round-trip that delivered the request.
//
// Each credential's own last_step bounds its own search, so a code accepted on
// one device never makes a code from another look replayed. The caller still has
// to advance the returned credential's step for the guard to mean anything —
// this function reports a match and changes nothing.
//
// A secret that cannot be opened is skipped rather than fatal, because one
// unreadable row must not lock a user out of an account whose other
// authenticators are fine. If none of them opens, the key provider is the
// problem and that error is returned rather than reported as a wrong code.
func (h Handler) matchTOTP(ctx context.Context, userID uuid.UUID, code string) (uuid.UUID, int64, error) {
	credentials, err := h.repo.TOTPCredentials(ctx, userID)
	if err != nil {
		return uuid.Nil, 0, err
	}
	if len(credentials) == 0 {
		return uuid.Nil, 0, sql.ErrNoRows
	}
	now := time.Now()
	var opened int
	var lastErr error
	for _, credential := range credentials {
		secret, err := unprotectTOTPSecret(ctx, h.protect, totpPurpose(userID.String()), credential.Secret)
		if err != nil {
			log.Printf("opening totp secret %s: %v", credential.ID, err)
			lastErr = err
			continue
		}
		opened++
		if step, valid := verifyTOTP(secret, code, now, credential.LastStep); valid {
			return credential.ID, step, nil
		}
	}
	if opened == 0 {
		return uuid.Nil, 0, lastErr
	}
	return uuid.Nil, 0, errInvalidCode
}

// urlEscape is the small subset of escaping an otpauth label needs. Issuer and
// account name are the two fields that can contain a colon or a space, which
// would otherwise split the label.
func urlEscape(s string) string {
	return (&url.URL{Path: s}).EscapedPath()
}

// protectTOTPSecret and unprotectTOTPSecret seal and open a secret under a
// purpose bound to whoever owns it. The purpose becomes additional authenticated
// data inside the key provider, so a ciphertext moved from one row to another
// fails to open rather than opening as someone else's factor.
func protectTOTPSecret(ctx context.Context, p Protector, purpose, secret string) ([]byte, error) {
	if p == nil {
		return nil, errNoProtector
	}
	return p.Protect(ctx, purpose, []byte(secret))
}

func unprotectTOTPSecret(ctx context.Context, p Protector, purpose string, sealed []byte) (string, error) {
	if p == nil {
		return "", errNoProtector
	}
	plain, err := p.Unprotect(ctx, purpose, sealed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// totpPurpose, enrollPurpose and sessionEnrollPurpose name what a sealed secret
// is for. An enrolment in progress is bound to whatever authorised it — a login
// challenge, or a session — and a confirmed credential to its user, so the
// promotion from one to the other is a re-seal rather than a copy: an abandoned
// enrolment's ciphertext cannot be replayed as a confirmed credential.
//
// The two enrolment purposes are separate namespaces so that a ciphertext parked
// by one path cannot be promoted through the other, which is the same reason
// they are separate from totpPurpose.
func totpPurpose(userID string) string        { return "totp:" + userID }
func enrollPurpose(challengeID string) string { return "totp-enroll:" + challengeID }
func sessionEnrollPurpose(sessionID string) string {
	return "totp-enroll:session:" + sessionID
}
