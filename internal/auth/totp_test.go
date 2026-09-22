package auth

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// rfc6238Secret is the seed from RFC 6238 appendix B, "12345678901234567890",
// in the base32 form an authenticator is given.
var rfc6238Secret = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

// TestVerifyTOTPMatchesRFC6238 pins this package against the published test
// vectors rather than against the library that happens to implement it. The
// vectors are the contract every authenticator application also implements; if
// a dependency bump, a parameter change, or a hand-rolled replacement ever
// disagreed with them, every user's authenticator would start producing codes
// the server rejects, and the failure would present as "2FA is broken" with
// nothing pointing at the cause.
//
// The SHA1 rows are the ones that matter: totpAlgo is SHA1, deliberately.
func TestVerifyTOTPMatchesRFC6238(t *testing.T) {
	// Time, and the eight-digit code RFC 6238 says HMAC-SHA1 must produce. The
	// implementation here uses six digits, so each expectation is the last six.
	cases := []struct {
		unix int64
		want string
	}{
		{unix: 59, want: "287082"},
		{unix: 1111111109, want: "081804"},
		{unix: 1111111111, want: "050471"},
		{unix: 1234567890, want: "005924"},
		{unix: 2000000000, want: "279037"},
		{unix: 20000000000, want: "353130"},
	}
	for _, tc := range cases {
		at := time.Unix(tc.unix, 0)
		got, err := totp.GenerateCodeCustom(rfc6238Secret, at, totp.ValidateOpts{
			Period: totpPeriod, Digits: totpDigits, Algorithm: totpAlgo,
		})
		if err != nil {
			t.Fatalf("generating at %d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("code at %d = %s, want %s (RFC 6238 appendix B)", tc.unix, got, tc.want)
		}
		// And the verifier accepts the code the vector says it should.
		if _, ok := verifyTOTP(rfc6238Secret, tc.want, at, 0); !ok {
			t.Errorf("verifyTOTP refused the RFC 6238 code %s at %d", tc.want, tc.unix)
		}
	}
}

// TestVerifyTOTPRefusesAReplay is the property last_step exists for. A code
// stays arithmetically valid for its whole step, so without this a code captured
// in transit — by a phishing proxy, over a shoulder, from a screenshot — can be
// used again by whoever captured it, inside the same window the real user just
// used it in.
func TestVerifyTOTPRefusesAReplay(t *testing.T) {
	now := time.Unix(1111111109, 0)
	code, err := totp.GenerateCodeCustom(rfc6238Secret, now, totp.ValidateOpts{
		Period: totpPeriod, Digits: totpDigits, Algorithm: totpAlgo,
	})
	if err != nil {
		t.Fatalf("generating: %v", err)
	}

	step, ok := verifyTOTP(rfc6238Secret, code, now, 0)
	if !ok {
		t.Fatal("first use of a fresh code was refused")
	}
	// The caller stores step; the same code presented again must not verify.
	if _, ok := verifyTOTP(rfc6238Secret, code, now, step); ok {
		t.Error("a code accepted once was accepted again; last_step is not being honoured")
	}
}

// TestVerifyTOTPRefusesAnEarlierStep covers the subtler half of the same
// property. Accepting a code advances last_step past the whole skew window, so
// the previous step's code — still inside its tolerance, and still generatable
// by anyone who saw it — must also be refused.
func TestVerifyTOTPRefusesAnEarlierStep(t *testing.T) {
	now := time.Unix(1111111109, 0)
	opts := totp.ValidateOpts{Period: totpPeriod, Digits: totpDigits, Algorithm: totpAlgo}

	current := now.Unix() / totpPeriod
	previous, err := totp.GenerateCodeCustom(rfc6238Secret, time.Unix((current-1)*totpPeriod, 0), opts)
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	// Within the skew window, the previous step's code is accepted from scratch.
	if _, ok := verifyTOTP(rfc6238Secret, previous, now, 0); !ok {
		t.Fatal("a code one step old was refused; the skew window is not working")
	}
	// But not once the current step has been accepted.
	if _, ok := verifyTOTP(rfc6238Secret, previous, now, current); ok {
		t.Error("a code from before last_step was accepted; replay prevention is not monotonic")
	}
}

// TestVerifyTOTPSkewWindow states how much drift is tolerated, in both
// directions, and that it stops where it says it does.
func TestVerifyTOTPSkewWindow(t *testing.T) {
	now := time.Unix(1111111109, 0)
	opts := totp.ValidateOpts{Period: totpPeriod, Digits: totpDigits, Algorithm: totpAlgo}
	current := now.Unix() / totpPeriod

	for _, offset := range []int64{-1, 0, 1} {
		code, err := totp.GenerateCodeCustom(rfc6238Secret, time.Unix((current+offset)*totpPeriod, 0), opts)
		if err != nil {
			t.Fatalf("generating at offset %d: %v", offset, err)
		}
		if _, ok := verifyTOTP(rfc6238Secret, code, now, 0); !ok {
			t.Errorf("a code %d step(s) away was refused; one step of drift must be tolerated", offset)
		}
	}
	for _, offset := range []int64{-2, 2} {
		code, err := totp.GenerateCodeCustom(rfc6238Secret, time.Unix((current+offset)*totpPeriod, 0), opts)
		if err != nil {
			t.Fatalf("generating at offset %d: %v", offset, err)
		}
		if _, ok := verifyTOTP(rfc6238Secret, code, now, 0); ok {
			t.Errorf("a code %d steps away was accepted; the window must not be that wide", offset)
		}
	}
}

func TestVerifyTOTPRefusesGarbage(t *testing.T) {
	now := time.Unix(1111111109, 0)
	for _, code := range []string{"", "000000", "12345", "1234567", "abcdef", "  081804  "} {
		if _, ok := verifyTOTP(rfc6238Secret, code, now, 0); ok {
			t.Errorf("verifyTOTP accepted %q", code)
		}
	}
}

// TestNewTOTPKeyIsScannable checks the parameters an authenticator reads off the
// QR. Getting any of these wrong produces an enrolment that looks successful and
// then generates codes the server rejects forever.
func TestNewTOTPKeyIsScannable(t *testing.T) {
	key, err := newTOTPKey("alex@example.com")
	if err != nil {
		t.Fatalf("newTOTPKey: %v", err)
	}
	if key.Issuer() != "SimpleSCEP" {
		t.Errorf("issuer = %q, want SimpleSCEP", key.Issuer())
	}
	if key.AccountName() != "alex@example.com" {
		t.Errorf("account = %q, want the user's email", key.AccountName())
	}
	if key.Period() != totpPeriod {
		t.Errorf("period = %d, want %d", key.Period(), totpPeriod)
	}
	if key.Digits() != otp.DigitsSix {
		t.Errorf("digits = %v, want 6", key.Digits())
	}
	if key.Algorithm() != otp.AlgorithmSHA1 {
		t.Errorf("algorithm = %v, want SHA1; other algorithms silently fail in common authenticators", key.Algorithm())
	}
	// A code generated from the fresh secret must verify, which is the whole
	// round trip the user performs by hand at enrolment.
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generating from the new secret: %v", err)
	}
	if _, ok := verifyTOTP(key.Secret(), code, time.Now(), 0); !ok {
		t.Error("a code from a freshly minted key did not verify")
	}
}

// TestKeyFromSecretRoundTrips covers re-rendering an enrolment in progress. The
// page can be reloaded, so the secret must come back out of storage and produce
// the same credential — minting a new one on each load would invalidate whatever
// the user had already scanned.
func TestKeyFromSecretRoundTrips(t *testing.T) {
	original, err := newTOTPKey("alex@example.com")
	if err != nil {
		t.Fatalf("newTOTPKey: %v", err)
	}
	restored, err := keyFromSecret("alex@example.com", original.Secret())
	if err != nil {
		t.Fatalf("keyFromSecret: %v", err)
	}
	if restored.Secret() != original.Secret() {
		t.Errorf("restored secret = %q, want %q", restored.Secret(), original.Secret())
	}
	if restored.Period() != original.Period() || restored.Digits() != original.Digits() ||
		restored.Algorithm() != original.Algorithm() {
		t.Error("restored key does not carry the same parameters as the one that was scanned")
	}
}

// TestQRRendersPNG guards the response GET /auth/2fa/qr.png writes. It is the
// only way the secret reaches the user's phone, and an empty or malformed body
// presents as a blank box with no error anywhere.
func TestQRRendersPNG(t *testing.T) {
	key, err := newTOTPKey("alex@example.com")
	if err != nil {
		t.Fatalf("newTOTPKey: %v", err)
	}
	var buf writerRecorder
	if err := writeQR(&buf, key); err != nil {
		t.Fatalf("writeQR: %v", err)
	}
	if len(buf.b) < 100 {
		t.Fatalf("QR body is %d bytes; that is not an image", len(buf.b))
	}
	// PNG magic number.
	if string(buf.b[1:4]) != "PNG" {
		t.Errorf("QR body does not start with the PNG signature; got %q", buf.b[:8])
	}
}

type writerRecorder struct{ b []byte }

func (w *writerRecorder) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}
