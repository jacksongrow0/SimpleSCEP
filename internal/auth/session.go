package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	CookieName   = "auth"
	CookieDomain = "simplescep.com"
)

type Session struct {
	ID               string `json:"id"`
	UserID           string `json:"user_id"`
	OrgID            string `json:"org_id"`
	Name             string `json:"name"`
	Email            string `json:"email"`
	Role             string `json:"role"`
	OrganizationName string `json:"organization_name"`

	// SteppedUpAt is when this session last proved a second factor for a
	// high-blast-radius action. Nil means never.
	SteppedUpAt *time.Time `json:"stepped_up_at"`

	// ExpiryAlertsEnabled and ExpiryAlertDays are the organization's
	// certificate-expiry notification preference, carried so the account
	// dialog renders the stored state. They are the organization's setting
	// rather than this user's: the alert goes to every administrator.
	ExpiryAlertsEnabled bool `json:"expiry_alerts_enabled"`
	ExpiryAlertDays     int  `json:"expiry_alert_days"`
}

func (s Session) IsAdmin() bool {
	return s.Role == "administrator"
}

func (s Session) CanManageCertificates() bool {
	return s.Role == "administrator" || s.Role == "certificate_manager"
}

func (s Session) CanViewAudit() bool {
	return s.Role == "administrator" || s.Role == "auditor"
}

// StepUpGrace is how long a proved second factor authorises destructive actions.
//
// A grace rather than a prompt per action, because the friction has to stay in
// proportion to the work: retiring three superseded CAs in a row should cost one
// code, not three. Auth friction that is out of proportion gets routed around by
// the people subject to it — codes read aloud, authenticators screenshotted —
// and those workarounds are worse than the window this leaves open.
//
// What a per-action token would additionally defend against is same-origin XSS
// riding a legitimate step-up. Cross-origin is already covered by SameSite=Lax
// and the origin-checking CSRF middleware. Same-origin script running on a page
// that already holds an authenticated session can simply wait for the user to
// step up and then fire its own request with whatever token it just saw, so the
// token buys less than it looks like it does.
//
// If that ever needs tightening, the upgrade path is to bind stepped_up_at to a
// class of action rather than to shorten this.
const StepUpGrace = 5 * time.Minute

// SteppedUp reports whether this session proved a second factor recently enough
// to authorise a destructive action.
func (s Session) SteppedUp(now time.Time) bool {
	return s.SteppedUpAt != nil && now.Sub(*s.SteppedUpAt) < StepUpGrace
}

type contextKey struct{}

func WithSession(ctx context.Context, session Session) context.Context {
	return context.WithValue(ctx, contextKey{}, session)
}

func FromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(contextKey{}).(Session)
	return session, ok
}

func ReadCookie(r *http.Request, secret string) (string, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return "", err
	}
	value, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return "", err
	}
	sessionID, sig, ok := strings.Cut(value, ".")
	if !ok || !validSignature(sessionID, sig, secret) {
		return "", errors.New("invalid auth cookie")
	}
	return sessionID, nil
}

func SetCookie(w http.ResponseWriter, sessionID, secret string, expires time.Time) {
	value := sessionID + "." + signature(sessionID, secret)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    url.QueryEscape(value),
		Path:     "/",
		Domain:   CookieDomain,
		HttpOnly: true,
		Secure:   SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Domain:   CookieDomain,
		HttpOnly: true,
		Secure:   SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// SecureCookie is always true.
//
// It was configurable so that local development over plain HTTP kept its
// session, which browsers no longer need: http://localhost is treated as a
// secure context, so a Secure cookie is set and sent there like any other. What
// the variable did offer was a way to ship a production deployment that handed
// session cookies to unencrypted requests, one typo away from every login being
// readable on the wire.
func SecureCookie() bool {
	return true
}

// ChallengeCookieName holds a login_challenge id: a browser that has proved one
// factor and not yet the second.
//
// It is a separate cookie from CookieName, not a flag on it, and that separation
// is the whole design. An "auth" cookie means fully authenticated, exactly as it
// did before two-factor existed, so every route behind middleware.Auth is
// unreachable with only this one — not because something checks, but because
// there is nothing for the session lookup to find. A route added later inherits
// that for free.
const ChallengeCookieName = "mfa"

// challengeTTL is how long a half-finished login may sit. It is short: the user
// is in front of the screen with an authenticator in hand, and a challenge that
// outlived the tab would be a standing invitation to whoever next used the
// machine. Enrolment is included in that time, which is why it is not tighter —
// scanning a QR and typing the first code takes a minute or two.
const challengeTTL = 15 * time.Minute

// SetChallengeCookie stores the challenge id, signed with the same HMAC as the
// session cookie so a client cannot point itself at somebody else's challenge.
// The value is only a row id; everything that matters about the challenge —
// which user, which stage, how many attempts are left — stays in the database
// where the client cannot reach it.
func SetChallengeCookie(w http.ResponseWriter, challengeID, secret string, expires time.Time) {
	value := challengeID + "." + signature(challengeID, secret)
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    url.QueryEscape(value),
		Path:     "/",
		HttpOnly: true,
		Secure:   SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

// ReadChallengeCookie returns the challenge id a request carries, if the
// signature holds.
func ReadChallengeCookie(r *http.Request, secret string) (string, error) {
	cookie, err := r.Cookie(ChallengeCookieName)
	if err != nil {
		return "", err
	}
	value, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return "", err
	}
	challengeID, sig, ok := strings.Cut(value, ".")
	if !ok || !validSignature(challengeID, sig, secret) {
		return "", errors.New("invalid challenge cookie")
	}
	return challengeID, nil
}

// ClearChallengeCookie removes it. Called when the challenge is spent — whether
// it succeeded, expired, or ran out of attempts — so a browser is never left
// holding a reference to a row that no longer exists.
func ClearChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// RecoveryCookieName carries a freshly issued set of recovery codes across the
// one redirect between confirming an enrolment and the page that displays them.
//
// The codes used to be rendered straight into the response to POST
// /auth/2fa/enroll, which htmx swapped into the result line under the code
// field — a second page's worth of content wedged inside the card that asked
// for six digits. Showing them on their own page instead means the enrolment
// response has to navigate, and a navigation discards its own body, so the
// codes have to travel in something the next request carries.
//
// A cookie rather than a database row because these are display strings: the
// database holds only their hashes, by design, and storing the plaintext to
// support one redirect would undo that. It is signed like every other cookie
// here so that nobody can plant a set of codes for a user to write down and
// trust, HttpOnly so no script can read them back out, scoped to the single
// path that renders them, and short-lived and cleared on first read so it is
// not still sitting in the jar an hour later.
const RecoveryCookieName = "recovery"

// recoveryCookiePath is both where the cookie is sent and where it is cleared.
// The two must agree: a cookie set on one path is not removed by a deletion
// written for another.
const recoveryCookiePath = "/auth/recovery-codes"

// recoveryHandoffTTL bounds the walk from one page to the next. It is a
// redirect, so this is generous by two orders of magnitude already.
const recoveryHandoffTTL = 5 * time.Minute

// SetRecoveryCodesCookie hands the codes to the page that will show them.
func SetRecoveryCodesCookie(w http.ResponseWriter, codes []string, secret string) error {
	body, err := json.Marshal(codes)
	if err != nil {
		return err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	http.SetCookie(w, &http.Cookie{
		Name:     RecoveryCookieName,
		Value:    url.QueryEscape(payload + "." + signature(payload, secret)),
		Path:     recoveryCookiePath,
		HttpOnly: true,
		Secure:   SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(recoveryHandoffTTL.Seconds()),
	})
	return nil
}

// TakeRecoveryCodes reads the handed-off codes and clears them, so a reload of
// the page shows nothing rather than showing the codes again to whoever is
// sitting at the machine next.
func TakeRecoveryCodes(w http.ResponseWriter, r *http.Request, secret string) ([]string, bool) {
	cookie, err := r.Cookie(RecoveryCookieName)
	if err != nil {
		return nil, false
	}
	ClearRecoveryCodesCookie(w)
	value, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return nil, false
	}
	payload, sig, ok := strings.Cut(value, ".")
	if !ok || !validSignature(payload, sig, secret) {
		return nil, false
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, false
	}
	var codes []string
	if err := json.Unmarshal(body, &codes); err != nil || len(codes) == 0 {
		return nil, false
	}
	return codes, true
}

func ClearRecoveryCodesCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     RecoveryCookieName,
		Value:    "",
		Path:     recoveryCookiePath,
		HttpOnly: true,
		Secure:   SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// Sign and VerifySignature expose the cookie HMAC to other packages that need a
// tamper-evident value round-tripped through the browser, such as the Intune
// consent flow's PKCE state.
func Sign(value, secret string) string { return signature(value, secret) }

func VerifySignature(value, sig, secret string) bool { return validSignature(value, sig, secret) }

func signature(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validSignature(value, sig, secret string) bool {
	expected, err := base64.RawURLEncoding.DecodeString(signature(value, secret))
	got, err2 := base64.RawURLEncoding.DecodeString(sig)
	return err == nil && err2 == nil && hmac.Equal(got, expected)
}
