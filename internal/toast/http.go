package toast

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Raising a toast takes one of two paths, and which one is not a matter of
// taste — htmx decides it.
//
// htmx's handleAjaxResponse processes HX-Trigger before it looks at the status
// code, which is why middleware.promptStepUp can raise a dialog from a 403 and
// why Fail below can report an error htmx would otherwise drop on the floor.
// But it processes HX-Redirect a few lines later by assigning location.href,
// and that navigation throws away anything the trigger just rendered. So a
// response that stays on the page carries its message in a header, and a
// response that navigates has to leave the message somewhere the *next* request
// will find it.
//
// That somewhere is a cookie rather than a query parameter. A query parameter
// costs a public URL shape, a validator, and a field on the view model for every
// message anyone ever wants to send. A cookie costs none of those and works
// identically for an HX-Redirect and for the plain 303 non-htmx forms get.
//
// All of this lives in this package rather than in internal/web, which is where
// the rest of the handler plumbing lives, because internal/web imports
// internal/auth and internal/auth needs to raise toasts too. This package
// imports nothing internal at all, so every handler can reach it and
// view/layout can read the result without dragging a cycle in behind it.

// CookieName holds a pending toast across one navigation.
const CookieName = "flash"

// cookieMaxAge is short on purpose. The cookie exists to survive a redirect,
// which takes milliseconds; anything still holding one thirty seconds later is
// a message about an action the user has stopped thinking about, and showing it
// then is worse than not showing it.
const cookieMaxAge = 30

// Config is what this package cannot work out for itself: the key to sign a
// flash with, and whether this deployment's cookies are Secure.
//
// It arrives on the request rather than through a constructor. Threading one
// more argument into pki.Handler, scep.Handler, acme.Handler, est.Handler,
// authentication and administration handlers — and through every
// NewHandler and RegisterRoutes on the way — would be a large diff for a value
// that is the same for the whole process and is already held by the middleware
// that owns this channel. It is also the reason neither field is read from the
// environment here: AUTH_SECRET is internal/auth's to interpret, and a second
// reader of a security default is a second thing to get wrong. middleware.Flash asks internal/auth and puts the answers here.
type Config struct {
	Secret       string
	SecureCookie bool
}

type configKey struct{}

// WithConfig carries the cookie settings on a request.
func WithConfig(ctx context.Context, c Config) context.Context {
	return context.WithValue(ctx, configKey{}, c)
}

func configFrom(r *http.Request) (Config, bool) {
	c, ok := r.Context().Value(configKey{}).(Config)
	return c, ok && c.Secret != ""
}

// Now raises a toast on a response that stays on the page.
//
// Safe to call before any status: htmx reads the header before it decides
// whether to swap. The event name carries no hyphen for the same reason
// `stepup` does not — see view/layout/scripts.go.
//
// A non-htmx caller gets nothing, because there is nothing listening: the
// browser is about to replace the current page with this response, so the
// message has to be in the body.
func Now(w http.ResponseWriter, r *http.Request, tone Tone, text string) {
	if r.Header.Get("HX-Request") != "true" {
		return
	}
	m := New(tone, text)
	if !m.Valid() {
		return
	}
	trigger, err := json.Marshal(map[string]Message{"toast": m})
	if err != nil {
		return
	}
	w.Header().Set("HX-Trigger", string(trigger))
}

// Announce stores a message for the next page load. Pair it with a redirect.
func Announce(w http.ResponseWriter, r *http.Request, tone Tone, text string) {
	c, ok := configFrom(r)
	if !ok {
		// No middleware, so no signing key. The redirect still happens; the
		// caller simply gets the silence it had before any of this existed.
		return
	}
	setCookie(w, c, New(tone, text))
}

// Fail reports a refusal and writes the status.
//
// The status is the real one. This is not another FormError answering 200 so a
// swap will happen: htmx handles the trigger header regardless of status, so
// the message arrives and the response stays honest to anything else reading
// it.
func Fail(w http.ResponseWriter, r *http.Request, status int, text string) {
	Now(w, r, Error, text)
	http.Error(w, text, status)
}

// Take reads the pending message and clears it, so one action produces one
// toast rather than one per page until the cookie expires.
func Take(w http.ResponseWriter, r *http.Request) (Message, bool) {
	c, ok := configFrom(r)
	if !ok {
		return Message{}, false
	}
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return Message{}, false
	}
	clearCookie(w, c)
	value, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return Message{}, false
	}
	payload, sig, ok := strings.Cut(value, ".")
	if !ok || !validSignature(payload, sig, c.Secret) {
		return Message{}, false
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Message{}, false
	}
	var m Message
	if err := json.Unmarshal(body, &m); err != nil {
		return Message{}, false
	}
	// Re-normalised on the way out rather than trusted: what arrives here has
	// been through the browser, and a valid signature proves only that this
	// application wrote it, not that the code which wrote it bounded the text.
	m = New(m.Tone, m.Text)
	return m, m.Valid()
}

// setCookie stores the message, signed.
//
// The signature is not ceremony. This is text the application renders into the
// corner of an authenticated page of a product that holds certificate authority
// keys; unsigned, anyone able to set a cookie could put their own sentence
// there — "your session expired, call this number" — which is a phishing
// surface rather than a cosmetic bug.
func setCookie(w http.ResponseWriter, c Config, m Message) {
	if !m.Valid() {
		return
	}
	body, err := json.Marshal(m)
	if err != nil {
		return
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    url.QueryEscape(payload + "." + signature(payload, c.Secret)),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cookieMaxAge,
	})
}

func clearCookie(w http.ResponseWriter, c Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   c.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// signature and validSignature mirror internal/auth's cookie HMAC. They are not
// a call into it: this package imports nothing internal, which is what lets
// view/layout read a message without an import cycle.
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
