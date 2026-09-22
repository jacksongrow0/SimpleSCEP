package auth

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieIsSharedWithLandingPage(t *testing.T) {
	w := httptest.NewRecorder()
	SetCookie(w, "session-id", "secret", time.Now().Add(time.Hour))

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("SetCookie wrote %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Domain != CookieDomain {
		t.Errorf("session cookie domain = %q, want %q", cookie.Domain, CookieDomain)
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must remain HttpOnly")
	}
}

func TestClearSessionCookieUsesSharedDomain(t *testing.T) {
	w := httptest.NewRecorder()
	ClearCookie(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("ClearCookie wrote %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Domain != CookieDomain {
		t.Errorf("cleared session cookie domain = %q, want %q", cookie.Domain, CookieDomain)
	}
	if cookie.MaxAge >= 0 {
		t.Errorf("cleared session cookie MaxAge = %d, want a negative value", cookie.MaxAge)
	}
}

