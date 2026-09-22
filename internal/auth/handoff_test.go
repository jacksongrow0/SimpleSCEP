package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const handoffSecret = "handoff-test-secret"

// handoff runs SetRecoveryCodesCookie and returns a request carrying whatever
// it set, which is the whole journey the codes make: one Set-Cookie on the
// response to the enrolment, one Cookie header on the request for the page that
// displays them.
func handoff(t *testing.T, codes []string) *http.Request {
	t.Helper()
	w := httptest.NewRecorder()
	if err := SetRecoveryCodesCookie(w, codes, handoffSecret); err != nil {
		t.Fatalf("setting the handoff cookie: %v", err)
	}
	r := httptest.NewRequest("GET", "/auth/recovery-codes", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestRecoveryCodesSurviveTheRedirectToTheirOwnPage(t *testing.T) {
	codes := []string{"ABCD-EFGH-JKMN-PQRS", "0123-4567-89AB-CDEF"}
	got, ok := TakeRecoveryCodes(httptest.NewRecorder(), handoff(t, codes), handoffSecret)
	if !ok {
		t.Fatal("the codes did not survive the redirect")
	}
	if strings.Join(got, ",") != strings.Join(codes, ",") {
		t.Errorf("codes = %v, want %v", got, codes)
	}
}

// Once means once. The read clears the cookie, so a reload — or the next person
// at this machine pressing back — finds nothing to show.
func TestTakingTheCodesClearsThem(t *testing.T) {
	r := handoff(t, []string{"ABCD-EFGH-JKMN-PQRS"})
	w := httptest.NewRecorder()
	if _, ok := TakeRecoveryCodes(w, r, handoffSecret); !ok {
		t.Fatal("the codes did not arrive")
	}
	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == RecoveryCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the handoff cookie was read but not cleared")
	}
}

// The signature is what stops someone planting a set of codes for a user to
// write down and rely on. A forged or re-signed cookie has to read as nothing
// at all rather than as somebody's recovery codes.
func TestForgedCodesAreNotShown(t *testing.T) {
	valid := handoff(t, []string{"ABCD-EFGH-JKMN-PQRS"})
	cookie, err := valid.Cookie(RecoveryCookieName)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"a different signing key": cookie.Value,
		"no signature":            strings.Split(cookie.Value, ".")[0],
		"an altered payload":      "AAAA" + cookie.Value,
		"nonsense":                "not-a-cookie",
	} {
		r := httptest.NewRequest("GET", "/auth/recovery-codes", nil)
		r.AddCookie(&http.Cookie{Name: RecoveryCookieName, Value: value})
		secret := handoffSecret
		if name == "a different signing key" {
			secret = "some-other-secret"
		}
		if got, ok := TakeRecoveryCodes(httptest.NewRecorder(), r, secret); ok {
			t.Errorf("%s was accepted, producing %v", name, got)
		}
	}
}

// The page itself: it renders the handed-off codes and nothing else can reach
// it. There is no copy on the server, so a caller without the cookie is not
// shown an empty card — it is sent to the dashboard.
func TestRecoveryCodesPageShowsTheHandoffAndNothingElse(t *testing.T) {
	h := Handler{secret: handoffSecret}

	w := httptest.NewRecorder()
	h.recoveryCodes(w, httptest.NewRequest("GET", "/auth/recovery-codes", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Errorf("without the handoff: %d to %q, want 303 to /", w.Code, w.Header().Get("Location"))
	}

	w = httptest.NewRecorder()
	h.recoveryCodes(w, handoff(t, []string{"ABCD-EFGH-JKMN-PQRS"}))
	if w.Code != http.StatusOK {
		t.Fatalf("with the handoff: status %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ABCD-EFGH-JKMN-PQRS") {
		t.Error("the page did not show the codes it was handed")
	}
}

// A browser that already holds a session has no use for either sign-in page,
// and /login in particular: the form there mails a link that would only lead
// back to where the browser already is.
func TestSignedInBrowsersAreSentToTheDashboard(t *testing.T) {
	h := Handler{secret: handoffSecret}
	ctx := WithSession(context.Background(), Session{ID: "s", UserID: "u", OrgID: "o"})

	for name, serve := range map[string]http.HandlerFunc{"login": h.login, "setup": h.setup, "2fa": h.twoFactor} {
		w := httptest.NewRecorder()
		serve(w, httptest.NewRequest("GET", "/login", nil).WithContext(ctx))
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
			t.Errorf("%s: %d to %q, want 303 to /", name, w.Code, w.Header().Get("Location"))
		}
	}

	// Without one it is the sign-in page, not a redirect loop.
	w := httptest.NewRecorder()
	h.login(w, httptest.NewRequest("GET", "/login", nil))
	if w.Code != http.StatusOK {
		t.Errorf("anonymous /login: status %d, want 200", w.Code)
	}
}
