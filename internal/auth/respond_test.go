package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

func configured(r *http.Request) *http.Request {
	return r.WithContext(toast.WithConfig(r.Context(), toast.Config{Secret: "secret"}))
}

// The status is the load-bearing part. These forms no longer carry an
// hx-target, so htmx defaults to the form itself; a 200 with an empty body
// would swap nothing into it and wipe what the person just typed. 204 is
// mapped to swap:false by htmx's default responseHandling.
func TestConfirmLeavesAnHTMXPageAlone(t *testing.T) {
	r := configured(httptest.NewRequest(http.MethodPost, "/login", nil))
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()

	confirm(w, r, toast.Info, loginAccepted, "/login")

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d so htmx does not swap over the form", w.Code, http.StatusNoContent)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", w.Body.String())
	}
	var trigger map[string]toast.Message
	if err := json.Unmarshal([]byte(w.Header().Get("HX-Trigger")), &trigger); err != nil {
		t.Fatalf("no toast on the confirmation: %v", err)
	}
	if trigger["toast"].Text != loginAccepted {
		t.Errorf("toast said %q", trigger["toast"].Text)
	}
}

// A plain form post has nothing listening, so the message has to outlive the
// response.
func TestConfirmSendsAPlainFormBackWithTheMessage(t *testing.T) {
	w := httptest.NewRecorder()
	confirm(w, configured(httptest.NewRequest(http.MethodPost, "/login", nil)),
		toast.Info, loginAccepted, "/login")

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if got := w.Header().Get("Location"); got != "/login" {
		t.Errorf("Location = %q", got)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == toast.CookieName && c.Value != "" {
			return
		}
	}
	t.Error("the page it lands on would say nothing")
}

// Every branch of POST /login says the same thing, and that is the whole point
// of it: a distinguishable response is a membership oracle over the user table.
// Moving the wording into a toast must not have introduced one.
func TestLoginSaysTheSameThingWhicheverBranchItTook(t *testing.T) {
	if loginAccepted == "" {
		t.Fatal("the uniform login response is empty")
	}
	// The handler's branches are exercised in routes_test; this pins the shape
	// the toast carries so a future edit cannot make one branch louder.
	r := configured(httptest.NewRequest(http.MethodPost, "/login", nil))
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	confirm(w, r, toast.Info, loginAccepted, "/login")

	if got := w.Header().Get("HX-Trigger"); !json.Valid([]byte(got)) {
		t.Fatalf("HX-Trigger is not JSON: %q", got)
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d; a status that varies by branch is an oracle", w.Code)
	}
}

// POST /login answers htmx with the confirmation itself, not with a toast over
// the form that asked. The form carries an hx-target now, so unlike confirm's
// 204 this is a 200 with a body — and the toast has to be gone, or the same
// sentence arrives twice.
func TestLoginSentReplacesTheFormRatherThanToasting(t *testing.T) {
	r := configured(httptest.NewRequest(http.MethodPost, "/login", nil))
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()

	loginSent(w, r, "you@company.com")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d so htmx swaps the confirmation in", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("HX-Trigger"); got != "" {
		t.Errorf("HX-Trigger = %q, want none: the confirmation is on the page now", got)
	}
	body := w.Body.String()
	if !strings.Contains(body, `id="login-form"`) {
		t.Errorf("the answer does not land where the form was: %q", body)
	}
	if strings.Contains(body, `name="email"`) {
		t.Error("the field that was just submitted came back with the confirmation")
	}
}

// A plain form post has nothing to swap, so it keeps the toast it always had:
// the browser is sent back to /login and the stored message is the only thing
// that survives the redirect.
func TestLoginSentKeepsTheToastForAPlainFormPost(t *testing.T) {
	w := httptest.NewRecorder()
	loginSent(w, configured(httptest.NewRequest(http.MethodPost, "/login", nil)), "you@company.com")

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == toast.CookieName && c.Value != "" {
			return
		}
	}
	t.Error("the page it lands on would say nothing")
}
