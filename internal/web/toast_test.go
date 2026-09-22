package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

func configured(method, path string, htmx bool) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if htmx {
		r.Header.Set("HX-Request", "true")
	}
	return r.WithContext(toast.WithConfig(r.Context(), toast.Config{Secret: "secret"}))
}

func flash(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == toast.CookieName && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// The header order in htmx's handleAjaxResponse is why the message cannot ride
// an HX-Trigger here: the trigger is processed, and then HX-Redirect assigns
// location.href and throws the rendered toast away. Both halves have to be on
// this response.
func TestDoneLeavesTheMessageForThePageItRedirectsTo(t *testing.T) {
	w := httptest.NewRecorder()
	Done(w, configured(http.MethodPost, "/api/scep/endpoints/x/delete", true), "/protocols", "Endpoint deleted")

	if got := w.Header().Get("HX-Redirect"); got != "/protocols" {
		t.Errorf("HX-Redirect = %q, want /protocols", got)
	}
	if flash(w) == "" {
		t.Error("no flash cookie, so the page htmx navigates to would say nothing")
	}
}

func TestDoneUsesAPlainRedirectForAPlainForm(t *testing.T) {
	w := httptest.NewRecorder()
	Done(w, configured(http.MethodPost, "/certificate-authorities/x/delete", false), "/certificate-authorities", "Deleted")

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if got := w.Header().Get("Location"); got != "/certificate-authorities" {
		t.Errorf("Location = %q", got)
	}
	if flash(w) == "" {
		t.Error("the plain-form path is the one with no other channel at all, and it carries no message")
	}
}

// The refusal keeps its real status. This is the whole point of the header
// route: htmx 2 will not swap a non-2xx body, so before this the user saw
// nothing at all.
func TestFailKeepsTheStatusAndStillReaches(t *testing.T) {
	w := httptest.NewRecorder()
	Fail(w, configured(http.MethodPost, "/certificate-authorities/x/status", true),
		http.StatusConflict, "Disable its SCEP endpoints first")

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
	if w.Header().Get("HX-Trigger") == "" {
		t.Error("the refusal carries no toast")
	}
	if flash(w) != "" {
		t.Error("a refusal that does not navigate should not leave a cookie behind")
	}
}
