package home

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUnknownPathIsNotTheDashboard covers the catch-all.
//
// "GET /" is a prefix pattern in net/http's mux, so this handler is what answers
// every path no other route claims. It used to render the overview at 200, which
// meant a mistyped URL, a stale bookmark and a vulnerability scanner probing
// /wp-admin all came back as a successful dashboard — so a broken link inside the
// product was invisible and no 404 could ever be reported.
func TestUnknownPathIsNotTheDashboard(t *testing.T) {
	h := Handler{}
	for _, path := range []string{"/nonexistent", "/wp-admin", "/certificates/typo/extra"} {
		w := httptest.NewRecorder()
		h.overview(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want %d", path, w.Code, http.StatusNotFound)
		}
		if !strings.Contains(w.Body.String(), "does not exist") {
			t.Errorf("GET %s did not render the not-found page", path)
		}
	}
}

// TestUnknownPathAnswersHtmxWithoutAWholeDocument: htmx will not swap a non-2xx
// response, and swapping a full document into a fragment target would be worse
// than the toast it gets instead.
func TestUnknownPathAnswersHtmxWithoutAWholeDocument(t *testing.T) {
	h := Handler{}
	r := httptest.NewRequest("GET", "/nonexistent", nil)
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	h.overview(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Error("a whole document was returned to an htmx request")
	}
	if w.Header().Get("HX-Trigger") == "" {
		t.Error("no HX-Trigger, so htmx would show nothing at all")
	}
}
