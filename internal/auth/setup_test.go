package auth

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testSetupToken = "test-setup-token"

func setupRequest(form url.Values) *http.Request {
	values := url.Values{}
	maps.Copy(values, form)
	values.Set("token", testSetupToken)
	r := httptest.NewRequest("POST", "/setup", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func setupHandler() Handler { return Handler{setupToken: testSetupToken} }

func TestSetupValidatesRequiredFields(t *testing.T) {
	w := httptest.NewRecorder()
	setupHandler().completeSetup(w, setupRequest(url.Values{
		"name": {"Alex Morgan"}, "organization": {"Acme, Inc."},
	}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "email") {
		t.Errorf("setup without an email returned %d: %q", w.Code, w.Body.String())
	}
}

func TestSetupRejectsAWrongOrMissingToken(t *testing.T) {
	valid := url.Values{"name": {"Alex Morgan"}, "email": {"alex@example.com"}, "organization": {"Acme, Inc."}}
	for name, token := range map[string]string{"missing": "", "wrong": "not-the-token"} {
		form := url.Values{}
		maps.Copy(form, valid)
		form.Set("token", token)
		r := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		setupHandler().completeSetup(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s token: status = %d, want %d", name, w.Code, http.StatusForbidden)
		}
	}
	w := httptest.NewRecorder()
	Handler{}.completeSetup(w, setupRequest(valid))
	if w.Code != http.StatusForbidden {
		t.Errorf("a handler with no setup token accepted a request: status = %d", w.Code)
	}
}
