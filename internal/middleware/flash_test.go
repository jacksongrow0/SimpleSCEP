package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

// The race this guards against is the reason rendersPage exists. Every asset on
// a page load carries the same cookie, and the file server sits inside this
// middleware, so whichever request arrived first would consume the message.
func TestOnlyAPageConsumesTheFlash(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		accept  string
		htmx    bool
		expects bool
	}{
		{"a page", http.MethodGet, "/certificate-authorities", "text/html,application/xhtml+xml", false, true},
		{"a stylesheet", http.MethodGet, "/static/app.css", "text/css,*/*;q=0.1", false, false},
		{"a script", http.MethodGet, "/static/toast.js", "*/*", false, false},
		{"an image", http.MethodGet, "/auth/2fa/qr.png", "image/avif,image/webp,*/*", false, false},
		// An htmx GET accepts HTML but renders a fragment into a page that is
		// already on screen, never the shell that holds the toast region.
		{"an htmx fragment", http.MethodGet, "/security/panel", "text/html", true, false},
		{"a form post", http.MethodPost, "/certificate-authorities", "text/html", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got bool
			h := Flash("secret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, got = toast.FromContext(r.Context())
			}))

			// The cookie a redirect would have left behind.
			issued := httptest.NewRecorder()
			seed := httptest.NewRequest(http.MethodPost, "/x", nil)
			toast.Announce(issued, seed.WithContext(
				toast.WithConfig(seed.Context(), toast.Config{Secret: "secret"})), toast.Success, "Deleted")

			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Accept", tc.accept)
			if tc.htmx {
				r.Header.Set("HX-Request", "true")
			}
			for _, c := range issued.Result().Cookies() {
				r.AddCookie(c)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)

			if got != tc.expects {
				t.Errorf("consumed the flash = %v, want %v", got, tc.expects)
			}
		})
	}
}

// Every request carries the config, not only the ones that render, because it
// is what lets a mutating POST sign the message it leaves behind.
func TestEveryRequestCanRaiseAFlash(t *testing.T) {
	var wrote bool
	h := Flash("secret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		toast.Announce(w, r, toast.Success, "Endpoint deleted")
		wrote = true
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/scep/endpoints/x/delete", nil))

	if !wrote {
		t.Fatal("handler did not run")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == toast.CookieName && c.Value != "" {
			return
		}
	}
	t.Error("a mutating POST could not store a message for the page it redirects to")
}
