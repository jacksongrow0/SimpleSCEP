package toast

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const secret = "test-secret"

func request(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/anything", nil)
	return r.WithContext(WithConfig(r.Context(), Config{Secret: secret}))
}

func TestNewBoundsAndDefaults(t *testing.T) {
	if got := New("shouting", "hello").Tone; got != Info {
		t.Errorf("unrecognised tone = %q, want it to fall back to info", got)
	}
	// A multi-byte body, so a naive byte slice would cut a rune in half and put
	// a replacement character on the page.
	long := strings.Repeat("é", MaxText*2)
	m := New(Success, long)
	if n := len([]rune(m.Text)); n > MaxText {
		t.Errorf("message kept %d runes, want at most %d", n, MaxText)
	}
	if !strings.HasSuffix(m.Text, "…") {
		t.Error("a truncated message does not say it was truncated")
	}
	if !json.Valid(mustJSON(t, m)) {
		t.Error("a truncated message does not survive JSON encoding")
	}
	if New(Success, "   ").Valid() {
		t.Error("a blank message is treated as a message")
	}
}

func mustJSON(t *testing.T, m Message) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// The trigger has to be a single named event whose payload htmx hands to the
// listener as event.detail, the same shape middleware.promptStepUp relies on.
func TestNowSendsOneNamedEventToHTMX(t *testing.T) {
	r := request(t)
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	Now(w, r, Success, "Endpoint paused")

	var trigger map[string]Message
	if err := json.Unmarshal([]byte(w.Header().Get("HX-Trigger")), &trigger); err != nil {
		t.Fatalf("HX-Trigger is not the JSON object htmx expects: %v", err)
	}
	if len(trigger) != 1 {
		t.Fatalf("HX-Trigger names %d events, want exactly one", len(trigger))
	}
	m, ok := trigger["toast"]
	if !ok {
		t.Fatalf("HX-Trigger does not name the toast event: %v", trigger)
	}
	if m.Text != "Endpoint paused" || m.Tone != Success {
		t.Errorf("trigger payload = %+v", m)
	}
	// A hyphen in the event name would tokenise as subtraction in hyperscript
	// and install none of the listening element's script. See
	// view/layout/scripts.go.
	if strings.Contains("toast", "-") {
		t.Error("the event name contains a hyphen")
	}
}

// The header is the only way a refusal reaches the screen, because htmx 2 will
// not swap a non-2xx body.
func TestFailReportsTheRealStatusAndStillSpeaks(t *testing.T) {
	r := request(t)
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	Fail(w, r, http.StatusConflict, "Disable its endpoints first")

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
	if !strings.Contains(w.Header().Get("HX-Trigger"), "Disable its endpoints first") {
		t.Error("a refusal carries no toast, so htmx would drop it silently")
	}
}

func TestNowIsSilentForANonHTMXCaller(t *testing.T) {
	w := httptest.NewRecorder()
	Now(w, request(t), Success, "Saved")
	if w.Header().Get("HX-Trigger") != "" {
		t.Error("a plain form post is about to navigate; nothing is listening for a trigger")
	}
}

// The round trip a redirect depends on.
func TestFlashSurvivesOneNavigationAndOnlyOne(t *testing.T) {
	w := httptest.NewRecorder()
	Announce(w, request(t), Warning, "Two lists were not published")

	next := carrying(t, w)
	got, ok := Take(httptest.NewRecorder(), next)
	if !ok {
		t.Fatal("the message did not survive the redirect")
	}
	if got.Tone != Warning || got.Text != "Two lists were not published" {
		t.Errorf("message = %+v", got)
	}

	// Taking it must clear it, or every page until the cookie expires would
	// repeat the same toast.
	cleared := httptest.NewRecorder()
	Take(cleared, next)
	if !clearsCookie(cleared) {
		t.Error("reading the flash does not clear it")
	}
}

func TestATamperedFlashIsDiscarded(t *testing.T) {
	w := httptest.NewRecorder()
	Announce(w, request(t), Info, "harmless")

	forged := forge(t, w, "eyJ0b25lIjoiZXJyb3IiLCJ0ZXh0IjoiWW91ciBzZXNzaW9uIGV4cGlyZWQsIGNhbGwgdXMifQ")
	if _, ok := Take(httptest.NewRecorder(), forged); ok {
		t.Error("a message with a broken signature was rendered; anyone who can set a cookie could put words on the dashboard")
	}
}

func TestNoConfigMeansNoFlashRatherThanAnUnsignedOne(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/anything", nil)
	w := httptest.NewRecorder()
	Announce(w, r, Success, "Saved")
	if len(w.Result().Cookies()) != 0 {
		t.Error("a handler running without middleware.Flash wrote an unsigned cookie")
	}
}

// carrying builds the follow-up request the browser would send, carrying
// whatever cookie the recorder was given.
func carrying(t *testing.T, w *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/somewhere", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	return r.WithContext(WithConfig(r.Context(), Config{Secret: secret}))
}

// forge replaces the payload while keeping the signature that was issued for a
// different one.
func forge(t *testing.T, w *httptest.ResponseRecorder, payload string) *http.Request {
	t.Helper()
	r := carrying(t, w)
	c, err := r.Cookie(CookieName)
	if err != nil {
		t.Fatalf("no flash cookie to forge: %v", err)
	}
	_, sig, _ := strings.Cut(c.Value, ".")
	c.Value = payload + "." + sig
	forged := httptest.NewRequest(http.MethodGet, "/somewhere", nil)
	forged.AddCookie(c)
	return forged.WithContext(WithConfig(forged.Context(), Config{Secret: secret}))
}

func clearsCookie(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestContextRoundTrip(t *testing.T) {
	ctx := WithMessage(t.Context(), New(Success, "Saved"))
	m, ok := FromContext(ctx)
	if !ok || m.Text != "Saved" {
		t.Fatalf("FromContext = %+v, %v", m, ok)
	}
	if _, ok := FromContext(t.Context()); ok {
		t.Error("a request with no message reports one")
	}
	if _, ok := FromContext(WithMessage(t.Context(), New(Success, ""))); ok {
		t.Error("an empty message would render an empty toast")
	}
}
