package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

const testID = "22222222-2222-2222-2222-222222222222"

// registeredPatterns collects every route pattern the application registers, by
// reading the source rather than by building a mux.
//
// Building the real mux would be the more direct check, but it cannot be done
// from this package: internal/scep, internal/acme and internal/est all import
// this one for RateLimiter, so importing them back is an import cycle. Reading
// the source has a compensating advantage — it sees routes this package could
// not otherwise reach, and it cannot be fooled by a registration that is
// conditional at runtime.
//
// http.ServeMux exposes no way to enumerate what has been registered, so there
// is no third option.
func registeredPatterns(t *testing.T) map[string]string {
	t.Helper()
	// Patterns are always string literals in a mux.Handle/HandleFunc call.
	call := regexp.MustCompile(`mux\.Handle(?:Func)?\(\s*"((?:GET|POST|PUT|DELETE|HEAD|OPTIONS) [^"]+)"`)

	found := map[string]string{}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Generated jet models and node_modules hold no routes and are large.
			if name := d.Name(); name == ".jet" || name == "node_modules" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range call.FindAllSubmatch(src, -1) {
			found[string(m[1])] = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning for routes: %v", err)
	}
	if len(found) < 20 {
		t.Fatalf("found only %d routes; the scan is broken and every check below "+
			"would pass vacuously", len(found))
	}
	return found
}

// TestStepUpPatternsAreRegistered is what keeps the allowlist honest. A pattern
// that no longer exists guards nothing, silently — an unmatched key in a map
// simply never fires — so a rename in another package would quietly drop the
// confirmation from a destructive route.
func TestStepUpPatternsAreRegistered(t *testing.T) {
	registered := registeredPatterns(t)
	for pattern := range stepUpPatterns {
		if _, ok := registered[pattern]; !ok {
			t.Errorf("step-up guards %q, but no route registers that pattern. "+
				"It was renamed or removed, and the guard no longer applies to anything", pattern)
		}
	}
}

// TestEveryDestructiveShapeIsGuarded turns the allowlist into a deny-by-shape
// check for the categories that exist today.
//
// An allowlist cannot be fail-closed for a route nobody thought to add, which is
// the one weakness of keying the guard by pattern. This closes most of that gap:
// anything that deletes, rotates, or changes a role must either be guarded or
// be exempted here, out loud, with a reason.
func TestEveryDestructiveShapeIsGuarded(t *testing.T) {
	destructive := regexp.MustCompile(
		`/delete$|/rotate$|/role$` +
			// The issuance shapes. A route that mints an enrollment credential or
			// signs a certificate belongs in the allowlist for the same reason a
			// delete does, and it is easier to add one of these without noticing:
			// it reads as ordinary provisioning rather than as destruction.
			`|/credentials$|/challenges$|/auth/static$|^POST /certificates/`)

	// Each exemption is a claim that the action is recoverable or narrow. Anything
	// added here should be arguable out loud rather than quietly.
	exempt := map[string]string{
		// Abandons a half-finished import. The key version it destroys has never
		// signed anything and anchors no trust. Confirming it would train people
		// to type codes for something inconsequential, which is how a
		// confirmation prompt stops being read.
		"POST /certificate-authorities/import/{id}/cancel": "abandons an unfinished import",
		// Deleting an enrollment endpoint stops future enrollments. It revokes
		// nothing, destroys no key material, and certificates already issued stay
		// valid; the endpoint can be recreated.
		"POST /api/scep/endpoints/{endpointID}/delete": "stops future enrollments only",
		"POST /api/acme/endpoints/{endpointID}/delete": "stops future enrollments only",
		"POST /api/est/endpoints/{endpointID}/delete":  "stops future enrollments only",
		// Revoking a pending invitation removes a grant rather than making one:
		// it is how an address typed wrong is undone, which is the safe
		// direction. Requiring a code to withdraw a mistake would leave the
		// mistake standing while somebody went to find their phone.
		"POST /settings/invitations/{id}/delete": "withdraws an unaccepted invitation",
		// Revokes one device's credential, which is the ordinary way to retire a
		// device and is done often enough that a code per device would be
		// unworkable.
		"POST /api/est/credentials/{credentialID}/delete":  "revokes one device credential",
		"POST /api/acme/credentials/{credentialID}/delete": "revokes one device credential",
	}

	for pattern, file := range registeredPatterns(t) {
		if !destructive.MatchString(pattern) {
			continue
		}
		if _, guarded := stepUpPatterns[pattern]; guarded {
			continue
		}
		if reason, ok := exempt[pattern]; ok {
			t.Logf("exempt: %s — %s", pattern, reason)
			continue
		}
		t.Errorf("%s (%s) looks destructive but requires no confirmation. Add it to "+
			"stepUpPatterns, or to the exemption list in this test with a reason", pattern, file)
	}
}

// guardedMux registers the patterns under test so mux.Handler resolves them.
// The middleware keys off the resolved pattern, so this is the minimum needed to
// exercise the decision.
func guardedMux() *http.ServeMux {
	mux := http.NewServeMux()
	nothing := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for pattern := range stepUpPatterns {
		mux.Handle(pattern, nothing)
	}
	// A few unguarded routes, so the pass-through half can be exercised too.
	for _, pattern := range []string{
		"GET /certificate-authorities",
		"POST /certificate-authorities",
		"POST /api/scep/endpoints/{endpointID}/policy",
		"GET /security",
	} {
		mux.Handle(pattern, nothing)
	}
	return mux
}

func TestStepUpDecision(t *testing.T) {
	recent := time.Now().Add(-time.Minute)
	stale := time.Now().Add(-2 * auth.StepUpGrace)

	cases := []struct {
		name    string
		session auth.Session
		want    int
	}{
		{name: "confirmed recently", session: auth.Session{SteppedUpAt: &recent}, want: http.StatusOK},
		{name: "confirmed too long ago", session: auth.Session{SteppedUpAt: &stale}, want: http.StatusForbidden},
		{name: "never confirmed", session: auth.Session{}, want: http.StatusForbidden},
	}
	for _, tc := range cases {
		reached := false
		mux := guardedMux()
		handler := StepUp(mux, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
		r := httptest.NewRequest("POST", "/certificate-authorities/"+testID+"/delete", nil)
		r = r.WithContext(auth.WithSession(r.Context(), tc.session))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		if w.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, w.Code, tc.want)
		}
		if reached != (tc.want == http.StatusOK) {
			t.Errorf("%s: handler reached = %v with status %d", tc.name, reached, w.Code)
		}
	}
}

// TestStepUpIgnoresUnguardedRoutes: the middleware must be invisible to
// everything not in the map, including reads of the same resources.
//
// Creating a CA is here rather than issuing a certificate, which used to be: a
// new CA anchors no trust until something is issued from it, whereas issuing is
// now guarded because it is the quiet half of the same escalation the CA-delete
// prompt exists to stop. Editing an endpoint's policy is here because it only
// narrows or widens what a credential may later ask for, and the credential
// itself is what carries the prompt.
func TestStepUpIgnoresUnguardedRoutes(t *testing.T) {
	mux := guardedMux()
	handler := StepUp(mux, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, tc := range []struct{ method, path string }{
		{"GET", "/certificate-authorities"},
		{"POST", "/certificate-authorities"},
		{"POST", "/api/scep/endpoints/" + testID + "/policy"},
		{"GET", "/security"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r = r.WithContext(auth.WithSession(r.Context(), auth.Session{}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s %s = %d; it is not guarded and must pass through", tc.method, tc.path, w.Code)
		}
	}
}

// TestStepUpTellsHtmxWhatToAsk covers the header the dialog is driven by. A 403
// with no HX-Trigger is a dead end: htmx will not swap a non-2xx body, so the
// action would appear to do nothing at all.
func TestStepUpTellsHtmxWhatToAsk(t *testing.T) {
	mux := guardedMux()
	handler := StepUp(mux, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest("POST", "/certificate-authorities/"+testID+"/delete", nil)
	r.Header.Set("HX-Request", "true")
	r = r.WithContext(auth.WithSession(r.Context(), auth.Session{}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	trigger := w.Header().Get("HX-Trigger")
	if trigger == "" {
		t.Fatal("no HX-Trigger; the confirmation dialog would never open")
	}
	for _, want := range []string{
		"stepup",
		// The prompt has to name what is about to happen, or the user is asked
		// for a code with no idea what for.
		"destroy its key",
		// And the request to retry, or confirming leaves them back where they
		// started wondering whether it ran.
		"/certificate-authorities/" + testID + "/delete",
	} {
		if !strings.Contains(trigger, want) {
			t.Errorf("HX-Trigger = %q, want it to contain %q", trigger, want)
		}
	}
	var event map[string]map[string]string
	if err := json.Unmarshal([]byte(trigger), &event); err != nil {
		t.Fatalf("HX-Trigger is not JSON: %v", err)
	}
	if got := event["stepup"]["method"]; got != http.MethodPost {
		t.Errorf("retry method = %q, want POST", got)
	}
}

// TestStepUpRetargetKeepsTheQueryString covers what the replay has left to work
// with.
//
// The dialog retries the refused request with htmx.ajax(method, url) and no
// form, so the request body is gone by the time it runs and the URL is all that
// survives. No guarded route reads a query parameter today, so this pins the
// contract ahead of the first one that does.
func TestStepUpRetargetKeepsTheQueryString(t *testing.T) {
	mux := guardedMux()
	handler := StepUp(mux, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	target := "/settings/users/" + testID + "/role?scope=all"
	r := httptest.NewRequest("POST", target, nil)
	r.Header.Set("HX-Request", "true")
	r = r.WithContext(auth.WithSession(r.Context(), auth.Session{}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	var event map[string]map[string]string
	if err := json.Unmarshal([]byte(w.Header().Get("HX-Trigger")), &event); err != nil {
		t.Fatalf("HX-Trigger is not JSON: %v", err)
	}
	if got := event["stepup"]["retarget"]; got != target {
		t.Errorf("retarget = %q, want %q", got, target)
	}
}

// TestSecurityPanelIsGuardedByItsHandlerNotHere records a deliberate absence.
//
// GET /security/panel used to be in stepUpPatterns and answered with a 403 that
// opened the standalone dialog. That put the prompt on top of the account
// dialog it was asking about — two stacked modals — so the handler draws its
// own prompt in the panel's place instead, and the pattern was removed.
//
// The reason this is a test rather than only a comment is that removing a
// pattern from an allowlist is exactly the shape of an accident. What makes the
// removal safe is the second half: every control the panel contains is still
// guarded here, so an unconfirmed session can look at nothing and change
// nothing regardless of how the panel itself is reached.
func TestSecurityPanelIsGuardedByItsHandlerNotHere(t *testing.T) {
	if action, guarded := stepUpPatterns["GET /security/panel"]; guarded {
		t.Errorf("GET /security/panel is guarded here as %q; the handler draws its own "+
			"prompt, and guarding it here brings back the stacked dialogs", action)
	}
	// The confirmation routes themselves must never be guarded: they are how a
	// confirmation is given, so requiring one to reach them is a loop with no
	// way in.
	for _, pattern := range []string{
		"POST /security/step-up",
		"POST /security/step-up/passkey/begin",
		"POST /security/step-up/passkey/finish",
		"POST /security/panel",
	} {
		if _, guarded := stepUpPatterns[pattern]; guarded {
			t.Errorf("%s is guarded by step-up, which cannot be satisfied without reaching it", pattern)
		}
	}
	// Everything the panel can actually do stays guarded.
	for _, pattern := range []string{
		"POST /security/totp/begin",
		"POST /security/totp/{id}/delete",
		"POST /security/passkeys/begin",
		"POST /security/passkeys/{id}/delete",
	} {
		if _, guarded := stepUpPatterns[pattern]; !guarded {
			t.Errorf("%s is not guarded; unguarding the panel is only safe while these are", pattern)
		}
	}
}

// TestStepUpEventNameIsHyperscriptSafe pins the one character that made every
// confirmation prompt in the application fail to appear.
//
// StepUpDialog listens for this event in hyperscript, whose tokeniser reads a
// hyphen in an event name as subtraction. It does not degrade: a parse error
// means none of that element's script is installed, so the dialog never opened,
// for any guarded action, and the only evidence was a console message. The
// server was refusing correctly the whole time.
//
// Reading the name out of the header rather than asserting on a constant is
// deliberate: the header is the contract, and it is what a future edit would
// change.
func TestStepUpEventNameIsHyperscriptSafe(t *testing.T) {
	mux := guardedMux()
	handler := StepUp(mux, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest("POST", "/certificate-authorities/"+testID+"/delete", nil)
	r.Header.Set("HX-Request", "true")
	r = r.WithContext(auth.WithSession(r.Context(), auth.Session{}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	var trigger map[string]map[string]string
	if err := json.Unmarshal([]byte(w.Header().Get("HX-Trigger")), &trigger); err != nil {
		t.Fatalf("HX-Trigger is not the JSON object htmx expects: %v", err)
	}
	if len(trigger) != 1 {
		t.Fatalf("HX-Trigger names %d events, want exactly one", len(trigger))
	}
	for name := range trigger {
		if strings.ContainsAny(name, "-. ") {
			t.Errorf("event name %q contains a character hyperscript cannot tokenise, so "+
				"StepUpDialog installs no handler at all and the prompt never opens", name)
		}
	}
}

// TestStepUpNeedsNoSessionToPassThrough: a guarded pattern reached without a
// session is Auth's problem, not this middleware's. Refusing here would replace
// Auth's redirect to /login with a confusing 403.
func TestStepUpNeedsNoSessionToPassThrough(t *testing.T) {
	mux := guardedMux()
	reached := false
	handler := StepUp(mux, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	r := httptest.NewRequest("POST", "/certificate-authorities/"+testID+"/delete", nil)
	handler.ServeHTTP(httptest.NewRecorder(), r)
	if !reached {
		t.Error("a request with no session was refused by StepUp; that is Auth's decision to make")
	}
}
