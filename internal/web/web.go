// Package web holds the request plumbing every administration handler repeats:
// deciding how a redirect reaches an htmx client, gating a route on the
// administrator role, and reading the two request shapes the forms arrive in.
//
// These live here rather than in each feature package because they encode
// whole-application conventions — an htmx swap ignores a 303, an administrator
// check must answer the same way everywhere — and a copy that drifts from the
// others is a bug rather than a variation.
package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

// MaxFormSize bounds an administration form or JSON body. The forms carry
// certificate policy, not certificates, so this is generous for every legitimate
// caller and small enough that a hostile one cannot spend much memory.
const MaxFormSize = 64 << 10

// Redirect sends htmx requests a full-page HX-Redirect (closing any open
// dialog) and everything else an ordinary 303. htmx swaps the response body in
// place, so a plain redirect would land the next page inside the dialog.
func Redirect(w http.ResponseWriter, r *http.Request, location string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", location)
		return
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// Admin resolves the session and reports whether it may administer the
// organization, having already written the refusal when it may not.
// Admin refuses through Fail rather than http.Error.
//
// This is the gate on most of internal/home, and every page and control behind
// it is reached by htmx — which does not swap a non-2xx response. So a refusal
// here used to be entirely mute: the control did nothing, said nothing, and left
// the person pressing it with no way to tell a permission problem from a bug.
func Admin(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	s, ok := auth.FromContext(r.Context())
	if !ok {
		Fail(w, r, http.StatusUnauthorized, "Your session has ended. Sign in again.")
		return s, false
	}
	if !s.IsAdmin() {
		Fail(w, r, http.StatusForbidden, "Only administrators can do that.")
		return s, false
	}
	return s, true
}

// DecodeJSON reads a bounded JSON body. Both failures are reported in the
// wording the form surfaces directly, because either one means the request was
// malformed before any policy could be applied to it.
func DecodeJSON(r *http.Request, into any) error {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, MaxFormSize))
	if err != nil {
		return errors.New("the request body is too large")
	}
	if err := json.Unmarshal(body, into); err != nil {
		return errors.New("the request body is not a JSON object")
	}
	return nil
}

// PositiveInt parses a whole number from a form field, falling back when the
// field was left blank. It rejects signs and separators rather than accepting
// what strconv would, so a field that means "how many days" cannot be handed a
// negative, and it caps the value so a long digit string cannot overflow.
func PositiveInt(raw string, fallback int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	n := 0
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, errors.New("that value must be a whole number")
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return 0, errors.New("that value is out of range")
		}
	}
	return n, nil
}
