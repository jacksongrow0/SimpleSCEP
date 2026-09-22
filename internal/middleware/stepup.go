package middleware

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

// stepUpPatterns names the actions that require a freshly proved second factor,
// keyed by the mux pattern that serves them, with the phrase shown in the
// confirmation prompt.
//
// Keyed by pattern rather than checked inside each handler for two reasons. The
// list is readable in one place, so "what needs confirming?" is answered by
// reading a dozen lines rather than by grepping every package. And a renamed or
// deleted route fails TestStepUpPatternsAreRegistered loudly, where a
// per-handler check would simply be carried along by the rename and keep
// guarding a route nobody calls.
//
// This is an allowlist, so it cannot be fail-closed for a destructive route
// nobody added to it. TestEveryDestructiveShapeIsGuarded compensates by
// requiring that anything matching the shape of the categories here is present.
//
// Key export is absent because no such route exists: the download endpoints
// serve certificates and chains, and KeyProvider has no export method at all. If
// one is ever added, it belongs here — that is the whole reason this note is
// attached to the map rather than buried in a commit message.
var stepUpPatterns = map[string]string{
	"POST /certificate-authorities/{id}/delete": "delete this certificate authority and destroy its key",
	"POST /certificate-authorities/{id}/rotate": "rotate this issuing CA",
	// Inviting an administrator is a role grant, and the cheapest privilege
	// escalation in the product: it needs no existing account to act against.
	"POST /settings/invitations":       "invite a user",
	"POST /settings/users/{id}/role":   "change this user's role",
	"POST /settings/users/{id}/delete": "remove this user",
	// GET /security/panel is deliberately absent, and this note is here so it
	// is not added back as an oversight.
	//
	// It was guarded here, and the guard worked: the panel refused to load
	// until a factor was proved. What was wrong was where the question got
	// asked. This middleware's answer is a 403 that opens the standalone
	// dialog, and that route is a tab inside the account dialog, so the prompt
	// opened on top of the thing it was asking about — two stacked modals, the
	// explanation underneath the question.
	//
	// The handler now draws its own prompt in the panel's place. Nothing is
	// unguarded by that: every control inside the panel — registering and
	// removing an authenticator or a passkey — is listed below in its own
	// right, so what moved is the location of the question, not whether it is
	// asked.
	// Adding or removing a second factor from an unattended screen would hand the
	// account over, so both ends of both kinds are confirmed.
	//
	// Only the begin half of each registration is here. The confirm half can
	// complete nothing that begin did not already authorise, and guarding it too
	// would mean typing two codes to register one device — which is how a
	// confirmation prompt stops being read.
	"POST /security/totp/begin":           "register an authenticator",
	"POST /security/totp/{id}/delete":     "remove an authenticator",
	"POST /security/passkeys/begin":       "register a passkey",
	"POST /security/passkeys/{id}/delete": "remove a passkey",

	// Minting an enrollment credential is issuing a certificate, one step
	// removed, and it is quieter than anything above it. Deleting a CA is loud
	// and its key version survives a scheduled-destroy window; a certificate
	// issued to the wrong subject is neither — it is valid until it expires or
	// somebody notices it in the audit log.
	//
	// So an unattended screen must not be able to hand out a credential that
	// enrolls CN=Domain Admin, which is exactly what these do. The endpoint's
	// subject and SAN policy bounds what the credential can then ask for, and
	// the default policy on a new endpoint bounds nothing.
	"POST /api/scep/endpoints/{endpointID}/challenges":  "issue a SCEP enrollment challenge",
	"POST /api/est/endpoints/{endpointID}/credentials":  "issue an EST credential",
	"POST /api/acme/endpoints/{endpointID}/credentials": "issue an ACME credential",
	// Not a mint but a re-mint, and wider: every device on the endpoint
	// authenticates with this one secret, so rotating it both hands out a new
	// credential and turns away every device still holding the old one.
	"POST /api/scep/endpoints/{endpointID}/auth/static": "rotate the shared SCEP secret",

	// The direct issuance paths, which need no credential at all — they sign
	// whatever subject the form or the CSR names, under the organization's own
	// CA. Revocation is here for the other direction: it is how a working device
	// is turned off, and a fleet-wide revocation from an unattended screen is an
	// outage.
	"POST /certificates/issue":       "issue a certificate",
	"POST /certificates/csr":         "sign a certificate request",
	"POST /certificates/{id}/revoke": "revoke this certificate",

	// Resending an invitation mints a fresh seven-day sign-up token for somebody
	// who has no account yet, and invalidates the previous one. That is the same
	// privilege grant POST /settings/invitations carries, so it is confirmed the
	// same way — an unattended screen must not be able to reissue a live invitation
	// to an address the person at the keyboard chose.
	"POST /settings/invitations/{id}/resend": "resend this invitation",
}

// StepUp refuses a request naming a high-blast-radius action unless the session
// proved a second factor within the last few minutes.
//
// It sits inside Auth, because it needs the session Auth resolves, and outside
// the mux, because resolving the pattern is what makes the list above checkable
// by a test. Mounted as Auth(db, repo, secret, StepUp(mux, mux)).
func StepUp(mux *http.ServeMux, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		action, guarded := stepUpPatterns[pattern]
		if !guarded {
			next.ServeHTTP(w, r)
			return
		}
		session, ok := auth.FromContext(r.Context())
		if !ok {
			// No session at all: Auth has already decided this is public, or the
			// route is unreachable. Either way there is nothing to step up from,
			// and refusing here would be a second, more confusing 401.
			next.ServeHTTP(w, r)
			return
		}
		if session.SteppedUp(time.Now()) {
			next.ServeHTTP(w, r)
			return
		}
		promptStepUp(w, r, action)
	})
}

// promptStepUp asks for a code without losing what the caller was trying to do.
//
// The retarget is the path the request was aimed at, so the dialog can re-fire
// the original request once the code is accepted rather than making the user
// find the button again. It is echoed back from the request itself and is only
// ever used to re-issue the same request, so there is nothing here a caller
// could redirect themselves to that they could not have requested directly.
//
// It carries the query string, not just the path. The replay is an
// htmx.ajax(method, url) from the dialog, which has no form to serialise, so
// anything the refused request said in its body is gone by the time it runs.
// The URL is all a confirmed request has left, and truncating it to the path
// would throw away the half that survives.
//
// No guarded route reads a query parameter today — every one of them is keyed
// by a path value — so this guards a trap rather than fixing a live bug. It is
// here because a future guarded action may take essential input from the query
// string, and a confirmed retry must not silently discard it.
func promptStepUp(w http.ResponseWriter, r *http.Request, action string) {
	if r.Header.Get("HX-Request") == "true" {
		// The event name carries no hyphen on purpose: StepUpDialog listens for it
		// in hyperscript, whose tokeniser reads one as subtraction and then
		// installs none of the element's script. See view/layout/scripts.go.
		trigger, err := json.Marshal(map[string]any{
			"stepup": map[string]string{
				"action": action, "retarget": r.URL.RequestURI(), "method": r.Method,
			},
		})
		if err == nil {
			w.Header().Set("HX-Trigger", string(trigger))
		}
		// 403 rather than 401: the caller is authenticated, they simply have not
		// confirmed recently enough. htmx will not swap this, which is what we
		// want — the dialog opens off the trigger instead.
		http.Error(w, "confirm with your authenticator to "+action, http.StatusForbidden)
		return
	}
	http.Error(w, "Confirm with your authenticator to "+action+
		". Open your account settings to confirm, then try again.", http.StatusForbidden)
}
