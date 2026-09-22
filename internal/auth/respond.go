package auth

import (
	"net/http"

	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

// confirm reports that something worked, to either kind of caller.
//
// These handlers used to answer with a bare sentence — fmt.Fprint(w, "Saved.")
// — swapped into a small grey <p> beside the button. That worked, and it is the
// wrong shape for what those sentences are. "If that address has an account, a
// sign-in link is on its way" is not a note about the email field; it is the
// whole outcome of the page, and it belongs where the application puts every
// other outcome now.
//
// Two paths, for the same reason every other confirmation has two:
//
//   - htmx gets a 204 and a trigger header. The status is load-bearing: these
//     forms no longer carry an hx-target, so htmx falls back to the form
//     itself, and a 200 with an empty body would swap that empty body over the
//     form and wipe what was just typed. htmx's default responseHandling maps
//     204 to swap:false, so the page is left exactly as it was and the toast is
//     the only change.
//   - A plain form post has no listener, so the message is stored and the
//     browser is sent back to a page that will render it. Reloading also clears
//     the form, which is the right end state for a submission that succeeded.
//
// This lives here rather than in internal/web because internal/web imports this
// package.
func confirm(w http.ResponseWriter, r *http.Request, tone toast.Tone, text, location string) {
	if r.Header.Get("HX-Request") == "true" {
		toast.Now(w, r, tone, text)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	toast.Announce(w, r, tone, text)
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// refuse reports that something was rejected, to either kind of caller. It is
// confirm's mirror image and exists for the same reason: the sentence belongs
// in the same corner of the page as every other outcome, not in a grey line
// under one field.
//
// The status is the real one, unlike the FormError helpers that answer 200 so
// htmx will swap a fragment. Nothing is being swapped here — htmx reads
// HX-Trigger before it looks at the status, raises the toast, and then declines
// to swap a 4xx, which leaves the form exactly as the user typed it. That is
// the behaviour a rejected code wants: the six digits stay put and can be
// corrected in place.
func refuse(w http.ResponseWriter, r *http.Request, status int, text, location string) {
	if r.Header.Get("HX-Request") == "true" {
		toast.Fail(w, r, status, text)
		return
	}
	toast.Announce(w, r, toast.Error, text)
	http.Redirect(w, r, location, http.StatusSeeOther)
}
