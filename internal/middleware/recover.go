package middleware

import (
	"log"
	"net/http"
	"runtime/debug"

	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

// Recover turns a handler panic into a 500 instead of a dropped connection.
//
// It belongs outermost, so the deferred cleanup in every inner middleware —
// notably the transaction rollback in Auth — runs as the stack unwinds before
// this catches it. Without that ordering a panic would leave the connection
// checked out until the driver noticed.
//
// The response body says nothing about what failed. A panic message can carry a
// query fragment or a key version, and the caller is not owed either; the detail
// goes to the log.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				// http.ErrAbortHandler is the documented way for a handler to drop
				// a connection deliberately; re-panicking lets the server treat it
				// as intended rather than logging a stack trace for it.
				if p == http.ErrAbortHandler {
					panic(p)
				}
				log.Printf("panic serving %s %s: %v\n%s", r.Method, r.URL.Path, p, debug.Stack())
				// If the handler already wrote a response this is a no-op beyond a
				// logged warning from net/http, which is the best available outcome:
				// the alternative is a silently truncated body.
				toast.Fail(w, r, http.StatusInternalServerError, "Something went wrong. Nothing was saved.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
