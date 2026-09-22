package middleware

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

func Auth(db *sql.DB, repo auth.Repository, secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := auth.ReadCookie(r, secret)
		id, err2 := uuid.Parse(sessionID)
		if err == nil && err2 == nil {
			// A failure to open the transaction falls through to the public
			// check below, so static assets and enrollment endpoints keep
			// working when the database is unreachable.
			if tx, txErr := db.BeginTx(r.Context(), nil); txErr == nil {
				served, err := serveSession(tx, repo, next, w, r, id)
				if served {
					return
				}
				if err != nil {
					log.Printf("auth failed: %v", err)
					http.Error(w, "auth failed", http.StatusInternalServerError)
					return
				}
				requireLogin(w, r)
				return
			}
		}
		if public(r) {
			next.ServeHTTP(w, r)
			return
		}
		requireLogin(w, r)
	})
}

// requireLogin clears the cookie and sends the caller to the login page in the
// way that caller can act on.
//
// The three branches exist because three kinds of caller reach this. A plain
// navigation follows a 303. An /api/ caller is script and wants a status code,
// not a login page in its response body. An htmx request is the one that used to
// go wrong: htmx follows a 303 transparently and swaps whatever comes back into
// the element that issued the request, so an expired session turned a status
// pill into a nested copy of the login page. HX-Redirect is htmx's own answer —
// it navigates the whole window instead.
//
// Both the no-cookie and the expired-session paths call this. They used to
// differ, with only the first honouring /api/; the difference was invisible
// while sessions quietly lapsed one at a time, and would not have stayed
// invisible once a deploy expired all of them at once.
func requireLogin(w http.ResponseWriter, r *http.Request) {
	auth.ClearCookie(w)
	// Only for a browser that arrived holding a cookie. That is what separates
	// a session that ended — the tab left open over a weekend, or a deploy
	// that expired every session at once — from someone who simply typed a URL
	// while signed out, and the second of those has nothing to be told.
	//
	// This used to say "no toast", correctly: the region was mounted on
	// layout.App, so /login had nowhere to render one and a flash set here
	// would have been consumed by a page that could not show it. It is mounted
	// on layout.Base now, which the sign-in pages are built from, and
	// view/auth/toast_test.go pins that.
	if _, err := r.Cookie(auth.CookieName); err == nil {
		toast.Announce(w, r, toast.Info, "Your session ended. Sign in again to continue.")
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// serveSession runs next inside tx with the request's RLS context set, and
// reports whether next was served and the transaction committed. A nil error
// with served false means the cookie named no live session.
//
// The rollback is deferred rather than called on each failure path. A panic in
// next unwinds through here, and an undeferred rollback would be skipped —
// leaking the connection until the driver noticed. Rolling back an already
// committed transaction returns sql.ErrTxDone and does nothing.
func serveSession(tx *sql.Tx, repo auth.Repository, next http.Handler, w http.ResponseWriter, r *http.Request, id uuid.UUID) (bool, error) {
	defer tx.Rollback()

	ctx := database.WithTx(r.Context(), tx)
	// app.session_id comes first: it is the only thing the session and user
	// policies can key off before the identity behind the cookie is known.
	if err := database.SetLocal(ctx, "app.session_id", id.String()); err != nil {
		return false, err
	}
	session, err := repo.SessionByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := database.SetLocal(ctx, "app.user_id", session.UserID); err != nil {
		return false, err
	}
	if err := database.SetLocal(ctx, "app.organization_id", session.OrgID); err != nil {
		return false, err
	}
	next.ServeHTTP(w, r.WithContext(auth.WithSession(ctx, session)))
	return tx.Commit() == nil, nil
}

// deviceClient reports whether the request comes from an enrollment client
// rather than from a browser. Such a client has no session, no way to acquire
// one, and sends neither Origin nor Sec-Fetch-Site — so it is exempt from the
// origin check in CSRF, and this predicate is that exemption and only that.
//
// It is deliberately separate from public(). The two used to be one function,
// which meant POST /login and POST /setup — browser form posts that complete
// an authentication — inherited an exemption written for SCEP clients. Keeping
// them apart is what lets a pre-session browser page skip the session without
// also skipping the origin check.
//
// /acme/ and /.well-known/est/ sit alongside /scep/ for the same reason: without
// them every enrollment request would be answered with a 303 to the login page,
// which a device reports as an unparseable response rather than as an
// authentication problem.
//
// /pki/ is here for the origin check rather than for the session. It is the CRL,
// issuer and OCSP distribution points, whose URLs this service prints into every
// certificate it issues, and one of them is a POST: OpenSSL, Windows CryptoAPI
// and NSS all send an OCSP request as a POST body once it outgrows the base64
// GET form, and several send it that way unconditionally. Such a caller has no
// Origin, no Sec-Fetch-Site and no Referer, so sameOrigin() refuses it — and a
// validator configured to hard-fail reads that 403 as "revocation status
// unavailable" and rejects the whole chain. Nothing under /pki/ changes state:
// the POST is a read that may warm a signed-response cache.
func deviceClient(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/scep/") || strings.HasPrefix(r.URL.Path, "/acme/") ||
		strings.HasPrefix(r.URL.Path, "/.well-known/est/") ||
		strings.HasPrefix(r.URL.Path, "/integrations/jamf/") ||
		strings.HasPrefix(r.URL.Path, "/pki/")
}

// public reports whether the request may proceed without a session. It is a
// superset of deviceClient: it also admits the static assets and the browser
// pages that exist to create a session — which are still origin-checked, because
// they are browsers. The public PKI distribution points arrive through
// deviceClient, because they need the origin exemption as well as this one.
func public(r *http.Request) bool {
	if deviceClient(r) {
		return true
	}
	// Everything under /auth/ is pre-session by construction: it is the flow that
	// turns a magic link into a session, and none of it can require the cookie it
	// exists to mint. The invariant that keeps this safe is that nothing needing a
	// session lives under /auth/ — post-session security management is under
	// /security/ instead, and auth_test.go pins both halves.
	if strings.HasPrefix(r.URL.Path, "/auth/") {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/static/") {
		return true
	}
	// /assets/ is the brand — logos, favicons, the web manifest. The sign-in page
	// renders the wordmark from it, so a session cannot be a condition of
	// fetching it: the first page anyone sees is the one page nobody has a
	// session for.
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		return true
	}
	// /healthz is here because the platform's probe carries no cookie: without
	// it every poll is answered with a 303 to /login, which some probes read as
	// healthy and others as a redirect loop, and neither answers the question.
	//
	// /robots.txt is here because a crawler carries no cookie, and a robots file
	// answered with a 303 to /login tells it nothing. The file it gets says to
	// index none of this.
	switch r.URL.Path {
	case "/login", "/setup", "/favicon.ico", "/robots.txt", "/healthz":
		return true
	default:
		return false
	}
}
