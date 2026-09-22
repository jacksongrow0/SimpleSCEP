package auth

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/model"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
	authview "github.com/jacksongrow0/SimpleSCEP/view/auth"
)

// sessionTTL is how long a fully authenticated session lives.
const sessionTTL = 30 * 24 * time.Hour

// beginChallenge turns a redeemed first factor into a login challenge.
//
// resolve is whatever proved the first factor — redeeming a magic link or
// accepting an invitation — and runs inside the auth flow transaction, so it
// still has the RLS escape hatch those redemptions need. Its user is then
// examined for a confirmed second factor, and the challenge is opened in the
// stage that answer implies. A user who has one is asked for a code; a user who
// has none must register one before any session can exist, which is what makes
// the requirement mandatory rather than encouraged.
func (h Handler) beginChallenge(w http.ResponseWriter, r *http.Request, resolve func(context.Context) (model.User, error)) error {
	expires := time.Now().UTC().Add(challengeTTL)
	var challengeID uuid.UUID
	err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		user, err := resolve(ctx)
		if err != nil {
			return err
		}
		stage := StageEnroll
		count, err := h.repo.CountTOTPCredentials(ctx, user.ID)
		if err != nil {
			return err
		}
		if count > 0 {
			stage = StageVerify
		}
		challengeID, err = h.repo.CreateChallenge(ctx, user.ID, stage, expires)
		return err
	})
	if err != nil {
		return err
	}
	SetChallengeCookie(w, challengeID.String(), h.secret, expires)
	return nil
}

// challenge resolves the challenge a request carries, or writes the response
// that sends the caller back to the start.
//
// Every second-factor handler begins here, so there is one place that decides
// what an absent, forged, expired or spent challenge means — and one place to
// read when asking whether any of them can reach a session.
func (h Handler) challenge(w http.ResponseWriter, r *http.Request) (Challenge, model.User, bool) {
	id, err := ReadChallengeCookie(r, h.secret)
	challengeID, parseErr := uuid.Parse(id)
	if err != nil || parseErr != nil {
		h.restartLogin(w, r, "Your sign-in has expired. Request a new link.")
		return Challenge{}, model.User{}, false
	}

	var c Challenge
	var user model.User
	err = h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		var err error
		if c, err = h.repo.ChallengeByID(ctx, challengeID); err != nil {
			return err
		}
		user, err = h.repo.UserByID(ctx, c.UserID)
		return err
	})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("challenge lookup failed: %v", err)
		}
		h.restartLogin(w, r, "Your sign-in has expired. Request a new link.")
		return Challenge{}, model.User{}, false
	}
	return c, user, true
}

// restartLogin discards the challenge and sends the caller back to /login.
// Written once because the alternative — each handler clearing the cookie and
// redirecting — is how a browser ends up holding a cookie for a row that no
// longer exists, looping between two pages that each blame the other.
func (h Handler) restartLogin(w http.ResponseWriter, r *http.Request, reason string) {
	ClearChallengeCookie(w)
	// The reason is stored for the next page rather than written into this
	// response. Both branches below navigate, and a navigation discards
	// whatever this response body or its headers were carrying — which is why
	// "Your sign-in has expired" used to be a sentence nobody ever saw. /login
	// is rendered by layout.Base, and Base hosts the toast region, so it
	// arrives with the page that replaces this one.
	toast.Announce(w, r, toast.Error, reason)
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login")
		http.Error(w, reason, http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// twoFactor renders whichever card the challenge calls for.
func (h Handler) twoFactor(w http.ResponseWriter, r *http.Request) {
	// Someone who already holds a session has no business here, and sending them
	// to a code prompt they cannot satisfy would be a dead end.
	if _, ok := FromContext(r.Context()); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	c, user, ok := h.challenge(w, r)
	if !ok {
		return
	}
	if c.Stage == StageVerify {
		authview.Verify().Render(r.Context(), w)
		return
	}

	secret, err := h.pendingSecret(r.Context(), c, user)
	if err != nil {
		log.Printf("enrolment secret unavailable: %v", err)
		h.restartLogin(w, r, "Enrolment could not be started. Request a new link.")
		return
	}
	authview.Enroll(formatSecret(secret)).Render(r.Context(), w)
}

// pendingSecret returns the unconfirmed secret for an enrolment, minting and
// storing one on first use.
//
// It is stored rather than regenerated per request because the page can be
// reloaded, and a fresh secret on every load would silently invalidate the QR
// the user has already scanned — presenting as an authenticator that produces
// permanently wrong codes. Sealed under the challenge id, so an abandoned
// enrolment's ciphertext cannot be promoted into a confirmed credential.
func (h Handler) pendingSecret(ctx context.Context, c Challenge, user model.User) (string, error) {
	if len(c.PendingSecret) > 0 {
		return unprotectTOTPSecret(ctx, h.protect, enrollPurpose(c.ID.String()), c.PendingSecret)
	}
	key, err := newTOTPKey(user.Email)
	if err != nil {
		return "", err
	}
	sealed, err := protectTOTPSecret(ctx, h.protect, enrollPurpose(c.ID.String()), key.Secret())
	if err != nil {
		return "", err
	}
	if err := h.repo.AuthFlow(ctx, func(ctx context.Context) error {
		return h.repo.SetPendingSecret(ctx, c.ID, sealed)
	}); err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// twoFactorQR serves the enrolment QR as its own no-store response, so the
// shared secret never lands in an HTML body, in view-source, or in htmx's swap
// history. Authorised by the challenge cookie and taking no parameters: there is
// nothing a caller could vary to be shown somebody else's secret.
func (h Handler) twoFactorQR(w http.ResponseWriter, r *http.Request) {
	c, user, ok := h.challenge(w, r)
	if !ok {
		return
	}
	if c.Stage != StageEnroll {
		http.Error(w, "no enrolment in progress", http.StatusNotFound)
		return
	}
	secret, err := h.pendingSecret(r.Context(), c, user)
	if err != nil {
		log.Printf("enrolment secret unavailable: %v", err)
		http.Error(w, "enrolment unavailable", http.StatusInternalServerError)
		return
	}
	key, err := keyFromSecret(user.Email, secret)
	if err != nil {
		log.Printf("building otpauth key: %v", err)
		http.Error(w, "enrolment unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, private")
	if err := writeQR(w, key); err != nil {
		log.Printf("rendering QR: %v", err)
	}
}

// confirmEnrollment completes a first enrolment: the submitted code proves the
// authenticator holds the secret, so the secret is promoted to a confirmed
// credential, a set of recovery codes is issued, and a session is finally
// created. The codes are shown exactly once, on the resulting authenticated
// page.
func (h Handler) confirmEnrollment(w http.ResponseWriter, r *http.Request) {
	if !allow(h.limits.Redeem, "mfa|"+clientip.ClientIP(r)) {
		http.Error(w, "too many attempts; try again shortly", http.StatusTooManyRequests)
		return
	}
	c, user, ok := h.spend(w, r)
	if !ok {
		return
	}
	if c.Stage != StageEnroll {
		http.Error(w, "no enrolment in progress", http.StatusBadRequest)
		return
	}
	secret, err := unprotectTOTPSecret(r.Context(), h.protect, enrollPurpose(c.ID.String()), c.PendingSecret)
	if err != nil {
		log.Printf("opening pending secret: %v", err)
		h.restartLogin(w, r, "Enrolment could not be completed. Request a new link.")
		return
	}
	step, valid := verifyTOTP(secret, formValue(r, "code"), time.Now(), 0)
	if !valid {
		h.codeRejected(w, r, c, user)
		return
	}

	// Re-sealed under the user rather than copied: the ciphertext that sat on the
	// challenge is bound to the challenge, and a confirmed credential must be
	// bound to the person.
	sealed, err := protectTOTPSecret(r.Context(), h.protect, totpPurpose(user.ID.String()), secret)
	if err != nil {
		log.Printf("sealing confirmed secret: %v", err)
		http.Error(w, "enrolment failed", http.StatusInternalServerError)
		return
	}
	display, rows, err := newRecoveryCodes()
	if err != nil {
		log.Printf("generating recovery codes: %v", err)
		http.Error(w, "enrolment failed", http.StatusInternalServerError)
		return
	}

	var sessionID uuid.UUID
	err = h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		credentialID, err := h.repo.SaveTOTPCredential(ctx, user.ID, firstTOTPLabel, sealed)
		if err != nil {
			return err
		}
		// The code just used is burned immediately, so the enrolment code cannot
		// also be replayed as a sign-in code.
		if _, err := h.repo.AdvanceTOTPStep(ctx, credentialID, step); err != nil {
			return err
		}
		if err := h.repo.ReplaceRecoveryCodes(ctx, user.ID, rows); err != nil {
			return err
		}
		if err := h.repo.DeleteChallenge(ctx, c.ID); err != nil {
			return err
		}
		sessionID, err = h.repo.CreateVerifiedSession(ctx, user, time.Now().UTC().Add(sessionTTL))
		if err != nil {
			return err
		}
		h.recordSignIn(ctx, r, user, sessionID, audit.ActionMFAEnrolled)
		return nil
	})
	if err != nil {
		log.Printf("completing enrolment: %v", err)
		http.Error(w, "enrolment failed", http.StatusInternalServerError)
		return
	}

	ClearChallengeCookie(w)
	SetCookie(w, sessionID.String(), h.secret, time.Now().Add(sessionTTL))
	// The codes get their own page. This response used to render them, which
	// htmx swapped into the result line beneath the code field: a full card's
	// worth of one-time secrets appended to the bottom of the card that had
	// just asked for six digits, with the QR and its instructions still sitting
	// above them. They are handed to the next request in a cookie instead —
	// see SetRecoveryCodesCookie for why that is the only place they can
	// travel — and the enrolment ends where every other successful form in the
	// application ends, on a new page.
	if err := SetRecoveryCodesCookie(w, display, h.secret); err != nil {
		// The enrolment itself is committed and the session is live, so this
		// cannot fail the request. It costs the display of the codes, which is
		// what the message has to say.
		log.Printf("handing off recovery codes: %v", err)
		confirm(w, r, toast.Warning,
			"Two-factor authentication is on, but your recovery codes could not be shown. Reset your authenticator from the account settings to be issued a new set.", "/")
		return
	}
	hxRedirect(w, r, "/auth/recovery-codes")
}

// recoveryCodes shows a freshly issued set exactly once.
//
// It reads them from the cookie confirmEnrollment set and clears it in the same
// breath, so a reload — or the next person to sit at this machine and press the
// back button — gets the dashboard rather than a second look at ten one-time
// secrets. There is no route that re-issues them and no copy on the server to
// re-read: what the cookie carried is all there ever was.
func (h Handler) recoveryCodes(w http.ResponseWriter, r *http.Request) {
	// The one page in the application whose body is a set of live secrets, so
	// it is kept out of every store that would keep it: the disk cache, an
	// intermediary, and the history entry the back button restores. Same
	// treatment twoFactorQR gives the enrolment secret.
	w.Header().Set("Cache-Control", "no-store, private")
	codes, ok := TakeRecoveryCodes(w, r, h.secret)
	if !ok {
		// Not an error worth a page. Either they have already been shown, or
		// somebody guessed the URL; both mean there is nothing here.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	authview.RecoveryCodes(codes).Render(r.Context(), w)
}

// verifyCode completes a sign-in for a user who already holds an authenticator.
func (h Handler) verifyCode(w http.ResponseWriter, r *http.Request) {
	if !allow(h.limits.Redeem, "mfa|"+clientip.ClientIP(r)) {
		http.Error(w, "too many attempts; try again shortly", http.StatusTooManyRequests)
		return
	}
	c, user, ok := h.spend(w, r)
	if !ok {
		return
	}
	if c.Stage != StageVerify {
		http.Error(w, "no authenticator registered", http.StatusBadRequest)
		return
	}

	// Read, verify and commit inside one transaction.
	//
	// The read has to be in here at all because user_totp_credential's RLS policy
	// admits either the auth flow or a matching app.user_id, and at this point
	// there is no session and so no app.user_id — a read on a bare connection
	// matches nothing and presents as "you have no authenticator registered".
	// Keeping the verification in the same transaction also closes the gap
	// between reading last_step and advancing it.
	var sessionID uuid.UUID
	err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		credentialID, step, err := h.matchTOTP(ctx, user.ID, formValue(r, "code"))
		if err != nil {
			return err
		}
		// The conditional update is the replay guard, not the match above: two
		// submissions of the same code race here, and exactly one wins.
		advanced, err := h.repo.AdvanceTOTPStep(ctx, credentialID, step)
		if err != nil {
			return err
		}
		if !advanced {
			return errInvalidCode
		}
		if err := h.repo.DeleteChallenge(ctx, c.ID); err != nil {
			return err
		}
		sessionID, err = h.repo.CreateVerifiedSession(ctx, user, time.Now().UTC().Add(sessionTTL))
		if err != nil {
			return err
		}
		h.recordSignIn(ctx, r, user, sessionID, audit.ActionSignedIn)
		return nil
	})
	if errors.Is(err, errInvalidCode) {
		h.codeRejected(w, r, c, user)
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		// The credential vanished between the challenge opening and this
		// submission, which means it was reset deliberately in the meantime.
		h.restartLogin(w, r, "Your authenticator is no longer registered. Request a new link.")
		return
	}
	if err != nil {
		log.Printf("completing sign-in: %v", err)
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}

	ClearChallengeCookie(w)
	SetCookie(w, sessionID.String(), h.secret, time.Now().Add(sessionTTL))
	hxRedirect(w, r, "/")
}

// verifyRecovery redeems a recovery code.
//
// It does not produce a session. A recovery code is used precisely when the
// authenticator is gone, so handing back a session would leave the account
// running on a dwindling pile of one-time codes with no second factor at all.
// Instead every registered authenticator is deleted and the challenge is moved
// to enrolment: the user registers a replacement on the spot, and the floor is
// restored before they reach anything.
//
// All of them, not just one, because a recovery code says "I cannot produce a
// code" — there is no way to know which of the registered devices is the lost
// one, and leaving a survivor would leave a factor the person redeeming this
// code has told us they may not hold.
func (h Handler) verifyRecovery(w http.ResponseWriter, r *http.Request) {
	if !allow(h.limits.Redeem, "mfa|"+clientip.ClientIP(r)) {
		http.Error(w, "too many attempts; try again shortly", http.StatusTooManyRequests)
		return
	}
	c, user, ok := h.spend(w, r)
	if !ok {
		return
	}
	selector, verifier, err := parseRecoveryCode(formValue(r, "code"))
	if err != nil {
		h.codeRejected(w, r, c, user)
		return
	}

	err = h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		id, hash, err := h.repo.RecoveryCodeBySelector(ctx, user.ID, selector)
		if err != nil {
			return err
		}
		// Verify before consuming, so a wrong verifier against a real selector
		// does not burn somebody's code.
		if !verifyRecoveryVerifier(hash, verifier) {
			return sql.ErrNoRows
		}
		consumed, err := h.repo.ConsumeRecoveryCode(ctx, id)
		if err != nil {
			return err
		}
		if !consumed {
			return sql.ErrNoRows
		}
		if err := h.repo.DeleteTOTPCredentials(ctx, user.ID); err != nil {
			return err
		}
		if err := h.repo.SetChallengeStage(ctx, c.ID, StageEnroll); err != nil {
			return err
		}
		// Every existing session was authorised by a factor the user has just told
		// us they no longer control.
		if err := h.repo.DeleteSessionsForUser(ctx, user.ID); err != nil {
			return err
		}
		h.recordUser(ctx, r, user, audit.ActionMFARecoveryUsed, "authenticator reset; re-enrolment required")
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		h.codeRejected(w, r, c, user)
		return
	}
	if err != nil {
		log.Printf("redeeming recovery code: %v", err)
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}
	hxRedirect(w, r, "/auth/2fa")
}

// spend resolves the challenge and consumes one of its attempts.
//
// Every handler that checks a secret goes through here rather than through
// challenge(), so the attempt counter cannot be bypassed by adding a new
// verification route that forgets to increment it.
func (h Handler) spend(w http.ResponseWriter, r *http.Request) (Challenge, model.User, bool) {
	id, err := ReadChallengeCookie(r, h.secret)
	challengeID, parseErr := uuid.Parse(id)
	if err != nil || parseErr != nil {
		h.restartLogin(w, r, "Your sign-in has expired. Request a new link.")
		return Challenge{}, model.User{}, false
	}

	var c Challenge
	var user model.User
	err = h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		var err error
		if c, err = h.repo.SpendChallengeAttempt(ctx, challengeID); err != nil {
			return err
		}
		user, err = h.repo.UserByID(ctx, c.UserID)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		// Out of attempts, expired, or already spent. All three end the same way:
		// the challenge is finished, and a new one costs a new magic link — which
		// costs mailbox access, the first factor.
		h.discardChallenge(r, challengeID)
		h.restartLogin(w, r, "Too many attempts. Request a new sign-in link.")
		return Challenge{}, model.User{}, false
	}
	if err != nil {
		log.Printf("spending challenge attempt: %v", err)
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return Challenge{}, model.User{}, false
	}
	return c, user, true
}

// discardChallenge removes a spent challenge. Best effort: the row has an expiry
// and a used-up attempt count, so failing to delete it leaves nothing usable
// behind, and reporting the failure would replace a clear message to the user
// with an opaque one.
func (h Handler) discardChallenge(r *http.Request, id uuid.UUID) {
	if err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		return h.repo.DeleteChallenge(ctx, id)
	}); err != nil {
		log.Printf("discarding challenge: %v", err)
	}
}

// codeRejected reports a wrong code, and says how many tries are left so a user
// mistyping is not left guessing why they were suddenly sent back to the start.
// The count is not a disclosure: whoever is typing already knows how many times
// they have typed.
//
// A toast rather than the inline line this used to swap in. The second-factor
// card is the one page in the application where the outcome of the form is the
// outcome of the page, and the line under the field competed with the
// three other things the card already says. refuse leaves the digits in the
// field, so correcting a typo is still a matter of fixing one character.
func (h Handler) codeRejected(w http.ResponseWriter, r *http.Request, c Challenge, user model.User) {
	if left := maxChallengeAttempts - c.Attempts; left > 0 {
		refuse(w, r, http.StatusBadRequest, "That code is not right. "+attemptsLeft(left), "/auth/2fa")
		return
	}
	// The one place a second factor is recorded as having failed. Every earlier
	// wrong code is a typo until the last one, and writing a row per attempt
	// would let anyone with an email address fill an organization's log from the
	// sign-in page — see ActionMFAFailed. This runs under the auth-flow escape
	// because there is no session, and so no organization context, behind it.
	h.recordAuthFlow(r, user, audit.ActionMFAFailed, "sign-in abandoned after "+
		itoa(maxChallengeAttempts)+" incorrect codes")
	h.discardChallenge(r, c.ID)
	h.restartLogin(w, r, "Too many attempts. Request a new sign-in link.")
}

// recordAuthFlow writes an event for something that happened to a user who has
// no session yet, opening the auth-flow context recordUser's callers already
// hold. Best effort, like every other audit write.
func (h Handler) recordAuthFlow(r *http.Request, user model.User, action, detail string) {
	if err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		h.recordUser(ctx, r, user, action, detail)
		return nil
	}); err != nil {
		log.Printf("audit action=%s not recorded: %v", action, err)
	}
}

func attemptsLeft(n int) string {
	if n == 1 {
		return "One attempt left."
	}
	return itoa(n) + " attempts left."
}

// recordSignIn writes the event that ties a session to the sign-in that created
// it, so every later action can be traced back to it. Written inside the
// creating transaction, which is the only place holding both the organization
// and the new session id before a session context exists.
func (h Handler) recordSignIn(ctx context.Context, r *http.Request, user model.User, sessionID uuid.UUID, action string) {
	event := audit.Event{
		OrganizationID: uuidString(user.OrganizationID),
		ActorUserID:    user.ID.String(),
		ActorEmail:     user.Email,
		Action:         action,
		Target:         user.Email,
	}
	h.record(ctx, event.From(r, sessionID.String()))
}

// recordUser writes an event for something that happened to a user before any
// session exists, so there is no session id to attribute it to.
func (h Handler) recordUser(ctx context.Context, r *http.Request, user model.User, action, detail string) {
	event := audit.Event{
		OrganizationID: uuidString(user.OrganizationID),
		ActorUserID:    user.ID.String(),
		ActorEmail:     user.Email,
		Action:         action,
		Target:         user.Email,
		Detail:         detail,
	}
	h.record(ctx, event.From(r, ""))
}

// errInvalidCode covers both a wrong code and a correct one that has already
// been spent. They are one case to the user, and deliberately so: telling
// someone their code was "already used" confirms they guessed a real one.
var errInvalidCode = errors.New("that code is not valid")

// formValue reads a submitted field, tolerating the spaces authenticator apps
// put in the codes they display and that users copy along with them.
func formValue(r *http.Request, name string) string {
	return strings.TrimSpace(r.FormValue(name))
}

// formError renders a message into the inline result element an htmx form
// targets. Status 200 deliberately: htmx 2 does not swap a non-2xx response, so
// a 400 here would leave the user staring at an unchanged form with no
// indication of what went wrong. Non-htmx posts get the real status code.
func formError(w http.ResponseWriter, r *http.Request, message string) {
	if r.Header.Get("HX-Request") == "true" {
		authview.FormError(message).Render(r.Context(), w)
		return
	}
	http.Error(w, message, http.StatusBadRequest)
}

// hxRedirect sends htmx a full-page navigation and a plain form post a 303.
// htmx would otherwise follow the redirect itself and swap a whole page into
// the small element the form targets.
func hxRedirect(w http.ResponseWriter, r *http.Request, location string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", location)
		return
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// formatSecret groups the base32 secret into fours for the people who cannot
// scan a QR — a desktop-only authenticator, a machine with no camera — and have
// to type it. An unbroken twenty-character run is transcribed wrongly often
// enough to matter when the cost of a mistake is an authenticator that never
// produces a working code.
func formatSecret(secret string) string {
	var b strings.Builder
	for i, c := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func itoa(n int) string { return strconv.Itoa(n) }
