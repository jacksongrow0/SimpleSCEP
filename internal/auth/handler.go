package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/model"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
	"github.com/jacksongrow0/SimpleSCEP/internal/mail"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
	authview "github.com/jacksongrow0/SimpleSCEP/view/auth"
)

type Handler struct {
	repo   Repository
	mail   mail.Service
	audit  audit.Repository
	secret string
	appURL string
	limits Limits
	// protect seals the TOTP secret. Without it enrolment is refused rather than
	// falling back to storing the secret in the clear.
	protect Protector
	// webauthn is nil when APP_URL cannot yield a relying-party id. Passkeys are
	// then simply unavailable; TOTP is the mandatory factor and does not depend
	// on it, so the service still works.
	webauthn *webauthn.WebAuthn
	// setupToken gates POST /setup, the one-time bootstrap that creates this
	// deployment's singleton organization and its first administrator. It is
	// generated once at startup and logged there — see cmd/main.go — and is
	// empty once an organization already exists, which /setup treats the same
	// as a wrong token: refused.
	setupToken string
}

// Limiter is the shape of middleware.RateLimiter. It is an interface here
// because middleware imports this package for auth.Session, so this package
// cannot import middleware back.
type Limiter interface {
	Allow(key string) bool
}

// Limits holds the per-concern budgets for the unauthenticated surface. They are
// separate limiters rather than one shared budget for the reason RateLimiter's
// own comment gives: a burst of sign-in attempts must not spend the allowance
// that stops someone mailbox-bombing a named customer.
//
// All of these are per-process, so behind more than one instance they bound a
// single bot rather than a distributed one. That is the right expectation to
// have of them: the control that actually bounds guessing is in the database,
// on the challenge row.
type Limits struct {
	// LoginIP bounds how much mail one source can cause to be sent.
	LoginIP Limiter
	// LoginEmail bounds how often one address can be mailed, whoever asks. This
	// is the anti-harassment limit: without it anyone can fill a customer's inbox
	// with real sign-in links from our sending domain.
	LoginEmail Limiter
	// Signup bounds organization and user creation.
	Signup Limiter
	// Redeem bounds token redemption. A 256-bit token is not guessable, so this
	// mostly bounds database round-trips from a bot spraying the endpoint.
	Redeem Limiter
	// StepUp bounds confirmation attempts, keyed by session: whoever is guessing
	// here already holds one, so the address they came from is not the identity
	// worth limiting.
	StepUp Limiter
}

// allow reports whether a limiter admits the key, treating a nil limiter as
// unlimited so a Handler built by a test does not have to construct four of them.
func allow(l Limiter, key string) bool {
	return l == nil || l.Allow(key)
}

func NewHandler(repo Repository, mail mail.Service, secret, appURL string, auditRepo audit.Repository, limits Limits, protect Protector, wa *webauthn.WebAuthn, setupToken string) Handler {
	return Handler{repo: repo, mail: mail, secret: secret, appURL: appURL,
		audit: auditRepo, limits: limits, protect: protect, webauthn: wa, setupToken: setupToken}
}

// link builds an emailed magic-link URL from the configured APP_URL. It never
// falls back to request headers (Host, X-Forwarded-Proto): those are
// client-controlled, and a forged Host would send the recipient a working
// login link pointing at an attacker's domain — from our own sending address,
// in a mail they asked for. Callers must abandon the send when this fails
// rather than mail a link built from anything else.
func (h Handler) link(path, token string) (string, error) {
	base, err := url.Parse(h.appURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return "", errors.New("valid APP_URL is required for login links")
	}
	base.Path = path
	base.RawQuery = "token=" + url.QueryEscape(token)
	return base.String(), nil
}

// record writes an audit event for something that has already happened. A
// failure to record must not undo or report against the change itself, so it is
// logged and swallowed; the alternative is telling an administrator their role
// change failed when it did not.
func (h Handler) record(ctx context.Context, e audit.Event) {
	if err := h.audit.Record(ctx, e); err != nil {
		log.Printf("audit org=%s action=%s not recorded: %v", e.OrganizationID, e.Action, err)
	}
}

// actorEvent seeds an event with the acting session and where the request came
// from, so each call site only says what happened.
func actorEvent(r *http.Request, s Session, action, target, detail string) audit.Event {
	event := audit.Event{OrganizationID: s.OrgID, ActorUserID: s.UserID, ActorEmail: s.Email,
		Action: action, Target: target, Detail: detail}
	return event.From(r, s.ID)
}

func (h Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", h.login)
	mux.HandleFunc("POST /login", h.sendLogin)
	// The one-time bootstrap: creates this deployment's singleton organization
	// and its first administrator. Gated by setupToken rather than open the way
	// signup once was, because this is a self-hosted, single-organization
	// application — there is no second organization to create after the first.
	mux.HandleFunc("GET /setup", h.setup)
	mux.HandleFunc("POST /setup", h.completeSetup)
	mux.HandleFunc("GET /auth/email", h.email)
	mux.HandleFunc("GET /auth/invite", h.invite)
	// The second factor. Everything here is authorised by the challenge cookie
	// and none of it can mint a session without verifying something, which is
	// why it may live under the session-exempt /auth/ prefix.
	mux.HandleFunc("GET /auth/2fa", h.twoFactor)
	// The page a completed enrolment lands on. It is under /auth/ with the rest
	// of the flow even though its reader now holds a session, because it is the
	// last step of the sign-in rather than the first of the dashboard, and what
	// authorises it is the one-shot cookie the enrolment set — not the session.
	mux.HandleFunc("GET /auth/recovery-codes", h.recoveryCodes)
	mux.HandleFunc("GET /auth/2fa/qr.png", h.twoFactorQR)
	mux.HandleFunc("POST /auth/2fa/enroll", h.confirmEnrollment)
	mux.HandleFunc("POST /auth/2fa/totp", h.verifyCode)
	mux.HandleFunc("POST /auth/2fa/recovery", h.verifyRecovery)
	mux.HandleFunc("POST /auth/2fa/passkey/begin", h.beginPasskeyLogin)
	mux.HandleFunc("POST /auth/2fa/passkey/finish", h.finishPasskeyLogin)
	mux.HandleFunc("POST /logout", h.logout)
	// Post-session security management. Under /security/ rather than /auth/
	// precisely so it stays behind the session — see middleware.public.
	//
	// There is no GET /security page: all of this renders into the account
	// settings dialog, because every setting here belongs to the person rather
	// than to the organization.
	mux.HandleFunc("GET /security/panel", h.securityPanel)
	mux.HandleFunc("POST /security/step-up", h.stepUp)
	// A confirmation given with a passkey rather than a code. Neither half is
	// in middleware.stepUpPatterns: these are how a confirmation is given, so
	// guarding them behind one would be a loop with no way in.
	mux.HandleFunc("GET /security/step-up/methods", h.stepUpMethodList)
	mux.HandleFunc("POST /security/step-up/passkey/begin", h.beginStepUpPasskey)
	mux.HandleFunc("POST /security/step-up/passkey/finish", h.finishStepUpPasskey)
	// POST is the Security tab's own prompt submitting. It answers with the
	// panel, so confirming and arriving are one round trip.
	mux.HandleFunc("POST /security/panel", h.unlockSecurityPanel)
	mux.HandleFunc("POST /security/totp/begin", h.beginTOTP)
	mux.HandleFunc("POST /security/totp/cancel", h.cancelTOTP)
	mux.HandleFunc("POST /security/totp/confirm", h.confirmTOTP)
	mux.HandleFunc("GET /security/totp/qr.png", h.totpQR)
	mux.HandleFunc("POST /security/totp/{id}/delete", h.deleteTOTP)
	mux.HandleFunc("POST /security/passkeys/begin", h.beginPasskeyRegistration)
	mux.HandleFunc("POST /security/passkeys/finish", h.finishPasskeyRegistration)
	mux.HandleFunc("POST /security/passkeys/{id}/delete", h.deletePasskey)
	mux.HandleFunc("POST /settings/profile", h.updateProfile)
	mux.HandleFunc("POST /settings/organization", h.updateOrganization)
	mux.HandleFunc("POST /settings/notifications", h.updateNotifications)
	mux.HandleFunc("POST /settings/invitations", h.createInvitation)
	mux.HandleFunc("POST /settings/invitations/{id}/delete", h.revokeInvitation)
	mux.HandleFunc("POST /settings/invitations/{id}/resend", h.resendInvitation)
	mux.HandleFunc("POST /settings/users/{id}/role", h.updateUserRole)
	mux.HandleFunc("POST /settings/users/{id}/delete", h.deleteUser)
}

// ErrAlreadySetUp means an organization already exists — the bootstrap has
// already run, whether by this request racing another or by a deployment
// reaching /setup after its first admin is long since signed up.
var ErrAlreadySetUp = errors.New("this instance is already set up")

// validSetupToken reports whether the supplied token matches the one
// generated at startup. Constant-time, and false whenever either side is
// empty: an empty h.setupToken means an organization already existed at
// boot, and an empty comparison of two zero-length slices must never read as
// a match.
func (h Handler) validSetupToken(token string) bool {
	return h.setupToken != "" && token != "" &&
		subtle.ConstantTimeCompare([]byte(token), []byte(h.setupToken)) == 1
}

func (h Handler) setup(w http.ResponseWriter, r *http.Request) {
	if _, ok := FromContext(r.Context()); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// AuthFlow, not a bare query: organization carries FORCE ROW LEVEL
	// SECURITY, and an unauthenticated request has no app.organization_id for
	// its policy to match — without the bypass, an existing organization is
	// invisible here and this page renders the bootstrap form a second time.
	var exists bool
	err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		var err error
		exists, err = h.repo.OrganizationExists(ctx)
		return err
	})
	if err != nil {
		h.linkFailed(w, r, "That page could not be loaded. Try again.")
		return
	}
	if exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	authview.Setup(r.URL.Query().Get("token")).Render(r.Context(), w)
}

func (h Handler) completeSetup(w http.ResponseWriter, r *http.Request) {
	if !allow(h.limits.Signup, "ip|"+clientip.ClientIP(r)) {
		toast.Fail(w, r, http.StatusTooManyRequests, "Too many attempts. Try again shortly.")
		return
	}
	if !h.validSetupToken(strings.TrimSpace(r.FormValue("token"))) {
		toast.Fail(w, r, http.StatusForbidden, "That setup link is invalid or has expired. Check the server log for the current one.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(r.FormValue("email"))
	orgName := strings.TrimSpace(r.FormValue("organization"))
	if name == "" || email == "" || orgName == "" {
		toast.Fail(w, r, http.StatusBadRequest, "A name, an email address and an organization name are all required")
		return
	}
	var userEmail string
	var token string
	err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		// Rechecked here, inside the transaction that does the insert, so two
		// concurrent submissions cannot both pass the GET-time check and both
		// try to create the organization. The organization_singleton index is
		// the backstop if this check itself races.
		exists, err := h.repo.OrganizationExists(ctx)
		if err != nil {
			return err
		}
		if exists {
			return ErrAlreadySetUp
		}
		if _, err := h.repo.UserByEmail(ctx, email); err == nil {
			return ErrEmailExists
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		orgID, err := h.repo.CreateOrganization(ctx, orgName)
		if err != nil {
			return err
		}
		user, err := h.repo.CreateUser(ctx, orgID, email, name, "administrator")
		if err != nil {
			return err
		}
		token, err = magicToken()
		if err != nil {
			return err
		}
		userEmail = user.Email
		return h.repo.CreateMagicLink(ctx, user.ID, tokenHash(token), time.Now().UTC().Add(magicLinkTTL))
	})
	if errors.Is(err, ErrAlreadySetUp) {
		toast.Fail(w, r, http.StatusConflict, "This instance has already been set up. Sign in instead.")
		return
	}
	if errors.Is(err, ErrEmailExists) {
		// This is an account-existence oracle, and it stays one on purpose, unlike
		// the one removed from sendLogin. The alternative is to accept the signup
		// and say nothing, which leaves someone staring at a confirmation for an
		// organization that was never created and a mail that never arrives. A
		// signup form that refuses a duplicate is also universal, so withholding
		// the answer here buys little: the same question can be asked of any
		// service the address is used with. The rate limit above is what makes it
		// impractical to ask it a million times.
		toast.Fail(w, r, http.StatusConflict, "An account already exists for that address. Sign in instead.")
		return
	}
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That account could not be created. Try again.")
		return
	}
	link, err := h.link("/auth/email", token)
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That account could not be created. Try again.")
		return
	}
	verify := mail.Action{
		Heading:     "Confirm your email address",
		Body:        "Your SimpleSCEP account is almost ready. Confirm this address to finish signing up.",
		ButtonLabel: "Confirm and open SimpleSCEP",
		URL:         link,
		Expiry:      magicLinkExpiryLabel,
		Unrequested: "If you did not sign up for SimpleSCEP, you can ignore this email and no account will be created.",
	}
	if err := h.mail.Send(r.Context(),
		mail.NoReply.Apply(verify.Message(userEmail, "Confirm your SimpleSCEP email"))); err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "The account was created but the verification email could not be sent. Try signing in to have another sent.")
		return
	}
	confirm(w, r, toast.Success,
		"We sent a verification link to "+userEmail+". Open it to finish setup.", "/login")
}

func (h Handler) login(w http.ResponseWriter, r *http.Request) {
	if _, ok := FromContext(r.Context()); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// A browser part-way through a sign-in gets sent back to where it was rather
	// than being offered a second magic link it does not need. Without this, the
	// back button from the code prompt lands on a form whose only effect is to
	// invalidate the challenge already in progress.
	if id, err := ReadChallengeCookie(r, h.secret); err == nil && id != "" {
		http.Redirect(w, r, "/auth/2fa", http.StatusSeeOther)
		return
	}
	authview.Login().Render(r.Context(), w)
}

// loginAccepted is the only thing POST /login ever says. It is deliberately
// uninformative: the previous "user not found" told an anonymous caller which of
// two addresses belonged to a customer, which is a membership oracle over the
// whole user table and the first step of a targeted phishing campaign.
//
// Every branch below returns it — found, not found, rate limited, and mail
// failed. A distinguishable status code would give the answer back just as
// surely as the words did, which is why the rate-limited branch is a 200 and not
// a 429: "you are being throttled on this address" means "this address exists
// and someone is already working on it".
const loginAccepted = "If that address has an account, a sign-in link is on its way."

// loginSent is how every branch of POST /login answers, in whichever shape the
// caller can render.
//
// htmx gets the confirmation as markup that replaces the form. The outcome of
// this page is the whole page — one field and one button, both of which have
// just done their job — so leaving them on screen under a toast asks the reader
// to work out whether anything happened. authview.LoginSent says the same
// conditional thing loginAccepted says, for the same reason.
//
// A plain form post has nothing to swap it into, so it keeps the toast: the
// browser is sent back to /login, and the stored message is the only thing that
// survives the redirect.
func loginSent(w http.ResponseWriter, r *http.Request, email string) {
	if r.Header.Get("HX-Request") == "true" {
		// The address is echoed back into the page, and the page is the answer
		// to a POST. Nothing here is worth a cache entry on the way.
		w.Header().Set("Cache-Control", "no-store")
		authview.LoginSent(email).Render(r.Context(), w)
		return
	}
	confirm(w, r, toast.Info, loginAccepted, "/login")
}

func (h Handler) sendLogin(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	// Keyed on a hash, not the address. The limiter map lives in process memory
	// for a minute at a time, and a plaintext key would make it an enumerable
	// list of customer addresses in any heap dump.
	if !allow(h.limits.LoginIP, "ip|"+clientip.ClientIP(r)) ||
		!allow(h.limits.LoginEmail, "email|"+tokenHash(strings.ToLower(email))[:16]) {
		loginSent(w, r, email)
		return
	}

	var userEmail string
	var token string
	err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		user, err := h.repo.UserByEmail(ctx, email)
		if err != nil {
			return err
		}
		token, err = magicToken()
		if err != nil {
			return err
		}
		if err := h.repo.CreateMagicLink(ctx, user.ID, tokenHash(token), time.Now().UTC().Add(magicLinkTTL)); err != nil {
			return err
		}
		userEmail = user.Email
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		loginSent(w, r, email)
		return
	}
	if err != nil {
		// An internal failure is not an oracle — it does not depend on whether the
		// address exists — but it is also not worth a different page for. Log it
		// and say the same thing.
		log.Printf("login link not created: %v", err)
		loginSent(w, r, email)
		return
	}

	link, err := h.link("/auth/email", token)
	if err != nil {
		log.Printf("login link not built: %v", err)
		loginSent(w, r, email)
		return
	}
	signIn := mail.Action{
		Heading:     "Sign in to SimpleSCEP",
		Body:        "Use the button below to sign in. You will be asked for your second factor afterwards.",
		ButtonLabel: "Sign in",
		URL:         link,
		Expiry:      magicLinkExpiryLabel,
		Unrequested: "If you did not try to sign in, you can ignore this email. Nobody can use this link without your second factor.",
	}
	h.sendAsync(r, userEmail,
		mail.NoReply.Apply(signIn.Message(userEmail, "Your SimpleSCEP sign-in link")))
	loginSent(w, r, email)
}

// sendAsync mails the message after the response has been written.
//
// The wording of the two branches above is identical; their timing was not.
// Only the branch with a real account reached mail.Send, which is a network
// round-trip to Resend, so an attacker could tell the two apart with a
// stopwatch and never read the body at all. Returning first makes both branches
// cost the same — one database round-trip — because neither waits for mail.
//
// A send failure is logged rather than reported for the same reason: only an
// address that exists can fail to be mailed, so surfacing the failure would hand
// back the answer the neutral response withholds. That is the trade record()
// already makes for audit writes.
//
// context.WithoutCancel is load-bearing. The request context is cancelled the
// moment the handler returns, and this goroutine outlives it by design, so
// without it every login mail would be aborted in flight. The token row is
// already committed by AuthFlow before this runs, so a user who beats the mail
// to the inbox still finds a live link.
func (h Handler) sendAsync(r *http.Request, to string, msg mail.Message) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Second)
	go func() {
		defer cancel()
		// middleware.Recover wraps requests, not goroutines. Nothing else stands
		// between a panicking mail provider and the process exiting, and a
		// sign-in email is the last thing that should be able to take the service
		// down — so the recover is here rather than assumed elsewhere.
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic sending mail to %s: %v", to, p)
			}
		}()
		if err := h.mail.Send(ctx, msg); err != nil {
			log.Printf("mail to %s not sent: %v", to, err)
		}
	}()
}

func (h Handler) email(w http.ResponseWriter, r *http.Request) {
	// A limited caller is sent to /login with the reason rather than handed a
	// bare 429: this URL is reached by clicking a link in a mail client, and
	// everything that can go wrong with it has to land somewhere a person can
	// act on. The link is not spent — the redemption below never ran — so
	// waiting a minute and clicking again works.
	if !allow(h.limits.Redeem, "token|"+clientip.ClientIP(r)) {
		h.linkFailed(w, r, "Too many sign-in attempts from this network. Wait a minute and open the link again.")
		return
	}
	// Redeeming the link proves the first factor and nothing more, so it opens a
	// challenge rather than a session. The sign-in audit event moves with the
	// session: recording it here would claim someone signed in when they had
	// only opened their mail, and the id it carried would name a session that
	// may never be created.
	token := r.URL.Query().Get("token")
	if err := h.beginChallenge(w, r, func(ctx context.Context) (model.User, error) {
		return h.repo.UserByMagicToken(ctx, token)
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// A dead link is the most ordinary thing that happens to a magic
			// link — it was clicked twice, or it sat in an inbox over lunch —
			// and it used to be answered with a bare 401 on a blank page, which
			// reads as a broken product rather than as an expired link. The
			// form that issues a new one is on /login, so that is where this
			// goes, with a sentence saying which of the two happened.
			h.linkRefused(w, r, token)
			return
		}
		log.Printf("login challenge not created: %v", err)
		h.linkFailed(w, r, "That sign-in link could not be opened. Request a new one.")
		return
	}
	http.Redirect(w, r, "/auth/2fa", http.StatusSeeOther)
}

// linkFailed reports a link that led nowhere, on the page best placed to do
// something about it.
//
// That page is /login for a browser with no session, because the form that
// issues a new link is on it. For a browser that already holds one it is the
// dashboard: /login would only bounce them straight back to it, and the bounce
// would consume the pending message on the way past — middleware.Flash clears
// the flash on any page render, including one that turns out to be a redirect.
func (h Handler) linkFailed(w http.ResponseWriter, r *http.Request, message string) {
	destination := "/login"
	if _, ok := FromContext(r.Context()); ok {
		destination = "/"
	}
	toast.Announce(w, r, toast.Error, message)
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

// linkRefused explains a sign-in link that did not work.
//
// Redemption deletes the row it matched, so a token that resolves to nothing
// has either expired or already been spent, and the two are told apart by
// whether the row is still there: an expired link is still in the table until
// it is cleaned up, a redeemed one is not. Neither answer says anything a
// stranger could not already infer — they are holding the token — and the
// difference decides what the person does next. "Expired" means send another
// one; "already used" means look for the tab that is already signed in, or
// suspect that someone else opened the mail.
func (h Handler) linkRefused(w http.ResponseWriter, r *http.Request, token string) {
	message := "That sign-in link has already been used. Request a new one below."
	var pending bool
	if err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		var err error
		pending, err = h.repo.MagicLinkExists(ctx, token)
		return err
	}); err != nil {
		log.Printf("classifying refused login link: %v", err)
		// Neither answer is available, so say the thing both have in common.
		message = "That sign-in link is no longer valid. Request a new one below."
	} else if pending {
		message = "That sign-in link has expired. Sign-in links last 15 minutes; request a new one below."
	}
	h.linkFailed(w, r, message)
}

func (h Handler) invite(w http.ResponseWriter, r *http.Request) {
	if !allow(h.limits.Redeem, "token|"+clientip.ClientIP(r)) {
		h.linkFailed(w, r, "Too many attempts from this network. Wait a minute and open the invitation again.")
		return
	}
	// An invitee is a new user with no second factor, so this lands in the same
	// enrolment path a fresh signup does. One code path, three entry points.
	if err := h.beginChallenge(w, r, func(ctx context.Context) (model.User, error) {
		return h.repo.AcceptInvitation(ctx, r.URL.Query().Get("token"))
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Same reasoning as the magic link above, with a different remedy:
			// nobody can reissue their own invitation, so the message has to
			// name who can.
			h.linkFailed(w, r,
				"That invitation link has expired or has already been used. Ask an administrator to send another.")
			return
		}
		log.Printf("invitation challenge not created: %v", err)
		h.linkFailed(w, r, "That invitation could not be opened. Ask an administrator to send another.")
		return
	}
	http.Redirect(w, r, "/auth/2fa", http.StatusSeeOther)
}

func (h Handler) logout(w http.ResponseWriter, r *http.Request) {
	if session, ok := FromContext(r.Context()); ok {
		if id, err := uuid.Parse(session.ID); err == nil {
			_ = h.repo.DeleteSession(r.Context(), id)
			h.record(r.Context(), actorEvent(r, session, audit.ActionSignedOut, session.Email, ""))
		}
	}
	ClearCookie(w)
	// Said on the way out rather than left implicit. /login is rendered by
	// layout.Base, and Base carries the toast region, so there is somewhere for
	// this to land — see the note in middleware.requireLogin, which used to
	// record the opposite.
	toast.Announce(w, r, toast.Success, "You have been signed out.")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h Handler) createInvitation(w http.ResponseWriter, r *http.Request) {
	session, orgID, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		toast.Fail(w, r, http.StatusBadRequest, "An email address is required")
		return
	}
	role, ok := validRole(w, r.FormValue("role"))
	if !ok {
		return
	}
	// The dialog has always rendered a "Full name" field and this handler has
	// always ignored it, so the invited person appeared in the team list under the
	// local part of their address. It is stored on the invitation rather than
	// applied here, because the user row does not exist until they accept.
	name := strings.TrimSpace(r.FormValue("name"))
	token, err := magicToken()
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That invitation could not be created. Try again.")
		return
	}
	if err := h.repo.CreateInvitation(r.Context(), orgID, email, name, role, tokenHash(token), time.Now().UTC().Add(invitationTTL)); err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That invitation could not be created. Try again.")
		return
	}
	if !h.sendInvitation(w, r, email, token) {
		return
	}
	h.record(r.Context(), actorEvent(r, session, audit.ActionUserInvited, email, "as "+roleLabel(role)))
	confirm(w, r, toast.Success, "Invitation sent to "+email, "/users")
}

// invitationTTL is how long an invitation link works. It is long because the
// person receiving it has no account yet and may not check that mailbox daily,
// and it is the reason a revoke path has to exist: for a week, a mistyped address
// is a working sign-up into somebody else's organization.
const invitationTTL = 7 * 24 * time.Hour

// magicLinkTTL and magicLinkExpiryLabel are the same fact twice, and they are
// beside each other so they cannot drift. The label goes in the email; a link
// whose lifetime is never stated is one people sit on until it stops working, and
// then report as broken.
const (
	magicLinkTTL         = 15 * time.Minute
	magicLinkExpiryLabel = "15 minutes"
)

// sendInvitation mails the link, reporting the refusal itself and returning
// whether the caller should carry on.
//
// Shared by the create and resend paths so the two cannot drift in what the
// invited person receives. The failure message no longer tells administrators to
// "remove it and invite them again" — which for a long time named an action that
// did not exist anywhere in the product — because Resend now does exactly that in
// one press.
func (h Handler) sendInvitation(w http.ResponseWriter, r *http.Request, email, token string) bool {
	link, err := h.link("/auth/invite", token)
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That invitation could not be created. Try again.")
		return false
	}
	invite := mail.Action{
		Heading:     "You have been invited to SimpleSCEP",
		Body:        "SimpleSCEP is a managed private certificate authority. Accept the invitation to set up your access.",
		ButtonLabel: "Accept the invitation",
		URL:         link,
		Expiry:      "7 days",
		Unrequested: "If you were not expecting this, you can ignore this email.",
	}
	if err := h.mail.Send(r.Context(),
		mail.Notifications.Apply(invite.Message(email, "You're invited to SimpleSCEP"))); err != nil {
		toast.Fail(w, r, http.StatusInternalServerError,
			"The invitation was recorded but the email could not be sent. Use Resend on the team page to try again.")
		return false
	}
	return true
}

// revokeInvitation makes a pending invitation's emailed token stop working.
//
// Nothing could do this before. Invitations were written and never shown, so an
// address typed wrong left a token valid for a week with no way to see it or
// withdraw it — and the only advice the product offered was to remove it, which
// was not possible.
func (h Handler) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	session, orgID, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That invitation could not be found.")
		return
	}
	invitation, err := h.repo.InvitationByID(r.Context(), orgID, id)
	if err != nil {
		toast.Fail(w, r, http.StatusNotFound, "That invitation is no longer pending. Reload the page.")
		return
	}
	if err := h.repo.DeleteInvitation(r.Context(), orgID, id); err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That invitation could not be revoked. Try again.")
		return
	}
	h.record(r.Context(), actorEvent(r, session, audit.ActionUserInvitationRevoked, invitation.Email, ""))
	confirm(w, r, toast.Success, "Invitation to "+invitation.Email+" revoked", "/users")
}

// resendInvitation issues a new link and invalidates the old one.
//
// The old token is not recoverable — only its hash is stored — so a resend is
// necessarily a re-mint. That is also the safer behaviour: whatever happened to
// the first email, exactly one link is live afterwards.
func (h Handler) resendInvitation(w http.ResponseWriter, r *http.Request) {
	session, orgID, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That invitation could not be found.")
		return
	}
	invitation, err := h.repo.InvitationByID(r.Context(), orgID, id)
	if err != nil {
		toast.Fail(w, r, http.StatusNotFound, "That invitation is no longer pending. Reload the page.")
		return
	}
	token, err := magicToken()
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That invitation could not be reissued. Try again.")
		return
	}
	// Delete then recreate rather than update the hash in place: it is one
	// statement fewer to get wrong, and it resets the seven days from now, which
	// is what a person pressing Resend means.
	if err := h.repo.DeleteInvitation(r.Context(), orgID, id); err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That invitation could not be reissued. Try again.")
		return
	}
	if err := h.repo.CreateInvitation(r.Context(), orgID, invitation.Email, invitation.Name, invitation.Role,
		tokenHash(token), time.Now().UTC().Add(invitationTTL)); err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That invitation could not be reissued. Try again.")
		return
	}
	if !h.sendInvitation(w, r, invitation.Email, token) {
		return
	}
	h.record(r.Context(), actorEvent(r, session, audit.ActionUserInvited, invitation.Email, "reissued"))
	confirm(w, r, toast.Success, "Invitation resent to "+invitation.Email, "/users")
}

// maxUserNameLength matches user.name's column width, so an over-long value is
// a message naming the field rather than a constraint violation surfacing as a
// 500 the person cannot act on.
const maxUserNameLength = 255

// updateProfile changes the acting user's own display name.
//
// Self-scoped and behind no role check, like the second-factor routes: this is
// the person's own account, and an auditor is still
// entitled to spell their own name correctly. There is deliberately no
// administrator path to rename a colleague — the name is what the audit log
// shows beside their actions, and one member editing another's would make that
// attribution somebody else's to write.
func (h Handler) updateProfile(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		toast.Fail(w, r, http.StatusBadRequest, "A name is required")
		return
	}
	if len(name) > maxUserNameLength {
		toast.Fail(w, r, http.StatusBadRequest, "That name is too long")
		return
	}
	if name == session.Name {
		confirm(w, r, toast.Info, "That is already your name", backTo(r, "/"))
		return
	}
	if err := h.repo.UpdateUserName(r.Context(), userID, name); err != nil {
		log.Printf("auth user=%s name change failed: %v", session.UserID, err)
		toast.Fail(w, r, http.StatusInternalServerError, "That could not be saved. Try again.")
		return
	}
	// Recorded because the name is how this person is identified in every other
	// entry, so a rename is context a reader of those entries needs.
	h.record(r.Context(), actorEvent(r, session, audit.ActionUserRenamed, session.Email,
		"was "+session.Name))
	confirm(w, r, toast.Success,
		"Saved. Your new name appears everywhere after your next page load.", backTo(r, "/"))
}

// defaultExpiryAlertDays mirrors the schema default, used when the form omits
// the field.
const defaultExpiryAlertDays = 30

// updateNotifications stores the organization's certificate-expiry alert
// preference from the account settings dialog.
//
// Administrators only, because the setting is the organization's rather than the
// person's: the alert names the whole fleet and goes to every administrator, so
// letting any member switch it off would silence a warning for colleagues who
// never saw the control.
func (h Handler) updateNotifications(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	// An unchecked switch posts nothing at all, which is what makes the
	// presence of the field the signal rather than its value.
	enabled := r.FormValue("expiry_alerts") == "true"
	days := defaultExpiryAlertDays
	if raw := strings.TrimSpace(r.FormValue("expiry_alert_days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		// Bounded here as well as by the CHECK constraint, so a bad value is a
		// 400 naming the field rather than a constraint violation surfacing as
		// a 500 the customer cannot act on.
		if err != nil || parsed < 1 || parsed > 365 {
			http.Error(w, "warning window must be between 1 and 365 days", http.StatusBadRequest)
			return
		}
		days = parsed
	}
	if err := h.repo.SetExpiryAlerts(r.Context(), orgID, enabled, days); err != nil {
		log.Printf("auth org=%s notification preference save failed: %v", orgID, err)
		toast.Fail(w, r, http.StatusInternalServerError, "That preference could not be saved. Try again.")
		return
	}
	// This used to redirect to "/", so saving a preference from the account
	// dialog silently threw the administrator off whatever page they were on
	// with no word that anything had been stored. The htmx path now leaves the
	// dialog open, which is where they still are.
	confirm(w, r, toast.Success, notificationMessage(enabled, days), backTo(r, "/organization"))
}

func (h Handler) updateOrganization(w http.ResponseWriter, r *http.Request) {
	session, orgID, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		toast.Fail(w, r, http.StatusBadRequest, "An organization name is required")
		return
	}
	org, err := h.repo.Organization(r.Context(), orgID)
	if err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "Your organization could not be read. Try again.")
		return
	}
	if err := h.repo.UpdateOrganization(r.Context(), orgID, name); err != nil {
		toast.Fail(w, r, http.StatusInternalServerError, "That could not be saved. Try again.")
		return
	}
	if org.Name != name {
		h.record(r.Context(), actorEvent(r, session, audit.ActionOrganizationRenamed, name, "was "+org.Name))
	}
	confirm(w, r, toast.Success, "Organization details saved", "/organization")
}

func (h Handler) updateUserRole(w http.ResponseWriter, r *http.Request) {
	session, orgID, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That is not a user on this organization")
		return
	}
	role, ok := validRole(w, r.FormValue("role"))
	if !ok {
		return
	}
	if session.UserID == userID.String() {
		toast.Fail(w, r, http.StatusBadRequest, "You cannot change your own role")
		return
	}
	// Read before the change: afterwards the previous role is gone, and it is
	// the part of a role change worth recording.
	before, err := h.repo.User(r.Context(), orgID, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			toast.Fail(w, r, http.StatusNotFound, "That user is no longer on this organization")
			return
		}
		toast.Fail(w, r, http.StatusInternalServerError, "That role change could not be saved. Try again.")
		return
	}
	if err := h.repo.UpdateUserRole(r.Context(), orgID, userID, role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			toast.Fail(w, r, http.StatusNotFound, "That user is no longer on this organization")
			return
		}
		toast.Fail(w, r, http.StatusInternalServerError, "That role change could not be saved. Try again.")
		return
	}
	if before.Role != role {
		h.record(r.Context(), actorEvent(r, session, audit.ActionUserRoleChanged, before.Email,
			roleLabel(before.Role)+" → "+roleLabel(role)))
	}
	confirm(w, r, toast.Success, before.Email+"'s role is now "+roleLabel(role), "/users")
}

func (h Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	session, orgID, ok := h.adminSession(w, r)
	if !ok {
		return
	}
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		toast.Fail(w, r, http.StatusBadRequest, "That is not a user on this organization")
		return
	}
	if session.UserID == userID.String() {
		toast.Fail(w, r, http.StatusBadRequest, "You cannot remove yourself")
		return
	}
	// Read before the delete: once the row is gone there is nothing left to
	// name the person the log is about.
	removed, err := h.repo.User(r.Context(), orgID, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		toast.Fail(w, r, http.StatusInternalServerError, "That user could not be removed. Try again.")
		return
	}
	if err := h.repo.DeleteUser(r.Context(), orgID, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			toast.Fail(w, r, http.StatusNotFound, "That user is no longer on this organization")
			return
		}
		toast.Fail(w, r, http.StatusInternalServerError, "That user could not be removed. Try again.")
		return
	}
	h.record(r.Context(), actorEvent(r, session, audit.ActionUserRemoved, removed.Email, roleLabel(removed.Role)))
	// An empty 200 used to end this. The form is a plain post, so the browser
	// replaced the users page with a blank white document and the
	// administrator had to navigate back to find out whether it had worked.
	toast.Announce(w, r, toast.Success, "Removed "+removed.Email)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (h Handler) adminSession(w http.ResponseWriter, r *http.Request) (Session, uuid.UUID, bool) {
	session, ok := FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return Session{}, uuid.Nil, false
	}
	if !session.IsAdmin() {
		http.Error(w, "administrators only", http.StatusForbidden)
		return Session{}, uuid.Nil, false
	}
	orgID, err := uuid.Parse(session.OrgID)
	if err != nil {
		http.Error(w, "organization required", http.StatusBadRequest)
		return Session{}, uuid.Nil, false
	}
	return session, orgID, true
}

// roleLabel renders a stored role for a reader of the audit log.
func roleLabel(role string) string {
	switch role {
	case "administrator":
		return "Administrator"
	case "certificate_manager":
		return "Certificate manager"
	case "auditor":
		return "Auditor"
	case "":
		return "unknown"
	}
	return role
}

// validRole resolves a submitted role. An omitted role is refused rather than
// defaulted: administrators may destroy CA key versions, so a form that forgets
// the field — or a direct POST that leaves it out — must not mint one.
func validRole(w http.ResponseWriter, role string) (string, bool) {
	switch strings.TrimSpace(role) {
	case "administrator":
		return "administrator", true
	case "certificate_manager", "auditor":
		return strings.TrimSpace(role), true
	default:
		http.Error(w, "invalid role", http.StatusBadRequest)
		return "", false
	}
}

func magicToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// tokenHash is what goes in the database; the token itself only ever exists in
// the email. A database backup or a read replica therefore carries no usable
// sign-in, which plaintext tokens did.
//
// SHA-256 and not argon2id, which is the reverse of the choice est_credential
// makes for its secrets. Those are short enough to guess, so the cost of a guess
// is the defence. A magic token is 256 bits from crypto/rand: there is nothing
// to guess, and the only thing a slow hash would slow down is our own sign-in
// path. Hex rather than base64 so a stored row greps against a log line.
//
// The comparison this feeds is an indexed equality in Postgres, not a byte
// compare in Go, so there is deliberately no constant-time helper here: the
// input is an unguessable random value, and there is no secret on our side of
// the comparison to leak by timing.
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// backTo returns the page a plain form post came from, so a setting saved in a
// dialog leaves the reader where they were. It accepts only a same-origin path,
// because what arrives here is a header the client controls.
func backTo(r *http.Request, fallback string) string {
	ref, err := url.Parse(r.Referer())
	if err != nil || ref.Path == "" || !strings.HasPrefix(ref.Path, "/") ||
		strings.HasPrefix(ref.Path, "//") {
		return fallback
	}
	if ref.Host != "" && ref.Host != r.Host {
		return fallback
	}
	return ref.Path
}

func notificationMessage(enabled bool, days int) string {
	if !enabled {
		return "Certificate expiry alerts are off"
	}
	return "Expiry alerts on, " + strconv.Itoa(days) + " day" + expiryPlural(days) + " ahead"
}

func expiryPlural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
