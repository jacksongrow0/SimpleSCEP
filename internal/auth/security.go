package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
	authview "github.com/jacksongrow0/SimpleSCEP/view/auth"
)

// lowRecoveryCodes is when the panel starts warning. Three is enough warning to
// act on, and few enough that it is not nagging from the day after enrolment.
//
// It matters more than it used to. Recovery codes are issued once and there is
// no way to ask for a fresh set, so running out is not an inconvenience that a
// button fixes — it is the last way back into an account whose authenticators
// are all lost.
const lowRecoveryCodes = 3

// This file is the second factor as its owner manages it: the authenticators
// they hold, the passkeys they have registered, and how many recovery codes are
// left.
//
// It renders into the account settings dialog rather than onto a page of its
// own. These settings belong to a person and not to an organization — none of
// them has an administrator view, at any role, because an administrator who
// could reset a colleague's authenticator would be a way around the requirement
// rather than a way to support it — and a top-level organization nav item said
// the opposite. The RLS policies on these tables have no
// organization arm to allow such a view even if the interface offered one.

// securityPanel renders the current state of the acting user's second factor. It
// is fetched when the Security tab is opened rather than rendered with every
// page, so the three queries below run only for people who look.
func (h Handler) securityPanel(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	// The confirmation this route needs is drawn here rather than raised by
	// middleware.StepUp, which is why the pattern is no longer in its list.
	//
	// The middleware's answer is a 403 that opens the standalone dialog, and
	// that dialog is the wrong shape for this one route. Every other guarded
	// action is a click somewhere on the page; this one is a tab inside a modal
	// that is already open, so the prompt landed on top of the dialog it was
	// about. Nothing is weakened by moving it: the actions inside the panel —
	// registering and removing factors — are each guarded in their own right,
	// so the gate here decides where the question is asked, not whether.
	if !session.SteppedUp(time.Now()) {
		h.renderLocked(w, r, userID, "")
		return
	}
	props, err := h.securityProps(r, session, userID)
	if err != nil {
		log.Printf("loading security panel: %v", err)
		http.Error(w, "could not load your security settings", http.StatusInternalServerError)
		return
	}
	// A stale session reaches this handler through StepUpDialog's replay rather
	// than through the tab that supplied an htmx target. Retarget the response so
	// the panel fragment cannot replace the whole document in that case.
	w.Header().Set("HX-Retarget", "#security-panel")
	w.Header().Set("HX-Reswap", "outerHTML")
	authview.SecurityPanel(props).Render(r.Context(), w)
}

// unlockSecurityPanel is the code form inside SecurityLocked submitting.
//
// It answers with the panel itself rather than with a 204 and a replay, so
// confirming and arriving are one round trip and the person never watches a
// fragment be fetched twice.
func (h Handler) unlockSecurityPanel(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	if message, ok := h.proveTOTP(w, r, session, userID); !ok {
		if message == "" {
			return
		}
		h.renderLocked(w, r, userID, message)
		return
	}
	// Read back, because the stamp this just wrote is what securityProps and
	// every control inside the panel are gated on; the session in this
	// request's context still carries the old one.
	session.SteppedUpAt = ptrTime(time.Now())
	props, err := h.securityProps(r, session, userID)
	if err != nil {
		log.Printf("loading security panel: %v", err)
		h.renderLocked(w, r, userID, "Your settings could not be loaded. Try again.")
		return
	}
	w.Header().Set("HX-Retarget", "#security-panel")
	w.Header().Set("HX-Reswap", "outerHTML")
	authview.SecurityPanel(props).Render(r.Context(), w)
}

func ptrTime(t time.Time) *time.Time { return &t }

// renderLocked draws the prompt in the panel's place, offering whatever this
// person can actually confirm with.
func (h Handler) renderLocked(w http.ResponseWriter, r *http.Request, userID uuid.UUID, message string) {
	methods, err := h.StepUpMethods(r.Context(), userID)
	if err != nil {
		log.Printf("listing step-up methods: %v", err)
		// An empty list still renders a prompt that says so, which is more use
		// than a 500 behind an open dialog.
		methods = nil
	}
	w.Header().Set("HX-Retarget", "#security-panel")
	w.Header().Set("HX-Reswap", "outerHTML")
	authview.SecurityLocked(authview.StepUpProps{
		Action:   "open your security settings",
		Methods:  stepUpViews(methods),
		Post:     "/security/panel",
		Target:   "#security-panel",
		Swap:     "outerHTML",
		FormID:   "security-unlock-form",
		ResultID: "security-unlock-result",
		Error:    message,
	}).Render(r.Context(), w)
}

// securityProps assembles everything the panel shows. Every query runs on the
// request's own transaction, where app.user_id is already set, so the
// user-scoped policies admit exactly this user's rows and no query needs to say
// so again.
func (h Handler) securityProps(r *http.Request, session Session, userID uuid.UUID) (authview.SecurityProps, error) {
	credentials, err := h.repo.TOTPCredentials(r.Context(), userID)
	if err != nil {
		return authview.SecurityProps{}, err
	}
	remaining, err := h.repo.CountRecoveryCodes(r.Context(), userID)
	if err != nil {
		return authview.SecurityProps{}, err
	}
	passkeys, err := h.repo.Passkeys(r.Context(), userID)
	if err != nil {
		return authview.SecurityProps{}, err
	}
	return authview.SecurityProps{
		Authenticators: authenticatorViews(credentials),
		// The last authenticator cannot be removed, so the button that would
		// remove it is not rendered at all. A control that is always refused
		// teaches people to ignore refusals.
		CanRemoveAuthenticator: len(credentials) > 1,
		RecoveryLeft:           remaining,
		RecoveryTotal:          recoveryCodeCount,
		RecoveryLow:            remaining <= lowRecoveryCodes,
		GraceMinutes:           int(StepUpGrace / time.Minute),
		Passkeys:               passkeyViews(passkeys),
		// Passkeys are unavailable rather than broken when APP_URL yields no
		// relying-party id; saying so beats a register button that always fails.
		PasskeysAvailable: h.webauthn != nil,
	}, nil
}

// authenticatorViews converts stored credentials into what the panel renders.
// The sealed secret and the last accepted step are deliberately left behind:
// neither means anything to the person reading the list, and the first is the
// factor itself.
func authenticatorViews(rows []TOTPCredential) []authview.AuthenticatorView {
	out := make([]authview.AuthenticatorView, 0, len(rows))
	for _, credential := range rows {
		out = append(out, authview.AuthenticatorView{
			ID: credential.ID.String(), Label: credential.Label,
			AddedAt: credential.ConfirmedAt, LastUsedAt: credential.LastUsedAt,
		})
	}
	return out
}

// passkeyViews converts stored credentials into what the panel renders. The
// public key, the AAGUID and the signature counter are deliberately left behind:
// none of them means anything to the person reading the list.
func passkeyViews(rows []Passkey) []authview.PasskeyView {
	out := make([]authview.PasskeyView, 0, len(rows))
	for _, p := range rows {
		out = append(out, authview.PasskeyView{
			ID: p.ID.String(), Label: p.Label, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt,
		})
	}
	return out
}

// beginTOTP starts registering a further authenticator, minting and parking a
// secret so the panel can render its QR.
//
// Behind step-up: adding a second factor from an unattended screen is how an
// attacker who found a logged-in laptop keeps the account after the owner
// notices. It is the same reasoning that guards passkey registration, and the
// same reasoning that guards removal.
func (h Handler) beginTOTP(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secret, err := h.pendingSessionSecret(r, sessionID, session.Email)
	if err != nil {
		log.Printf("starting authenticator enrolment: %v", err)
		http.Error(w, "could not start registration", http.StatusInternalServerError)
		return
	}
	h.renderPanel(w, r, session, userID, authview.SecurityProps{
		Enrolling: true, EnrollSecret: formatSecret(secret)})
}

// cancelTOTP abandons a half-finished enrolment. Clearing the parked secret is
// what makes the next attempt mint a fresh one, so a user who scanned a QR onto
// the wrong device is not stuck with it.
func (h Handler) cancelTOTP(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.repo.SetPendingTOTP(r.Context(), sessionID, nil, ""); err != nil {
		log.Printf("clearing pending authenticator: %v", err)
		http.Error(w, "could not cancel", http.StatusInternalServerError)
		return
	}
	h.renderPanel(w, r, session, userID, authview.SecurityProps{})
}

// totpQR serves the enrolment QR for a registration in progress.
//
// Its own no-store response rather than a data: URI, so the shared secret never
// lands in an HTML body — where it would sit in view-source, in any intermediary
// that buffers the page, and in htmx's swap history. It takes no parameters:
// there is nothing a caller can vary to be shown somebody else's secret, which
// is the same property GET /auth/2fa/qr.png has and the reason both are their
// own route rather than one route with a query string.
func (h Handler) totpQR(w http.ResponseWriter, r *http.Request) {
	session, _, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secret, err := h.pendingSessionSecret(r, sessionID, session.Email)
	if err != nil {
		log.Printf("reading pending authenticator secret: %v", err)
		http.Error(w, "no registration is in progress", http.StatusNotFound)
		return
	}
	key, err := keyFromSecret(session.Email, secret)
	if err != nil {
		log.Printf("building otpauth key: %v", err)
		http.Error(w, "registration unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, private")
	if err := writeQR(w, key); err != nil {
		log.Printf("rendering QR: %v", err)
	}
}

// pendingSessionSecret returns the unconfirmed secret of a registration started
// from the panel, minting and parking one on first use.
//
// Stored rather than regenerated per request for the reason Handler.pendingSecret
// gives about the sign-in path: the panel can be reopened and the QR re-rendered,
// and a fresh secret each time would silently invalidate what the user already
// scanned — presenting as an authenticator that produces permanently wrong codes.
func (h Handler) pendingSessionSecret(r *http.Request, sessionID uuid.UUID, email string) (string, error) {
	purpose := sessionEnrollPurpose(sessionID.String())
	sealed, _, err := h.repo.PendingTOTP(r.Context(), sessionID)
	if err != nil {
		return "", err
	}
	if len(sealed) > 0 {
		return unprotectTOTPSecret(r.Context(), h.protect, purpose, sealed)
	}
	key, err := newTOTPKey(email)
	if err != nil {
		return "", err
	}
	sealed, err = protectTOTPSecret(r.Context(), h.protect, purpose, key.Secret())
	if err != nil {
		return "", err
	}
	if err := h.repo.SetPendingTOTP(r.Context(), sessionID, sealed, ""); err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// confirmTOTP completes a registration started from the panel: the submitted
// code proves the authenticator holds the parked secret, so the secret is
// re-sealed under the user and stored as a further confirmed credential.
//
// No recovery codes are issued here, and that is the point of the split. They
// are issued once, when the account's first factor is enrolled; re-issuing them
// every time a device is added would void the set the user wrote down for the
// sake of an event that did not weaken it.
//
// Not itself behind step-up: beginTOTP is, and this can only complete an
// enrolment that call authorised. Asking for a second code here would mean
// typing two codes to register one device.
func (h Handler) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sealed, _, err := h.repo.PendingTOTP(r.Context(), sessionID)
	if err != nil || len(sealed) == 0 {
		h.renderPanel(w, r, session, userID, authview.SecurityProps{
			Error: "That registration has expired. Start again."})
		return
	}
	secret, err := unprotectTOTPSecret(r.Context(), h.protect, sessionEnrollPurpose(sessionID.String()), sealed)
	if err != nil {
		log.Printf("opening pending authenticator secret: %v", err)
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	// Keyed by session, like step-up: whoever is guessing here already holds one,
	// so the address they came from is not the identity worth limiting. Checked
	// after the secret is read so a refusal can re-render the enrolment the user
	// is part-way through rather than throwing it away.
	if !allow(h.limits.StepUp, "totp-add|"+session.ID) {
		h.renderPanel(w, r, session, userID, authview.SecurityProps{
			Enrolling: true, EnrollSecret: formatSecret(secret),
			Error: "Too many attempts. Wait a moment and try again."})
		return
	}
	step, valid := verifyTOTP(secret, formValue(r, "code"), time.Now(), 0)
	if !valid {
		h.renderPanel(w, r, session, userID, authview.SecurityProps{
			Enrolling: true, EnrollSecret: formatSecret(secret),
			Error: "That code is not right. Check your authenticator and try again."})
		return
	}

	// Re-sealed under the user rather than copied: the ciphertext that sat on the
	// session is bound to the session, and a confirmed credential must be bound to
	// the person, so that ending the session leaves nothing promotable behind.
	label := totpLabel(r.FormValue("label"))
	confirmed, err := protectTOTPSecret(r.Context(), h.protect, totpPurpose(session.UserID), secret)
	if err != nil {
		log.Printf("sealing confirmed secret: %v", err)
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	credentialID, err := h.repo.SaveTOTPCredential(r.Context(), userID, label, confirmed)
	if err != nil {
		log.Printf("saving authenticator: %v", err)
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	// The code just used is burned immediately, so the code that registered this
	// device cannot also be replayed as a sign-in code.
	if _, err := h.repo.AdvanceTOTPStep(r.Context(), credentialID, step); err != nil {
		log.Printf("burning registration code: %v", err)
	}
	if err := h.repo.SetPendingTOTP(r.Context(), sessionID, nil, ""); err != nil {
		log.Printf("clearing pending authenticator: %v", err)
	}
	h.record(r.Context(), actorEvent(r, session, audit.ActionMFAEnrolled, session.Email, label))
	toast.Now(w, r, toast.Success, "Authenticator “"+label+"” registered")
	h.renderPanel(w, r, session, userID, authview.SecurityProps{})
}

// deleteTOTP removes one authenticator, refusing to remove the last one. Behind
// step-up for the same reason registration is: an unattended screen must not be
// able to strip a factor.
func (h Handler) deleteTOTP(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid authenticator", http.StatusBadRequest)
		return
	}
	// Read before the delete: afterwards there is nothing left to name it by, and
	// the label is the part of the event a reader can act on.
	label := h.authenticatorLabel(r, userID, id)
	err = h.repo.DeleteTOTPCredential(r.Context(), userID, id)
	if errors.Is(err, ErrLastTOTPCredential) {
		h.renderPanel(w, r, session, userID, authview.SecurityProps{
			Error: "This is your only authenticator. Register another one before removing it."})
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		h.renderPanel(w, r, session, userID, authview.SecurityProps{
			Error: "That authenticator is no longer registered."})
		return
	}
	if err != nil {
		log.Printf("deleting authenticator: %v", err)
		http.Error(w, "could not remove that authenticator", http.StatusInternalServerError)
		return
	}
	h.record(r.Context(), actorEvent(r, session, audit.ActionMFARemoved, session.Email, label))
	toast.Now(w, r, toast.Success, "Authenticator “"+label+"” removed")
	h.renderPanel(w, r, session, userID, authview.SecurityProps{})
}

// authenticatorLabel names one credential for the audit log, best effort: a
// failure to read it must not stop the removal the user asked for.
func (h Handler) authenticatorLabel(r *http.Request, userID, id uuid.UUID) string {
	credentials, err := h.repo.TOTPCredentials(r.Context(), userID)
	if err != nil {
		log.Printf("naming authenticator for audit: %v", err)
		return ""
	}
	for _, credential := range credentials {
		if credential.ID == id {
			return credential.Label
		}
	}
	return ""
}

// renderPanel answers a panel action with the panel's new state, carrying
// through whatever the action wants to say about itself.
//
// HX-Retarget and HX-Reswap are set on the response rather than left to the form
// that posted, because a request refused by step-up is re-fired by
// StepUpDialog's htmx.ajax call, which has no target of its own and would
// otherwise swap this fragment over the whole document body.
func (h Handler) renderPanel(w http.ResponseWriter, r *http.Request, session Session, userID uuid.UUID, with authview.SecurityProps) {
	props, err := h.securityProps(r, session, userID)
	if err != nil {
		log.Printf("reloading security panel: %v", err)
		http.Error(w, "could not load your security settings", http.StatusInternalServerError)
		return
	}
	props.Enrolling, props.EnrollSecret, props.Error = with.Enrolling, with.EnrollSecret, with.Error
	w.Header().Set("HX-Retarget", "#security-panel")
	w.Header().Set("HX-Reswap", "outerHTML")
	authview.SecurityPanel(props).Render(r.Context(), w)
}

// stepUp accepts a code and stamps the session, which is what middleware.StepUp
// checks.
//
// It deliberately does not perform the action that prompted it. The dialog
// re-fires the original request afterwards, so this endpoint can never be
// tricked into triggering something the caller did not ask for — it only ever
// grants the grace.
// proveTOTP verifies a submitted code and stamps the session on success.
//
// It is shared by the two places a code is accepted — the standalone dialog and
// the prompt drawn inside the account dialog — which is the point: one path
// through the rate limit, the replay guard and the audit entry, whichever
// prompt collected the digits.
//
// Three outcomes rather than two. ("", true) is confirmed; (message, false) is a
// rejection the caller should draw in its own prompt; ("", false) means a
// response has already been written and the caller must not write another.
func (h Handler) proveTOTP(w http.ResponseWriter, r *http.Request, session Session, userID uuid.UUID) (string, bool) {
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	// Keyed by session rather than by address: whoever is guessing already holds
	// a session, so that is the identity worth limiting.
	if !allow(h.limits.StepUp, "stepup|"+session.ID) {
		return "Too many attempts. Wait a moment and try again.", false
	}

	credentialID, step, err := h.matchTOTP(r.Context(), userID, formValue(r, "code"))
	if errors.Is(err, sql.ErrNoRows) {
		// Unreachable while enrolment is mandatory, but a user whose factors were
		// cleared by an operator mid-session would land here.
		return "No authenticator is registered on your account.", false
	}
	if errors.Is(err, errInvalidCode) {
		h.record(r.Context(), actorEvent(r, session, audit.ActionStepUpFailed, session.Email, ""))
		return "That code is not right.", false
	}
	if err != nil {
		log.Printf("matching totp for step-up: %v", err)
		http.Error(w, "confirmation failed", http.StatusInternalServerError)
		return "", false
	}
	// The same replay guard as sign-in: the code that authorised this
	// confirmation cannot authorise a second one.
	advanced, err := h.repo.AdvanceTOTPStep(r.Context(), credentialID, step)
	if err != nil {
		log.Printf("advancing totp step: %v", err)
		http.Error(w, "confirmation failed", http.StatusInternalServerError)
		return "", false
	}
	if !advanced {
		return "That code has already been used. Wait for the next one.", false
	}
	if err := h.repo.StampStepUp(r.Context(), sessionID); err != nil {
		log.Printf("stamping step-up: %v", err)
		http.Error(w, "confirmation failed", http.StatusInternalServerError)
		return "", false
	}
	return "", true
}

// stepUpMethodList is what the standalone dialog fetches when it opens.
//
// It is fetched rather than rendered with the shell because the shell is on
// every authenticated page and this needs two queries. Paying them when a
// confirmation is actually asked for is the same bargain the security panel
// makes.
func (h Handler) stepUpMethodList(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	methods, err := h.StepUpMethods(r.Context(), userID)
	if err != nil {
		log.Printf("listing step-up methods: %v", err)
		methods = nil
	}
	authview.StepUpMethods(authview.StepUpProps{
		Methods:  stepUpViews(methods),
		Post:     "/security/step-up",
		Target:   "#step-up-result",
		Swap:     "innerHTML",
		FormID:   "step-up-form",
		ResultID: "step-up-result",
	}).Render(r.Context(), w)
}

func (h Handler) stepUp(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	message, ok := h.proveTOTP(w, r, session, userID)
	if !ok {
		if message != "" {
			formError(w, r, message)
		}
		return
	}
	// Two events on one header: the toast, and the signal the dialog closes and
	// replays on. htmx reads HX-Trigger before it decides whether to swap, so
	// both arrive despite the empty body.
	//
	// stepupdone is named rather than inferred from the response. The dialog
	// now fetches its own methods, so "a successful request from inside the
	// dialog" no longer means "the confirmation succeeded" — it is just as
	// likely to be the fragment arriving.
	stepUpAccepted(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// selfSession resolves the acting user for the routes that manage their own
// second factor. There is no role check and no feature gate on any of them: every
// user has a second factor because every user is required to, so every user must
// be able to manage it — including an auditor.
func (h Handler) selfSession(w http.ResponseWriter, r *http.Request) (Session, uuid.UUID, bool) {
	session, ok := FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return Session{}, uuid.Nil, false
	}
	userID, err := uuid.Parse(session.UserID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return Session{}, uuid.Nil, false
	}
	return session, userID, true
}

// stepUpAccepted writes the header that tells the standalone dialog it may
// close and replay, along with the confirmation the user sees.
//
// Both events go out in one HX-Trigger because a second Set would replace the
// first: the header holds one JSON object naming every event to raise.
func stepUpAccepted(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "true" {
		return
	}
	trigger, err := json.Marshal(map[string]any{
		"toast":      toast.New(toast.Success, "Confirmed"),
		"stepupdone": map[string]string{},
	})
	if err != nil {
		return
	}
	w.Header().Set("HX-Trigger", string(trigger))
}
