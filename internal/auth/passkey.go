package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
	authview "github.com/jacksongrow0/SimpleSCEP/view/auth"
)

// The passkey ceremonies are the only browser-facing JSON in this application,
// and the exception is unavoidable rather than a change of house style. The
// WebAuthn API takes and returns ArrayBuffers nested inside structured objects;
// there is no form-encoded representation of a PublicKeyCredential, and
// PublicKeyCredential.toJSON() is the platform's own answer to serialising one.
// Everything else about these routes — where they sit, what authorises them,
// how failures are reported — follows the same rules as the rest of the package.

// writeJSON sends a ceremony's options or its result.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writing json: %v", err)
	}
}

// beginPasskeyLogin starts an assertion for a browser holding a challenge.
//
// The page starts one of these on arrival as well as on the button, so this is
// reached once per visit to the second-factor prompt by accounts that hold no
// passkey at all. That costs one query and answers 404, which the caller
// treats as "nothing to offer" — it is not an error, and it is why the branch
// below says so with a status rather than a log line.
func (h Handler) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "passkeys are not configured", http.StatusNotFound)
		return
	}
	if !allow(h.limits.Redeem, "mfa|"+clientip.ClientIP(r)) {
		http.Error(w, "too many attempts; try again shortly", http.StatusTooManyRequests)
		return
	}
	c, user, ok := h.challenge(w, r)
	if !ok {
		return
	}

	var options *protocol.CredentialAssertion
	err := h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		wu, err := h.webAuthnUser(ctx, user.ID, user.Email, user.Name)
		if err != nil {
			return err
		}
		if len(wu.credentials) == 0 {
			return errNoPasskeys
		}
		var data *webauthn.SessionData
		options, data, err = h.webauthn.BeginLogin(wu)
		if err != nil {
			return err
		}
		encoded, err := encodeSessionData(data)
		if err != nil {
			return err
		}
		return h.repo.SetChallengeCeremony(ctx, c.ID, encoded)
	})
	if errors.Is(err, errNoPasskeys) {
		http.Error(w, "no passkey is registered on this account", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("beginning passkey login: %v", err)
		http.Error(w, "could not start passkey sign-in", http.StatusInternalServerError)
		return
	}
	writeJSON(w, options)
}

// finishPasskeyLogin verifies an assertion and, on success, creates the session.
// This is the second of the two places that can mint one; like the TOTP path it
// only does so after verifying something.
func (h Handler) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "passkeys are not configured", http.StatusNotFound)
		return
	}
	// Spending an attempt here as well as on the TOTP path: a malformed-assertion
	// loop is otherwise free, and the challenge counter is the control that works
	// across processes.
	c, user, ok := h.spend(w, r)
	if !ok {
		return
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(http.MaxBytesReader(w, r.Body, maxCeremonyBody))
	if err != nil {
		http.Error(w, "that passkey response could not be read", http.StatusBadRequest)
		return
	}

	var sessionID uuid.UUID
	err = h.repo.AuthFlow(r.Context(), func(ctx context.Context) error {
		raw, err := h.repo.ChallengeCeremony(ctx, c.ID)
		if err != nil {
			return err
		}
		data, err := decodeSessionData(raw)
		if err != nil {
			return err
		}
		wu, err := h.webAuthnUser(ctx, user.ID, user.Email, user.Name)
		if err != nil {
			return err
		}
		credential, err := h.webauthn.ValidateLogin(wu, *data, parsed)
		if err != nil {
			return errInvalidCode
		}
		// A counter that did not move forward means the authenticator was cloned,
		// or a backup of it was restored. Refused rather than merely flagged:
		// accepting it would make the counter decorative.
		advanced, err := h.repo.AdvancePasskeyCounter(ctx, credential.ID, credential.Authenticator.SignCount)
		if err != nil {
			return err
		}
		if !advanced {
			if err := h.repo.FlagPasskeyClone(ctx, credential.ID); err != nil {
				return err
			}
			h.recordUser(ctx, r, user, audit.ActionPasskeyCloneWarning,
				"signature counter did not advance; sign-in refused")
			return errClonedAuthenticator
		}
		// The ceremony is spent; clearing it stops a captured response being
		// replayed against the same challenge.
		if err := h.repo.SetChallengeCeremony(ctx, c.ID, nil); err != nil {
			return err
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
	if errors.Is(err, errClonedAuthenticator) {
		http.Error(w, "This passkey has been refused. Use your authenticator app instead, "+
			"then remove and re-register it from your account settings.", http.StatusForbidden)
		return
	}
	if errors.Is(err, errInvalidCode) {
		http.Error(w, "That passkey was not accepted.", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("finishing passkey login: %v", err)
		http.Error(w, "passkey sign-in failed", http.StatusInternalServerError)
		return
	}

	ClearChallengeCookie(w)
	SetCookie(w, sessionID.String(), h.secret, time.Now().Add(sessionTTL))
	// The fetch that sent this reads the header and navigates; it cannot follow a
	// redirect itself without losing the Set-Cookie.
	w.Header().Set("HX-Redirect", "/")
	writeJSON(w, map[string]bool{"ok": true})
}

// beginPasskeyRegistration starts an attestation for a signed-in user. Behind
// step-up: registering a second factor from an unattended screen would hand the
// account over.
func (h Handler) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "passkeys are not configured", http.StatusNotFound)
		return
	}
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	wu, err := h.webAuthnUser(r.Context(), userID, session.Email, session.Name)
	if err != nil {
		log.Printf("loading passkeys: %v", err)
		http.Error(w, "could not start registration", http.StatusInternalServerError)
		return
	}
	// Excluding what is already registered makes the authenticator say "you
	// already have one of these" rather than silently creating a duplicate that
	// the unique index would then refuse at the very end of the ceremony.
	exclude := make([]protocol.CredentialDescriptor, 0, len(wu.credentials))
	for _, c := range wu.credentials {
		exclude = append(exclude, c.Descriptor())
	}
	options, data, err := h.webauthn.BeginRegistration(wu, webauthn.WithExclusions(exclude))
	if err != nil {
		log.Printf("beginning registration: %v", err)
		http.Error(w, "could not start registration", http.StatusInternalServerError)
		return
	}
	encoded, err := encodeSessionData(data)
	if err != nil {
		log.Printf("encoding ceremony: %v", err)
		http.Error(w, "could not start registration", http.StatusInternalServerError)
		return
	}
	if err := h.repo.SetSessionCeremony(r.Context(), sessionID, encoded); err != nil {
		log.Printf("storing ceremony: %v", err)
		http.Error(w, "could not start registration", http.StatusInternalServerError)
		return
	}
	writeJSON(w, options)
}

// finishPasskeyRegistration stores a newly created credential.
func (h Handler) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "passkeys are not configured", http.StatusNotFound)
		return
	}
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	label := passkeyLabel(r.URL.Query().Get("label"))

	parsed, err := protocol.ParseCredentialCreationResponseBody(http.MaxBytesReader(w, r.Body, maxCeremonyBody))
	if err != nil {
		http.Error(w, "that passkey response could not be read", http.StatusBadRequest)
		return
	}
	raw, err := h.repo.SessionCeremony(r.Context(), sessionID)
	if err != nil {
		log.Printf("reading ceremony: %v", err)
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	data, err := decodeSessionData(raw)
	if err != nil {
		http.Error(w, "no registration is in progress; start again", http.StatusBadRequest)
		return
	}
	wu, err := h.webAuthnUser(r.Context(), userID, session.Email, session.Name)
	if err != nil {
		log.Printf("loading passkeys: %v", err)
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	credential, err := h.webauthn.CreateCredential(wu, *data, parsed)
	if err != nil {
		http.Error(w, "That passkey was not accepted.", http.StatusBadRequest)
		return
	}
	if err := h.repo.SavePasskey(r.Context(), userID, fromCredential(credential, label)); err != nil {
		// The unique index on credential_id is what refuses an authenticator
		// already registered to another account.
		log.Printf("saving passkey: %v", err)
		http.Error(w, "That authenticator is already registered.", http.StatusConflict)
		return
	}
	if err := h.repo.SetSessionCeremony(r.Context(), sessionID, nil); err != nil {
		log.Printf("clearing ceremony: %v", err)
	}
	h.record(r.Context(), actorEvent(r, session, audit.ActionPasskeyRegistered, session.Email, label))
	writeJSON(w, map[string]bool{"ok": true})
}

// deletePasskey removes one credential. Behind step-up for the same reason
// registration is: an unattended screen must not be able to strip a factor.
func (h Handler) deletePasskey(w http.ResponseWriter, r *http.Request) {
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid passkey", http.StatusBadRequest)
		return
	}
	if err := h.repo.DeletePasskey(r.Context(), userID, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.renderPanel(w, r, session, userID, authview.SecurityProps{
				Error: "That passkey is no longer registered."})
			return
		}
		log.Printf("deleting passkey: %v", err)
		http.Error(w, "could not remove that passkey", http.StatusInternalServerError)
		return
	}
	// Removing a passkey never leaves an account without a second factor: at
	// least one authenticator is mandatory and the delete path refuses to remove
	// the last one, so this is always a reduction from two methods to one rather
	// than to none.
	h.record(r.Context(), actorEvent(r, session, audit.ActionPasskeyRemoved, session.Email, ""))
	toast.Now(w, r, toast.Success, "Passkey removed")
	h.renderPanel(w, r, session, userID, authview.SecurityProps{})
}

// webAuthnUser assembles the library's view of a user from their stored
// credentials.
func (h Handler) webAuthnUser(ctx context.Context, userID uuid.UUID, email, name string) (webAuthnUser, error) {
	rows, err := h.repo.Passkeys(ctx, userID)
	if err != nil {
		return webAuthnUser{}, err
	}
	credentials := make([]webauthn.Credential, 0, len(rows))
	for _, p := range rows {
		// A credential already flagged as cloned is left out of both ceremonies,
		// so it can neither be asserted with nor be silently re-enrolled.
		if p.CloneWarning {
			continue
		}
		credentials = append(credentials, p.credential())
	}
	return webAuthnUser{id: userID, email: email, name: name, credentials: credentials}, nil
}

var (
	errNoPasskeys          = errors.New("no passkey registered")
	errClonedAuthenticator = errors.New("authenticator signature counter did not advance")
)

// A passkey as a way of confirming, rather than a way of signing in.
//
// Until this existed the answer to every confirmation was a six-digit code,
// including for people who hold a passkey and sign in with one. The ceremony is
// the login assertion — prove possession of a registered credential — but it
// ends by stamping the session's step-up rather than by minting a session,
// because there is already a session and it is the caller's.
//
// It is deliberately not in middleware.stepUpPatterns. These two routes are how
// a confirmation is given, so guarding them behind a confirmation is a loop with
// no way in.

// beginStepUpPasskey starts an assertion against the signed-in user's own
// credentials.
func (h Handler) beginStepUpPasskey(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "passkeys are not configured", http.StatusNotFound)
		return
	}
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// The same limiter the code path spends, keyed the same way. A confirmation
	// is a confirmation whichever factor answers it, and leaving one of the two
	// unmetered would make the choice of factor a way around the limit.
	if !allow(h.limits.StepUp, "stepup|"+session.ID) {
		http.Error(w, "Too many attempts. Wait a moment and try again.", http.StatusTooManyRequests)
		return
	}

	wu, err := h.webAuthnUser(r.Context(), userID, session.Email, session.Name)
	if err != nil {
		log.Printf("loading passkeys for step-up: %v", err)
		http.Error(w, "could not start confirmation", http.StatusInternalServerError)
		return
	}
	if len(wu.credentials) == 0 {
		http.Error(w, "no passkey is registered on this account", http.StatusNotFound)
		return
	}
	options, data, err := h.webauthn.BeginLogin(wu)
	if err != nil {
		log.Printf("beginning step-up assertion: %v", err)
		http.Error(w, "could not start confirmation", http.StatusInternalServerError)
		return
	}
	encoded, err := encodeSessionData(data)
	if err != nil {
		log.Printf("encoding ceremony: %v", err)
		http.Error(w, "could not start confirmation", http.StatusInternalServerError)
		return
	}
	if err := h.repo.SetSessionCeremony(r.Context(), sessionID, encoded); err != nil {
		log.Printf("storing ceremony: %v", err)
		http.Error(w, "could not start confirmation", http.StatusInternalServerError)
		return
	}
	writeJSON(w, options)
}

// finishStepUpPasskey verifies the assertion and stamps the grace.
func (h Handler) finishStepUpPasskey(w http.ResponseWriter, r *http.Request) {
	if h.webauthn == nil {
		http.Error(w, "passkeys are not configured", http.StatusNotFound)
		return
	}
	session, userID, ok := h.selfSession(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(session.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(http.MaxBytesReader(w, r.Body, maxCeremonyBody))
	if err != nil {
		http.Error(w, "that passkey response could not be read", http.StatusBadRequest)
		return
	}
	raw, err := h.repo.SessionCeremony(r.Context(), sessionID)
	if err != nil {
		log.Printf("reading ceremony: %v", err)
		http.Error(w, "confirmation failed", http.StatusInternalServerError)
		return
	}
	data, err := decodeSessionData(raw)
	if err != nil {
		http.Error(w, "no confirmation is in progress; start again", http.StatusBadRequest)
		return
	}
	wu, err := h.webAuthnUser(r.Context(), userID, session.Email, session.Name)
	if err != nil {
		log.Printf("loading passkeys for step-up: %v", err)
		http.Error(w, "confirmation failed", http.StatusInternalServerError)
		return
	}
	credential, err := h.webauthn.ValidateLogin(wu, *data, parsed)
	if err != nil {
		h.record(r.Context(), actorEvent(r, session, audit.ActionStepUpFailed, session.Email, "passkey"))
		http.Error(w, "That passkey was not accepted.", http.StatusForbidden)
		return
	}
	// The same clone check sign-in makes, and for the same reason. A signature
	// counter that has not advanced means the credential was copied or a backup
	// of it was restored. Refusing it at sign-in but accepting it here would
	// make confirmation the weaker of the two doors, which is exactly backwards:
	// what it guards is the ability to add and remove factors.
	advanced, err := h.repo.AdvancePasskeyCounter(r.Context(), credential.ID, credential.Authenticator.SignCount)
	if err != nil {
		log.Printf("advancing passkey counter: %v", err)
		http.Error(w, "confirmation failed", http.StatusInternalServerError)
		return
	}
	if !advanced {
		if err := h.repo.FlagPasskeyClone(r.Context(), credential.ID); err != nil {
			log.Printf("flagging passkey clone: %v", err)
		}
		h.record(r.Context(), actorEvent(r, session, audit.ActionPasskeyCloneWarning, session.Email,
			"signature counter did not advance; confirmation refused"))
		http.Error(w, "That passkey was not accepted.", http.StatusForbidden)
		return
	}
	// Spent before the stamp, so a replayed assertion cannot buy a second
	// confirmation out of the same ceremony.
	if err := h.repo.SetSessionCeremony(r.Context(), sessionID, nil); err != nil {
		log.Printf("clearing ceremony: %v", err)
	}
	if err := h.repo.StampStepUp(r.Context(), sessionID); err != nil {
		log.Printf("stamping step-up: %v", err)
		http.Error(w, "confirmation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
