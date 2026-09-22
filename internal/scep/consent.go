package scep

// Onboarding an Intune tenant through the SimpleSCEP multi-tenant Entra
// application, replacing the app registration each customer used to build by
// hand.
//
// Microsoft warns that the `tenant` parameter on an admin-consent callback is
// attacker-supplied and must never be treated as an authenticated identity
// (learn.microsoft.com/entra/identity-platform/v2-admin-consent). Consent alone
// therefore cannot say *whose* directory was connected: anyone could replay
// another customer's tenant ID into their own callback and bind a directory they
// do not own. So the flow runs in two legs.
//
//	leg 1  OpenID Connect sign-in against /organizations. We redeem the code
//	       ourselves over TLS, so the tid claim in the returned id_token is a
//	       first-hand statement from Microsoft about which directory the signed-in
//	       administrator belongs to. No signature check is needed for the same
//	       reason: the token never passed through the browser.
//	leg 2  admin consent, pinned to that tid, and the callback must come back
//	       naming the same directory.
//
// Both legs are bound to the browser by a signed, short-lived cookie carrying a
// nonce echoed as the OAuth state parameter.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
	"github.com/jacksongrow0/SimpleSCEP/internal/web"
)

const (
	consentCookie   = "intune_consent"
	consentTTL      = 10 * time.Minute
	signInPath      = "/integrations/intune/signin/callback"
	consentPath     = "/integrations/intune/consent/callback"
	stageSignIn     = "signin"
	stageConsent    = "consent"
	consentScope    = msGraphResourceURL + ".default"
	signInScope     = "openid profile"
	restartMessage  = "That did not come back from Microsoft as expected. Start the connection again."
	declinedMessage = "Failed to connect Microsoft Intune: the administrator declined or could not approve consent. Please try again and ensure you have the correct permissions."
)

// consentState is the in-flight connection, held only in the browser cookie.
type consentState struct {
	Stage    string `json:"stage"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	TenantID string `json:"tenant_id"`
	OrgID    string `json:"org_id"`
}

// connectIntune starts leg 1. It deliberately does not touch the auth method
// row: nothing is written until consent is proved.
func (h Handler) connectIntune(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	if !h.intuneApp.Deployed() {
		enroll.FormError(w, r, errors.New("the Intune connector is not deployed"))
		return
	}
	// The directory binds the organization, not an endpoint, so an administrator
	// may connect it before creating any SCEP endpoint at all.
	nonce, err := enroll.RandomSecret()
	if err != nil {
		enroll.FormError(w, r, errors.New("could not start the Microsoft sign-in"))
		return
	}
	verifier, err := enroll.RandomSecret()
	if err != nil {
		enroll.FormError(w, r, errors.New("could not start the Microsoft sign-in"))
		return
	}
	h.setConsentCookie(w, consentState{Stage: stageSignIn, Nonce: nonce, Verifier: verifier, OrgID: s.OrgID})

	// Sign in against /organizations rather than /common: personal Microsoft
	// accounts cannot grant admin consent, and a tenant-scoped URL is not
	// available yet because the tenant is what this leg is discovering.
	query := url.Values{
		"client_id":             {h.intuneApp.ClientID},
		"response_type":         {"code"},
		"response_mode":         {"query"},
		"redirect_uri":          {h.publicURL + signInPath},
		"scope":                 {signInScope},
		"state":                 {nonce},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	h.leaveForMicrosoft(w, r, intuneAuthority+"organizations/oauth2/v2.0/authorize?"+query.Encode())
}

// intuneSignInCallback ends leg 1 and starts leg 2.
func (h Handler) intuneSignInCallback(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	state, ok := h.readConsentCookie(r, s.OrgID, stageSignIn)
	if !ok {
		h.consentFailed(w, r, restartMessage)
		return
	}
	query := r.URL.Query()
	if !matchesNonce(state.Nonce, query.Get("state")) {
		h.consentFailed(w, r, restartMessage)
		return
	}
	if message, failed := entraError(query); failed {
		h.consentFailed(w, r, message)
		return
	}
	tenantID, err := h.redeemSignIn(r.Context(), query.Get("code"), state.Verifier)
	if err != nil {
		h.consentFailed(w, r, err.Error())
		return
	}
	nonce, err := enroll.RandomSecret()
	if err != nil {
		h.consentFailed(w, r, restartMessage)
		return
	}
	h.setConsentCookie(w, consentState{Stage: stageConsent, Nonce: nonce, TenantID: tenantID, OrgID: s.OrgID})

	// Pinning the consent URL to the directory leg 1 proved means a callback
	// naming any other directory is a mismatch we can reject outright.
	consent := url.Values{
		"client_id":    {h.intuneApp.ClientID},
		"scope":        {consentScope},
		"redirect_uri": {h.publicURL + consentPath},
		"state":        {nonce},
	}
	h.leaveForMicrosoft(w, r, intuneAuthority+url.PathEscape(tenantID)+"/v2.0/adminconsent?"+consent.Encode())
}

// intuneConsentCallback ends leg 2 and stores the connection.
func (h Handler) intuneConsentCallback(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	state, ok := h.readConsentCookie(r, s.OrgID, stageConsent)
	if !ok {
		h.consentFailed(w, r, restartMessage)
		return
	}
	query := r.URL.Query()
	if !matchesNonce(state.Nonce, query.Get("state")) {
		h.consentFailed(w, r, restartMessage)
		return
	}
	if message, failed := entraError(query); failed {
		h.consentFailed(w, r, message)
		return
	}
	if !strings.EqualFold(query.Get("admin_consent"), "true") {
		h.consentFailed(w, r, declinedMessage)
		return
	}
	// The identity check the whole two-leg shape exists for.
	if !strings.EqualFold(query.Get("tenant"), state.TenantID) {
		h.consentFailed(w, r, "Consent came back for a different Microsoft Entra directory than the one you signed in to. Start the connection again.")
		return
	}
	if err := h.service.VerifyIntuneTenant(r.Context(), state.TenantID); err != nil {
		h.consentFailed(w, r, "Microsoft has not finished applying the consent yet. Wait a minute and connect again. ("+err.Error()+")")
		return
	}
	if err := h.service.ConnectIntune(r.Context(), s.OrgID, state.TenantID); err != nil {
		h.consentFailed(w, r, err.Error())
		return
	}
	// Recorded here and not in connectIntune: that handler only starts the
	// redirect, and an administrator who abandons the Microsoft sign-in has
	// connected nothing. The tenant is the detail — binding a directory decides
	// whose devices this organization will validate SCEP requests for.
	h.record(r, s, audit.ActionSCEPIntuneConnected, "Microsoft Intune", "tenant "+state.TenantID)
	h.clearConsentCookie(w)
	// Success used to be a bare redirect while every failure had a banner, so
	// the one outcome an administrator was waiting to see confirmed was the one
	// that looked identical to having done nothing.
	toast.Announce(w, r, toast.Success, "Microsoft Intune connected. SCEP requests from this tenant can now be validated.")
	http.Redirect(w, r, "/protocols", http.StatusSeeOther)
}

// disconnectIntune unbinds the directory. Consent itself lives in the customer's
// own tenant, which they withdraw by deleting the SimpleSCEP enterprise
// application there.
func (h Handler) disconnectIntune(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	if err := h.service.DisconnectIntune(r.Context(), s.OrgID); err != nil {
		enroll.FormError(w, r, errors.New("could not disconnect Microsoft Intune"))
		return
	}
	h.record(r, s, audit.ActionSCEPIntuneDisconnected, "Microsoft Intune", "")
	web.Done(w, r, "/protocols", "Microsoft Intune disconnected. Withdraw consent in your own tenant to finish.")
}

// redeemSignIn exchanges the authorization code and reports which directory the
// administrator signed in to. The id_token is read without verifying its
// signature: it was fetched here, directly from Microsoft over TLS, so there is
// no untrusted party between issuer and reader for a signature to protect
// against.
func (h Handler) redeemSignIn(ctx context.Context, code, verifier string) (string, error) {
	if code == "" {
		return "", errors.New(restartMessage)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {h.intuneApp.ClientID},
		"client_secret": {h.intuneApp.ClientSecret},
		"code":          {code},
		"redirect_uri":  {h.publicURL + signInPath},
		"code_verifier": {verifier},
		"scope":         {signInScope},
	}
	endpoint := intuneAuthority + "organizations/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New(restartMessage)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("Could not reach Microsoft to complete the sign-in: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", errors.New(restartMessage)
	}
	if resp.StatusCode/100 != 2 {
		// The AADSTS code names the actual misconfiguration and carries no
		// secret material, so it is worth showing.
		return "", fmt.Errorf("Microsoft rejected the sign-in: %s", strings.TrimSpace(string(body)))
	}
	var parsed struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.IDToken == "" {
		return "", errors.New("Microsoft did not return an identity token for the signed-in administrator")
	}
	tenantID, err := tenantFromIDToken(parsed.IDToken)
	if err != nil {
		return "", err
	}
	return tenantID, nil
}

// tenantFromIDToken pulls the tid claim out of a JWT payload.
func tenantFromIDToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("Microsoft returned an unreadable identity token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("Microsoft returned an unreadable identity token")
	}
	var claims struct {
		TenantID string `json:"tid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.TenantID == "" {
		return "", errors.New("Microsoft did not say which directory the administrator belongs to")
	}
	return claims.TenantID, nil
}

// entraError turns an OAuth error callback into something an administrator can
// act on. A declined or unapproved consent is by far the common case.
func entraError(query url.Values) (string, bool) {
	code := query.Get("error")
	if code == "" {
		return "", false
	}
	switch code {
	case "access_denied", "consent_required":
		return declinedMessage, true
	}
	description := strings.TrimSpace(query.Get("error_description"))
	if description == "" {
		description = code
	}
	return "Microsoft returned an error: " + description, true
}

// leaveForMicrosoft sends the browser to Entra. htmx will not follow a 303 into
// another origin, so posts from the page get an HX-Redirect instead.
func (h Handler) leaveForMicrosoft(w http.ResponseWriter, r *http.Request, location string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", location)
		return
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// consentFailed abandons the flow and reports why on the protocols page. The
// callbacks arrive as full-page navigations, so there is no htmx target to swap
// the message into.
func (h Handler) consentFailed(w http.ResponseWriter, r *http.Request, message string) {
	h.clearConsentCookie(w)
	http.Redirect(w, r, "/protocols?intune_error="+url.QueryEscape(message), http.StatusSeeOther)
}

func (h Handler) setConsentCookie(w http.ResponseWriter, state consentState) {
	encoded, err := json.Marshal(state)
	if err != nil {
		return
	}
	value := base64.RawURLEncoding.EncodeToString(encoded)
	http.SetCookie(w, &http.Cookie{
		Name: consentCookie,
		// Signed so a sibling subdomain cannot toss in a cookie naming a
		// directory the administrator never signed in to.
		Value:    url.QueryEscape(value + "." + auth.Sign(value, h.authSecret)),
		Path:     "/",
		HttpOnly: true,
		Secure:   auth.SecureCookie(),
		// Lax, not Strict: the cookie has to survive the top-level navigation
		// back from login.microsoftonline.com.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(consentTTL.Seconds()),
	})
}

func (h Handler) readConsentCookie(r *http.Request, orgID, stage string) (consentState, bool) {
	var state consentState
	cookie, err := r.Cookie(consentCookie)
	if err != nil {
		return state, false
	}
	raw, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return state, false
	}
	value, sig, ok := strings.Cut(raw, ".")
	if !ok || !auth.VerifySignature(value, sig, h.authSecret) {
		return state, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || json.Unmarshal(decoded, &state) != nil {
		return state, false
	}
	// A cookie from another organization's flow, or replayed against the wrong
	// leg, is not usable here.
	return state, state.Stage == stage && state.OrgID == orgID
}

func (h Handler) clearConsentCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     consentCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   auth.SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func matchesNonce(want, got string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// pkceChallenge is the S256 transform from RFC 7636. PKCE binds the redeemed
// code to this flow even though the client is confidential, so a code leaked out
// of the redirect cannot be spent elsewhere.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
