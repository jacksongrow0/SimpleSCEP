package scep

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	"github.com/jacksongrow0/SimpleSCEP/internal/middleware"
	"github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/jacksongrow0/SimpleSCEP/internal/web"
	homeview "github.com/jacksongrow0/SimpleSCEP/view/home"
)

const maxMessageSize = 2 << 20

type Handler struct {
	db        *sql.DB
	repo      Repository
	service   Service
	limiter   *middleware.RateLimiter
	publicURL string
	// intuneApp and authSecret serve the Entra consent flow in consent.go: the
	// application connected directories consent to, and the key its state cookie is
	// signed with.
	intuneApp  IntuneApp
	authSecret string
	http       *http.Client
	audit      audit.Repository
}

// record writes an audit event for a change that has already been made.
// Recording is never allowed to fail the change it describes, so a failure is
// logged and swallowed.
func (h Handler) record(r *http.Request, s auth.Session, action, target, detail string) {
	event := audit.Event{OrganizationID: s.OrgID, ActorUserID: s.UserID, ActorEmail: s.Email,
		Action: action, Target: target, Detail: detail}
	if err := h.audit.Record(r.Context(), event.From(r, s.ID)); err != nil {
		log.Printf("audit org=%s action=%s not recorded: %v", s.OrgID, action, err)
	}
}

func RegisterRoutes(mux *http.ServeMux, db *sql.DB, keys pki.KeyProvider, publicURL string, intuneApp IntuneApp, authSecret string) {
	repo := NewRepository(db)
	client := &http.Client{Timeout: 30 * time.Second}
	validator := NewIntuneClient(client)
	h := Handler{db: db, repo: repo, service: NewService(repo, db, keys, publicURL, validator, intuneApp),
		limiter: middleware.NewRateLimiter(60), publicURL: strings.TrimRight(publicURL, "/"),
		intuneApp: intuneApp, authSecret: authSecret, http: client, audit: audit.NewRepository(db)}
	mux.HandleFunc("GET /scep/{endpointID}", h.public)
	mux.HandleFunc("POST /scep/{endpointID}", h.public)
	// Windows builds its request URL by appending NDES's CGI name to whatever
	// SCEP URL the profile carries, so it asks for <endpoint>/pkiclient.exe.
	// Without these the request falls through to the catch-all "GET /" and the
	// device parses an HTML page as a SCEP response, which it reports as
	// "Failed to Initialize SCEP enrollment" and 0x800700CE.
	mux.HandleFunc("GET /scep/{endpointID}/pkiclient.exe", h.public)
	mux.HandleFunc("POST /scep/{endpointID}/pkiclient.exe", h.public)
	// An organization runs several endpoints, so administration names the one it
	// acts on. The session still scopes the lookup, so an ID from another
	// customer is not found rather than served.
	mux.HandleFunc("POST /api/scep/endpoints", h.createEndpoint)
	mux.HandleFunc("POST /api/scep/endpoints/{endpointID}/delete", h.deleteEndpoint)
	mux.HandleFunc("POST /api/scep/endpoints/{endpointID}/enabled", h.setEnabled)
	mux.HandleFunc("POST /api/scep/endpoints/{endpointID}/policy", h.updatePolicy)
	mux.HandleFunc("POST /api/scep/endpoints/{endpointID}/challenges", h.createChallenge)
	mux.HandleFunc("GET /api/scep/endpoints/{endpointID}/ca", h.downloadCA)
	mux.HandleFunc("POST /api/scep/endpoints/{endpointID}/auth/{method}/enabled", h.setMethodEnabled)
	mux.HandleFunc("POST /api/scep/endpoints/{endpointID}/auth/static", h.rotateStaticSecret)
	mux.HandleFunc("POST /api/scep/endpoints/{endpointID}/auth/jamf", h.configureJamf)
	// The Entra directory binds the organization, not an endpoint, so these two
	// carry no endpoint identifier and say so in their paths.
	mux.HandleFunc("POST /api/scep/intune/connect", h.connectIntune)
	mux.HandleFunc("POST /api/scep/intune/disconnect", h.disconnectIntune)
	mux.HandleFunc("POST /integrations/jamf/scep-challenge/{endpointID}", h.jamfChallenge)
	// The Entra consent callbacks are administrator navigations, not device
	// traffic, so they stay behind the session middleware rather than joining
	// the public allowlist alongside /integrations/jamf/.
	mux.HandleFunc("GET "+signInPath, h.intuneSignInCallback)
	mux.HandleFunc("GET "+consentPath, h.intuneConsentCallback)
}

func (h Handler) public(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	id := r.PathValue("endpointID")
	if _, err := uuid.Parse(id); err != nil {
		http.NotFound(w, r)
		return
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx := database.WithTx(r.Context(), tx)
	defer tx.Rollback()
	if err := database.SetLocal(ctx, "app.scep_endpoint_id", id); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	e, err := h.repo.Endpoint(ctx, id)
	if err != nil || !e.Enabled {
		http.NotFound(w, r)
		return
	}
	if !h.limiter.Allow(id + "|" + clientip.ClientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if err := database.SetLocal(ctx, "app.organization_id", e.OrganizationID); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	op := r.URL.Query().Get("operation")
	w.Header().Set("Cache-Control", "no-store")
	var body []byte
	var failure *Failure
	switch op {
	case "GetCACaps":
		caps := "AES\r\nPOSTPKIOperation\r\nRenewal\r\nSCEPStandard\r\nSHA-256"
		if e.AllowLegacyCrypto {
			caps += "\r\nDES3\r\nSHA-1"
		}
		w.Header().Set("Content-Type", "text/plain")
		body = []byte(caps)
	case "GetCACert":
		body, err = h.service.CACertificates(ctx, e)
		w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
	case "PKIOperation":
		var raw []byte
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxMessageSize)
			raw, err = io.ReadAll(r.Body)
		} else {
			if len(r.URL.Query().Get("message")) > maxMessageSize*2 {
				http.Error(w, "SCEP request failed", http.StatusRequestEntityTooLarge)
				return
			}
			raw, err = decodeMessage(r.URL.Query().Get("message"))
		}
		if err == nil {
			body, failure, err = h.service.PKIOperation(ctx, e, raw)
		}
		w.Header().Set("Content-Type", "application/x-pki-message")
	default:
		http.Error(w, "unsupported operation", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("scep endpoint=%s operation=%s legacy=%t duration_ms=%d result=failure error=%v", id, op, e.AllowLegacyCrypto, time.Since(started).Milliseconds(), err)
		// The request transaction is discarded, so the rejection is recorded on
		// its own transaction to keep the enrollment log useful for diagnosis.
		_ = tx.Rollback()
		if failure != nil {
			h.service.RecordFailure(r.Context(), h.db, e, failure.TransactionID, failure.MessageType, failure.Reason)
		}
		if len(body) == 0 {
			http.Error(w, "SCEP request failed", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	log.Printf("scep endpoint=%s operation=%s legacy=%t duration_ms=%d result=success", id, op, e.AllowLegacyCrypto, time.Since(started).Milliseconds())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func decodeMessage(raw string) ([]byte, error) {
	raw = strings.ReplaceAll(raw, " ", "+")
	if b, e := base64.StdEncoding.DecodeString(raw); e == nil {
		return b, nil
	}
	if b, e := base64.RawURLEncoding.DecodeString(raw); e == nil {
		return b, nil
	}
	return nil, errors.New("invalid SCEP message encoding")
}

// endpointPath is where an endpoint is administered. It deliberately sits under
// /protocols rather than /scep, which the middleware treats as unconditionally
// public for the device paths.
func endpointPath(id string) string { return "/protocols/scep/" + id }

// endpointFromPath resolves the endpoint named in the URL, scoped to the
// session's organization so an ID belonging to another customer is simply not
// found. The UUID guard matters: without it a malformed path value reaches
// Postgres as a 22P02 and surfaces as a 500 rather than as a refusal.
func (h Handler) endpointFromPath(w http.ResponseWriter, r *http.Request, s auth.Session) (Endpoint, bool) {
	id := r.PathValue("endpointID")
	if _, err := uuid.Parse(id); err != nil {
		enroll.FormError(w, r, errors.New("unknown SCEP endpoint"))
		return Endpoint{}, false
	}
	e, err := h.repo.EndpointByID(r.Context(), s.OrgID, id)
	if errors.Is(err, sql.ErrNoRows) {
		enroll.FormError(w, r, errors.New("unknown SCEP endpoint"))
		return e, false
	}
	if err != nil {
		http.Error(w, "SCEP lookup failed", http.StatusInternalServerError)
		return e, false
	}
	return e, true
}

func (h Handler) createEndpoint(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, err := h.service.CreateEndpoint(r.Context(), CreateEndpointRequest{OrgID: s.OrgID, UserID: s.UserID,
		CAID: r.FormValue("ca_id"), Name: r.FormValue("name")})
	if err != nil {
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionEndpointCreated, e.Name, "")
	web.Done(w, r, endpointPath(e.ID), "SCEP endpoint “"+e.Name+"” created")
}

func (h Handler) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	if !enroll.ConfirmsEndpointName(r.FormValue("confirm_name"), e.Name) {
		enroll.FormError(w, r, errors.New("type the endpoint's name exactly to confirm deletion"))
		return
	}
	if err := h.service.DeleteEndpoint(r.Context(), s.OrgID, e.ID); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionEndpointDeleted, e.Name, "")
	web.Done(w, r, "/protocols", "SCEP endpoint “"+e.Name+"” deleted")
}

func (h Handler) setEnabled(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	enabled := r.FormValue("enabled") == "true" || r.FormValue("enabled") == "on"
	if enabled {
		methods, err := h.service.AuthMethods(r.Context(), e)
		if err != nil {
			http.Error(w, "update failed", http.StatusInternalServerError)
			return
		}
		if !slices.ContainsFunc(methods, func(m AuthMethod) bool { return m.Enabled }) {
			enroll.FormError(w, r, errors.New("turn on at least one enrollment authentication method first"))
			return
		}
	}
	if err := h.repo.SetEnabled(r.Context(), s.OrgID, e.ID, enabled); err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	if enabled {
		h.record(r, s, audit.ActionEndpointEnabled, e.Name, "")
		web.Done(w, r, endpointPath(e.ID), "SCEP endpoint “"+e.Name+"” is now enrolling devices")
		return
	}
	h.record(r, s, audit.ActionEndpointPaused, e.Name, "")
	web.Done(w, r, endpointPath(e.ID), "SCEP endpoint “"+e.Name+"” paused. Devices can no longer enroll.")
}

func (h Handler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	days, err := strconv.Atoi(r.FormValue("validity_days"))
	if err != nil || days < 1 || days > 3650 {
		enroll.FormError(w, r, errors.New("validity must be between 1 and 3650 days"))
		return
	}
	renewal, err := strconv.Atoi(r.FormValue("renewal_window_days"))
	if err != nil || renewal < 1 || renewal > 365 {
		enroll.FormError(w, r, errors.New("renewal window must be between 1 and 365 days"))
		return
	}
	if renewal >= days {
		enroll.FormError(w, r, errors.New("the renewal window must be shorter than the certificate validity"))
		return
	}
	for _, pattern := range []string{r.FormValue("subject_pattern"), r.FormValue("san_pattern")} {
		if pattern != "" {
			if _, err := regexp.Compile(pattern); err != nil {
				enroll.FormError(w, r, errors.New("invalid policy expression: "+err.Error()))
				return
			}
		}
	}
	name, err := validEndpointName(r.FormValue("name"))
	if err != nil {
		enroll.FormError(w, r, err)
		return
	}
	ekus := r.Form["allowed_eku"]
	if err := h.service.ValidateAllowedEKUs(r.Context(), e, ekus); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	// A name collision is the administrator's to see; anything else here is a
	// storage failure and stays opaque.
	err = h.repo.UpdatePolicy(r.Context(), s.OrgID, e.ID, PolicyUpdate{Name: name, ValidityDays: days,
		RenewalWindowDays: renewal, SubjectPattern: r.FormValue("subject_pattern"),
		SANPattern: r.FormValue("san_pattern"), AllowedEKUs: strings.Join(ekus, ","),
		AllowLegacyCrypto: r.FormValue("allow_legacy_crypto") != ""})
	if err != nil && strings.Contains(err.Error(), "already exists") {
		enroll.FormError(w, r, err)
		return
	}
	if err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	h.record(r, s, audit.ActionEndpointPolicy, name,
		fmt.Sprintf("%d day validity · %d day renewal window", days, renewal))
	web.Done(w, r, endpointPath(e.ID), "Enrollment policy saved")
}

func (h Handler) setMethodEnabled(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	enabled := r.FormValue("enabled") == "true" || r.FormValue("enabled") == "on"
	method := r.PathValue("method")
	if err := h.service.SetMethodEnabled(r.Context(), e, method, enabled); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionSCEPAuthMethodChanged, e.Name, method+" "+enabledWord(enabled))
	web.Done(w, r, endpointPath(e.ID), authMethodMessage(method, enabled))
}

type challengeRequest struct {
	ExpectedSubject string   `json:"expectedSubject"`
	ExpectedSANs    string   `json:"expectedSANs"`
	ExpectedEKUs    []string `json:"expectedEKUs"`
	ExternalID      string   `json:"externalId"`
	TTLSeconds      int      `json:"ttlSeconds"`
}

// challengeInput accepts both the admin form post and a JSON body, so the same
// route serves the dialog and future automation.
func challengeInput(w http.ResponseWriter, r *http.Request) (challengeRequest, error) {
	var req challengeRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil && err != io.EOF {
			return req, errors.New("invalid JSON body")
		}
		return req, nil
	}
	minutes, _ := strconv.Atoi(r.FormValue("ttl_minutes"))
	return challengeRequest{ExpectedSubject: strings.TrimSpace(r.FormValue("expected_subject")),
		ExpectedSANs: strings.TrimSpace(r.FormValue("expected_sans")), ExpectedEKUs: r.Form["expected_eku"],
		TTLSeconds: minutes * 60}, nil
}

func (h Handler) createChallenge(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	req, err := challengeInput(w, r)
	if err != nil {
		enroll.FormError(w, r, err)
		return
	}
	// Checked here as well as in the service so a rejected pin reports which
	// usage was refused, while the call below keeps failing opaquely rather
	// than surfacing storage errors to the browser.
	if _, err := narrowEKUs(e.AllowedEKUs, req.ExpectedEKUs); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	secret, err := h.service.CreateChallenge(r.Context(), e, ChallengeSpec{ExpectedSubject: req.ExpectedSubject,
		ExpectedSANs: req.ExpectedSANs, ExpectedEKUs: req.ExpectedEKUs, ExternalID: req.ExternalID, TTL: ttl})
	if err != nil {
		enroll.FormError(w, r, errors.New("could not create a challenge"))
		return
	}
	// Recorded before either response shape is written, because both of them
	// return. The pinned subject is the detail worth keeping: it is what the
	// challenge authorises, and the only part of the request a reader can check
	// the resulting certificate against.
	h.record(r, s, audit.ActionSCEPChallengeIssued, e.Name, challengeDetail(req, ttl))
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("HX-Request") != "true" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"challenge": secret, "expiresIn": ttlLabel(ttl)})
		return
	}
	_ = homeview.ProtocolSecret("challenge-dialog", "One-time challenge password",
		"Paste this into the device's SCEP profile. It works once, expires in "+ttlLabel(ttl)+
			", and cannot be shown again.", secret, "", endpointPath(e.ID)).Render(r.Context(), w)
}

func ttlLabel(ttl time.Duration) string {
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 15 * time.Minute
	}
	return ttl.String()
}

func (h Handler) rotateStaticSecret(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	secret, err := h.service.RotateStaticSecret(r.Context(), e)
	if err != nil {
		enroll.FormError(w, r, errors.New("could not rotate the shared secret"))
		return
	}
	// Rotation invalidates the secret every already-enrolled device holds, so
	// this row is the answer to "why did enrollments start failing".
	h.record(r, s, audit.ActionSCEPSecretRotated, e.Name, "previous shared secret invalidated")
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("HX-Request") != "true" {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, secret)
		return
	}
	_ = homeview.ProtocolSecret("static-dialog", "Shared secret",
		"Every device enrolling with this method uses this password. It replaces any previous secret and cannot be shown again.",
		secret, "", endpointPath(e.ID)).Render(r.Context(), w)
}

// downloadCA serves the endpoint's CA trust material. With no "format" query
// parameter it is the SCEP protocol bundle: a PKCS#7 blob carrying the RA
// certificate alongside the CA chain, the shape MDM auto-configuration
// expects. A "format" of pem, crt, or cer instead serves the plain CA
// certificate for someone installing it by hand — see CACertificatePEM.
func (h Handler) downloadCA(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	if r.URL.Query().Get("format") != "" {
		certPEM, chainPEM, err := h.service.CACertificatePEM(r.Context(), e)
		if err != nil {
			http.Error(w, "CA download failed", http.StatusInternalServerError)
			return
		}
		if err := pki.WriteCertificateDownload(w, r, e.Name+"-ca", certPEM, chainPEM); err != nil {
			http.Error(w, "That certificate format is not supported.", http.StatusBadRequest)
			return
		}
		return
	}
	der, err := h.service.CACertificates(r.Context(), e)
	if err != nil {
		http.Error(w, "CA download failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="simplescep-scep-ca.p7b"`)
	_, _ = w.Write(der)
}

func (h Handler) configureJamf(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password, err := h.service.ConfigureJamf(r.Context(), e, username)
	if err != nil {
		enroll.FormError(w, r, errors.New("could not save the Jamf Pro connection"))
		return
	}
	h.record(r, s, audit.ActionSCEPJamfConfigured, e.Name, "webhook user "+username)
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("HX-Request") != "true" {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, password)
		return
	}
	_ = homeview.ProtocolSecret("jamf-dialog", "Jamf Pro webhook password",
		"Create a webhook in Jamf Pro for the SCEPChallenge event pointing at the URL below, using Basic authentication with this password. It cannot be shown again.",
		password, h.publicURL+"/integrations/jamf/scep-challenge/"+e.ID, endpointPath(e.ID)).Render(r.Context(), w)
}

func (h Handler) jamfChallenge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("endpointID")
	if _, err := uuid.Parse(id); err != nil {
		http.NotFound(w, r)
		return
	}
	// Verifying the Basic password costs one argon2id at 64 MiB, and this route
	// is public. Both budgets are spent before the transaction opens and before
	// any hashing, so an unauthenticated caller cannot turn the endpoint into a
	// memory-exhaustion oracle against the whole process.
	//
	// The key is the endpoint, not the client address: ClientIP still comes from
	// headers nothing has verified, so an address-keyed budget here would be
	// spoofable per request. A Jamf server asks for one challenge per device
	// enrollment, so 60/min per endpoint is generous. The "jamf" prefixes keep
	// these buckets clear of the device keys, which are id + "|" + ip.
	if !h.limiter.Allow("jamf") || !h.limiter.Allow("jamf|"+id) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx := database.WithTx(r.Context(), tx)
	defer tx.Rollback()
	if err := database.SetLocal(ctx, "app.scep_endpoint_id", id); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	e, err := h.repo.Endpoint(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := database.SetLocal(ctx, "app.organization_id", e.OrganizationID); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	user, hash, active, err := h.service.JamfCredentials(ctx, e)
	givenUser, givenPassword, ok := r.BasicAuth()
	// The username compare is constant-time, but it deliberately still
	// short-circuits: letting a wrong username reach verifySecret would spend an
	// argon2id on every guess. The rate limit above is what bounds that cost;
	// this ordering just avoids paying it needlessly.
	sameUser := subtle.ConstantTimeCompare([]byte(givenUser), []byte(user)) == 1
	if err != nil || !active || !ok || !sameUser || !enroll.VerifySecret(hash, givenPassword) {
		w.Header().Set("WWW-Authenticate", `Basic realm="SimpleSCEP"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var payload struct {
		Webhook struct {
			ID    json.RawMessage `json:"id"`
			Event string          `json:"webhookEvent"`
		} `json:"webhook"`
		Event json.RawMessage `json:"event"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&payload); err != nil || payload.Webhook.Event != "SCEPChallenge" {
		http.Error(w, "invalid webhook", 400)
		return
	}
	externalID := strings.Trim(string(payload.Webhook.ID), `"`)
	// Jamf asks for a challenge before it knows what the device will request,
	// so this one pins nothing beyond the endpoint's own policy.
	secret, err := h.service.CreateChallenge(ctx, e, ChallengeSpec{ExternalID: externalID, TTL: 15 * time.Minute})
	if err != nil {
		http.Error(w, "challenge failed", 500)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "challenge failed", 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, secret)
}

// authMethodMessage names what just changed. "Saved" would be true and useless:
// which of the four authentication methods was switched, and in which
// direction, is the whole of what the administrator needs confirmed.
// enabledWord names the direction of a method change for the audit detail,
// where "challenge enabled" reads better than a bare boolean.
func enabledWord(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

// challengeDetail summarises what a one-time challenge was pinned to. An
// unpinned challenge says so rather than rendering an empty detail, since the
// difference between "any subject" and "not recorded" matters to a reader.
func challengeDetail(req challengeRequest, ttl time.Duration) string {
	subject := strings.TrimSpace(req.ExpectedSubject)
	if subject == "" {
		subject = "any subject"
	}
	return subject + " · expires in " + ttlLabel(ttl)
}

func authMethodMessage(method string, enabled bool) string {
	name := map[string]string{
		"challenge": "One-time challenge passwords",
		"static":    "The shared secret",
		"jamf":      "Jamf challenge validation",
		"intune":    "Microsoft Intune validation",
	}[method]
	if name == "" {
		name = "That authentication method"
	}
	if enabled {
		return name + " is now accepted for enrollment"
	}
	return name + " is no longer accepted for enrollment"
}
