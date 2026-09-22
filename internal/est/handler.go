package est

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
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

type Handler struct {
	db        *sql.DB
	repo      Repository
	service   Service
	limiter   *middleware.RateLimiter
	publicURL string
	audit     audit.Repository
}

// secureChannel reports whether the request reached us over a confidential
// channel. RFC 7030 §3.2.3 permits HTTP Basic only over server-authenticated
// TLS, and the password is the one thing in this protocol worth stealing.
//
// The decision lives in internal/clientip alongside ClientIP because both answer
// the same question — how much of this request's provenance can be believed —
// from the same configured set of trusted proxies.
func secureChannel(r *http.Request) bool {
	return clientip.SecureChannel(r)
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

func RegisterRoutes(mux *http.ServeMux, db *sql.DB, keys pki.KeyProvider, publicURL string) {
	repo := NewRepository(db)
	pkiRepo := pki.NewRepository(db)
	service := NewService(repo, pki.NewServiceWithURL(pkiRepo, keys, publicURL), pkiRepo, publicURL)
	h := Handler{db: db, repo: repo, service: service, limiter: middleware.NewRateLimiter(60),
		publicURL: strings.TrimRight(publicURL, "/"), audit: audit.NewRepository(db)}

	// The client-facing protocol. RFC 7030 §3.2.2 puts these under /.well-known
	// with a free-form label naming which CA to enroll against; the label here is
	// the endpoint ID. Everything below the prefix is unauthenticated as far as
	// the session middleware is concerned and reaches the database through
	// app.est_endpoint_id, so middleware.public must list it or every enrollment
	// is answered with a redirect to the login page.
	mux.HandleFunc("GET /.well-known/est/{endpointID}/cacerts", h.public)
	mux.HandleFunc("GET /.well-known/est/{endpointID}/csrattrs", h.public)
	mux.HandleFunc("POST /.well-known/est/{endpointID}/simpleenroll", h.public)
	mux.HandleFunc("POST /.well-known/est/{endpointID}/simplereenroll", h.public)

	// Administration. These carry a session and never speak EST.
	mux.HandleFunc("POST /api/est/endpoints", h.createEndpoint)
	mux.HandleFunc("POST /api/est/endpoints/{endpointID}/delete", h.deleteEndpoint)
	mux.HandleFunc("POST /api/est/endpoints/{endpointID}/enabled", h.setEnabled)
	mux.HandleFunc("POST /api/est/endpoints/{endpointID}/policy", h.updatePolicy)
	mux.HandleFunc("POST /api/est/endpoints/{endpointID}/credentials", h.createCredential)
	mux.HandleFunc("POST /api/est/endpoints/{endpointID}/credentials/{credentialID}/revoke", h.revokeCredential)
}

// ---------------------------------------------------------------------------
// The client path
// ---------------------------------------------------------------------------

// public is the single entry point for every EST operation. The lifecycle
// mirrors acme.Handler.public step for step, because the constraints are the
// same: no session, no transaction from the middleware, and a caller who must
// learn nothing about endpoints that are not theirs.
func (h Handler) public(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	id := r.PathValue("endpointID")
	// Guarded before the database: without this a malformed path value reaches
	// Postgres as a 22P02 and surfaces as a 500 rather than as a refusal.
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

	if err := database.SetLocal(ctx, "app.est_endpoint_id", id); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	e, err := h.repo.Endpoint(ctx, id)
	// A disabled endpoint and another customer's endpoint are both simply not
	// found. An unauthenticated caller learns nothing either way.
	if err != nil || !e.Enabled {
		http.NotFound(w, r)
		return
	}
	// Checked before any credential is verified: argon2id is deliberately
	// expensive, so an unauthenticated caller must not be able to spend it
	// repeatedly.
	if !h.limiter.Allow(id + "|" + clientip.ClientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if err := database.SetLocal(ctx, "app.organization_id", e.OrganizationID); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	operation, failure, err := h.dispatch(ctx, w, r, e)
	if err != nil {
		log.Printf("est endpoint=%s operation=%s duration_ms=%d result=failure error=%v",
			id, operation, time.Since(started).Milliseconds(), err)
		// The request transaction is discarded before the reply, so a rejection
		// leaves nothing behind — no certificate, and no enrollment row. The
		// refusal is then recorded on its own transaction, because a device that
		// is being turned away is exactly what the endpoint's log is for.
		_ = tx.Rollback()
		if failure != nil {
			h.service.RecordFailure(r.Context(), h.db, e, *failure)
		}
		h.fail(w, e, err)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	log.Printf("est endpoint=%s operation=%s duration_ms=%d result=success",
		id, operation, time.Since(started).Milliseconds())
}

// dispatch routes one request and writes its response. It returns the operation
// name for the log, the refusal to record if there is one, and any error for the
// failure reply.
//
// Nothing here writes a status before it is certain of one: every branch below
// either fails and returns, or succeeds and writes exactly once.
func (h Handler) dispatch(ctx context.Context, w http.ResponseWriter, r *http.Request, e Endpoint) (string, *Failure, error) {
	operation := strings.TrimPrefix(r.URL.Path, "/.well-known/est/"+e.ID+"/")
	switch operation {
	case OpCACerts:
		// §4.1.1: the server MUST NOT require client authentication here. A
		// client that does not yet hold the CA cannot verify the TLS connection
		// it would have to authenticate over.
		body, err := h.service.CACerts(ctx, e)
		if err != nil {
			return operation, nil, err
		}
		writeCerts(w, body)
		return operation, nil, nil

	case OpCSRAttrs:
		if _, err := h.authenticate(ctx, w, r, e); err != nil {
			return operation, nil, err
		}
		body, ok, err := h.service.CSRAttrs(ctx, e)
		if err != nil {
			return operation, nil, err
		}
		if !ok {
			// §4.5.2: a CA with nothing to add answers 204, and a client reads
			// that as "generate whatever you were going to generate".
			w.WriteHeader(http.StatusNoContent)
			return operation, nil, nil
		}
		w.Header().Set("Content-Type", ContentTypeCSRAttrs)
		w.Header().Set("Content-Transfer-Encoding", "base64")
		_, _ = w.Write(body)
		return operation, nil, nil

	case OpSimpleEnroll, OpSimpleReenrol:
		cred, err := h.authenticate(ctx, w, r, e)
		if err != nil {
			return operation, nil, err
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMessageSize))
		if err != nil {
			return operation, nil, errorf(http.StatusRequestEntityTooLarge, "the request body is too large")
		}
		csr, err := parseCSR(body)
		if err != nil {
			return operation, nil, err
		}
		var cert pki.Certificate
		var failure *Failure
		if operation == OpSimpleEnroll {
			cert, failure, err = h.service.Enroll(ctx, e, cred, csr)
		} else {
			cert, failure, err = h.service.Reenroll(ctx, e, cred, csr)
		}
		if err != nil {
			return operation, failure, err
		}
		response, err := CertificateResponse(cert)
		if err != nil {
			return operation, nil, err
		}
		writeCerts(w, response)
		return operation, nil, nil
	}
	return operation, nil, errorf(http.StatusNotFound, "unknown operation")
}

// authenticate resolves the Basic credential a request carries, challenging when
// it carries none. The challenge is sent for a missing credential and for a
// wrong one alike, so a caller cannot tell the two apart.
//
// The channel is checked first, before anything is challenged: a 401 over a
// plaintext connection would invite the client to send its password over that
// same connection.
func (h Handler) authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, e Endpoint) (Credential, error) {
	username, password, ok := basicAuth(r)
	if !secureChannel(r) {
		// By the time this runs the password, if one was sent, has already
		// crossed the wire in the clear. Refusing it contains the damage rather
		// than preventing it, which is why the log says to revoke rather than
		// merely noting the refusal.
		if ok {
			log.Printf("est endpoint=%s username=%s: credential presented over a plaintext channel from %s; treat it as compromised and re-mint it",
				e.ID, username, clientip.ClientIP(r))
		} else {
			log.Printf("est endpoint=%s: credentials refused over a plaintext channel from %s",
				e.ID, clientip.ClientIP(r))
		}
		// Always refused. This was once downgradeable to a warning so a
		// deployment could confirm what its proxies send before a header nobody
		// had verified began turning enrollments away — but the escape hatch and
		// the hazard are the same switch, and left on it accepts enrollment
		// credentials over plaintext indefinitely.
		return Credential{}, errorf(http.StatusForbidden,
			"this endpoint accepts credentials only over HTTPS")
	}
	if !ok {
		challengeBasic(w, e.Name)
		return Credential{}, unauthorized()
	}
	cred, err := h.service.Authenticate(ctx, e, username, password)
	if err != nil {
		challengeBasic(w, e.Name)
		return Credential{}, err
	}
	return cred, nil
}

func writeCerts(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", ContentTypePKCS7)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	_, _ = w.Write(body)
}

// fail answers a rejected request. EST has no problem-document format, so this
// is a status and a sentence — but only for an *Error. Anything else is a fault
// on this side, and an unauthenticated caller is told nothing about it beyond
// that it happened.
func (h Handler) fail(w http.ResponseWriter, e Endpoint, err error) {
	var estErr *Error
	if !errors.As(err, &estErr) {
		http.Error(w, "enrollment failed", http.StatusInternalServerError)
		return
	}
	if estErr.Status == http.StatusUnauthorized {
		// Re-set on the way out: the header was written onto a response that a
		// rolled-back transaction may have discarded.
		challengeBasic(w, e.Name)
	}
	http.Error(w, estErr.Message, estErr.Status)
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

// endpointPath is where an endpoint is administered. Like SCEP's and ACME's it
// sits under /protocols rather than under the protocol's own prefix, which the
// middleware treats as unconditionally public for the client paths.
func endpointPath(id string) string { return "/protocols/est/" + id }

// endpointFromPath resolves the endpoint named in the URL, scoped to the
// session's organization so an ID belonging to another customer is simply not
// found.
func (h Handler) endpointFromPath(w http.ResponseWriter, r *http.Request, s auth.Session) (Endpoint, bool) {
	id := r.PathValue("endpointID")
	if _, err := uuid.Parse(id); err != nil {
		enroll.FormError(w, r, errors.New("unknown EST endpoint"))
		return Endpoint{}, false
	}
	e, err := h.repo.EndpointByID(r.Context(), s.OrgID, id)
	if errors.Is(err, sql.ErrNoRows) {
		enroll.FormError(w, r, errors.New("unknown EST endpoint"))
		return e, false
	}
	if err != nil {
		http.Error(w, "EST lookup failed", http.StatusInternalServerError)
		return e, false
	}
	return e, true
}

func (h Handler) createEndpoint(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, err := h.service.CreateEndpoint(r.Context(), s.OrgID, r.FormValue("name"), r.FormValue("ca_id"))
	if err != nil {
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionESTEndpointCreated, e.Name, "")
	web.Done(w, r, endpointPath(e.ID), "EST endpoint “"+e.Name+"” created")
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
	enabled := r.FormValue("enabled") == "true"
	if err := h.service.SetEnabled(r.Context(), s.OrgID, e.ID, enabled); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	action := audit.ActionESTEndpointPaused
	message := "EST endpoint “" + e.Name + "” paused. Clients can no longer enroll."
	if enabled {
		action = audit.ActionESTEndpointEnabled
		message = "EST endpoint “" + e.Name + "” is now enrolling clients"
	}
	h.record(r, s, action, e.Name, "")
	web.Done(w, r, endpointPath(e.ID), message)
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
	if err := r.ParseForm(); err != nil {
		enroll.FormError(w, r, errors.New("the form could not be read"))
		return
	}
	days, err := web.PositiveInt(r.FormValue("validity_days"), DefaultValidityDays)
	if err != nil {
		enroll.FormError(w, r, err)
		return
	}
	window, err := web.PositiveInt(r.FormValue("renewal_window_days"), DefaultRenewalWindowDays)
	if err != nil {
		enroll.FormError(w, r, err)
		return
	}
	// The EKU checkboxes name the usages to allow. They are a ceiling: a CSR
	// that asks for a subset is issued that subset, and one that asks for
	// something outside it is refused rather than silently narrowed.
	update := PolicyUpdate{
		Name:              r.FormValue("name"),
		ValidityDays:      days,
		RenewalWindowDays: window,
		SubjectPattern:    strings.TrimSpace(r.FormValue("subject_pattern")),
		SANPattern:        strings.TrimSpace(r.FormValue("san_pattern")),
		AllowedEKUs:       strings.Join(r.Form["allowed_eku"], ","),
		// An unchecked checkbox sends nothing, so absence is off.
		ReenrollRequiresSameKey: r.FormValue("reenroll_requires_same_key") == "on",
	}
	if err := h.service.UpdatePolicy(r.Context(), s.OrgID, e.ID, update); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionESTEndpointPolicy, update.Name, "")
	web.Done(w, r, endpointPath(e.ID), "Enrollment policy saved")
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
		enroll.FormError(w, r, errors.New("type the endpoint's name to confirm"))
		return
	}
	if err := h.service.DeleteEndpoint(r.Context(), s.OrgID, e.ID); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionESTEndpointDeleted, e.Name, "")
	web.Done(w, r, "/protocols", "EST endpoint “"+e.Name+"” deleted")
}

// createCredential mints a Basic credential and shows its password once. Like
// acme.Handler.createCredential it serves both the htmx dialog and JSON
// automation from one route, because an organization that provisions devices
// from a script needs the same operation an administrator gets a form for.
func (h Handler) createCredential(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}

	var spec CredentialSpec
	wantsJSON := r.Header.Get("Content-Type") == "application/json"
	if wantsJSON {
		var body struct {
			Label       string `json:"label"`
			Username    string `json:"username"`
			Identifiers string `json:"identifiers"`
			TTLHours    int    `json:"ttl_hours"`
		}
		if err := web.DecodeJSON(r, &body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		spec = CredentialSpec{Label: body.Label, Username: body.Username,
			Identifiers: body.Identifiers, TTLHours: body.TTLHours}
	} else {
		if err := r.ParseForm(); err != nil {
			enroll.FormError(w, r, errors.New("the form could not be read"))
			return
		}
		hours, err := web.PositiveInt(r.FormValue("ttl_hours"), 0)
		if err != nil {
			enroll.FormError(w, r, err)
			return
		}
		spec = CredentialSpec{Label: r.FormValue("label"), Username: r.FormValue("username"),
			Identifiers: r.FormValue("identifiers"), TTLHours: hours}
	}

	credential, password, err := h.service.CreateCredential(r.Context(), e, spec)
	if err != nil {
		if wantsJSON {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionESTCredentialIssued, e.Name, credential.Username)

	if wantsJSON {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"url":      h.service.EndpointURL(e.ID),
			"username": credential.Username,
			"password": password,
		})
		return
	}
	// The password is swapped into the dialog rather than redirected to, because
	// this is the only moment it exists in a readable form.
	w.Header().Set("Cache-Control", "no-store")
	_ = homeview.ESTCredentialSecret(h.service.EndpointURL(e.ID), credential.Username, password,
		endpointPath(e.ID)).Render(r.Context(), w)
}

func (h Handler) revokeCredential(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	e, ok := h.endpointFromPath(w, r, s)
	if !ok {
		return
	}
	id := r.PathValue("credentialID")
	if _, err := uuid.Parse(id); err != nil {
		enroll.FormError(w, r, errors.New("unknown credential"))
		return
	}
	if err := h.service.RevokeCredential(r.Context(), s.OrgID, e.ID, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			enroll.FormError(w, r, errors.New("unknown credential"))
			return
		}
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionESTCredentialRevoked, e.Name, id)
	web.Done(w, r, endpointPath(e.ID), "Credential revoked. Clients using it can no longer enroll.")
}
