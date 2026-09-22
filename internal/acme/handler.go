package acme

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

// maxMessageSize bounds a JOSE request body. ACME carries JSON and a DER CSR,
// not SCEP's PKCS#7 envelope, so it needs far less headroom.
const maxMessageSize = 256 << 10

type Handler struct {
	db        *sql.DB
	repo      Repository
	service   Service
	limiter   *middleware.RateLimiter
	publicURL string
	audit     audit.Repository
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
	service := NewService(repo, pki.NewServiceWithURL(pkiRepo, keys, publicURL), pkiRepo, keys, publicURL)
	h := Handler{db: db, repo: repo, service: service, limiter: middleware.NewRateLimiter(120),
		publicURL: strings.TrimRight(publicURL, "/"), audit: audit.NewRepository(db)}

	// The client-facing protocol. Everything below /acme/ is unauthenticated and
	// reaches the database through app.acme_endpoint_id, so middleware.public
	// must list this prefix or every client is redirected to the login page.
	mux.HandleFunc("GET /acme/{endpointID}/directory", h.public)
	// §7.2 specifies HEAD for a nonce and requires GET to work as well, for
	// clients and proxies that cannot issue a HEAD.
	mux.HandleFunc("HEAD /acme/{endpointID}/new-nonce", h.public)
	mux.HandleFunc("GET /acme/{endpointID}/new-nonce", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/new-account", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/accounts/{accountID}", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/key-change", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/new-order", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/orders/{orderID}", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/orders/{orderID}/finalize", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/authorizations/{authzID}", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/challenges/{challengeID}", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/certificates/{orderID}", h.public)
	mux.HandleFunc("POST /acme/{endpointID}/revoke-cert", h.public)

	// Administration. These carry a session and never speak ACME.
	mux.HandleFunc("POST /api/acme/endpoints", h.createEndpoint)
	mux.HandleFunc("POST /api/acme/endpoints/{endpointID}/delete", h.deleteEndpoint)
	mux.HandleFunc("POST /api/acme/endpoints/{endpointID}/enabled", h.setEnabled)
	mux.HandleFunc("POST /api/acme/endpoints/{endpointID}/policy", h.updatePolicy)
	mux.HandleFunc("POST /api/acme/endpoints/{endpointID}/credentials", h.createCredential)
	mux.HandleFunc("POST /api/acme/endpoints/{endpointID}/credentials/{credentialID}/revoke", h.revokeCredential)
}

// ---------------------------------------------------------------------------
// The client path
// ---------------------------------------------------------------------------

// public is the single entry point for every ACME resource. The lifecycle
// mirrors scep.Handler.public step for step, because the constraints are the
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

	if err := database.SetLocal(ctx, "app.acme_endpoint_id", id); err != nil {
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
	if !h.limiter.Allow(id + "|" + clientip.ClientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if err := database.SetLocal(ctx, "app.organization_id", e.OrganizationID); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	operation, err := h.dispatch(ctx, w, r, e)
	if err != nil {
		log.Printf("acme endpoint=%s operation=%s duration_ms=%d result=failure error=%v",
			id, operation, time.Since(started).Milliseconds(), err)
		// The request transaction is discarded before the reply, so a rejection
		// leaves nothing behind — including any nonce it happened to spend, which
		// is why a client that retries after an error gets badNonce and fetches a
		// fresh one.
		_ = tx.Rollback()
		h.problem(w, r, e, err)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	log.Printf("acme endpoint=%s operation=%s duration_ms=%d result=success",
		id, operation, time.Since(started).Milliseconds())
}

// dispatch routes one request and writes its response. It returns the operation
// name for the log, and any error for the problem document.
//
// Nothing here writes a status before it is certain of one: every handler below
// either fails and returns, or succeeds and writes exactly once, so an error
// never arrives at a response that has already begun.
func (h Handler) dispatch(ctx context.Context, w http.ResponseWriter, r *http.Request, e Endpoint) (string, error) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/directory"):
		return "directory", h.writeJSON(ctx, w, e, http.StatusOK, h.service.Directory(e))

	case strings.HasSuffix(r.URL.Path, "/new-nonce"):
		// §7.2: 200 for GET, 204 for HEAD, and a nonce on both.
		if err := h.setNonce(ctx, w, e); err != nil {
			return "new-nonce", err
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return "new-nonce", nil
		}
		w.WriteHeader(http.StatusOK)
		return "new-nonce", nil
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessageSize))
	if err != nil {
		return "post", problemf(http.StatusRequestEntityTooLarge, ProblemMalformed, "the request body is too large")
	}
	url := h.absoluteURL(r)

	switch {
	case strings.HasSuffix(r.URL.Path, "/new-account"):
		return "new-account", h.newAccount(ctx, w, r, e, body, url)
	case strings.HasSuffix(r.URL.Path, "/key-change"):
		return "key-change", h.keyChange(ctx, w, r, e, body, url)
	case strings.HasSuffix(r.URL.Path, "/new-order"):
		return "new-order", h.newOrder(ctx, w, r, e, body, url)
	case strings.HasSuffix(r.URL.Path, "/revoke-cert"):
		return "revoke-cert", h.revokeCert(ctx, w, r, e, body, url)
	case strings.HasSuffix(r.URL.Path, "/finalize"):
		return "finalize", h.finalize(ctx, w, r, e, body, url)
	case r.PathValue("accountID") != "":
		return "account", h.account(ctx, w, r, e, body, url)
	case r.PathValue("orderID") != "" && strings.Contains(r.URL.Path, "/certificates/"):
		return "certificate", h.certificate(ctx, w, r, e, body, url)
	case r.PathValue("orderID") != "":
		return "order", h.order(ctx, w, r, e, body, url)
	case r.PathValue("authzID") != "":
		return "authorization", h.authorization(ctx, w, r, e, body, url)
	case r.PathValue("challengeID") != "":
		return "challenge", h.challenge(ctx, w, r, e, body, url)
	}
	return "unknown", problemf(http.StatusNotFound, ProblemMalformed, "no such resource")
}

// absoluteURL reconstructs the address a request was sent to, which is what the
// signed url header is compared against.
//
// It is built from the configured public URL rather than from the Host header.
// Trusting the header would let a client sign for whatever host it claimed, and
// the url binding exists precisely to stop a signature being valid anywhere
// other than where it was aimed.
func (h Handler) absoluteURL(r *http.Request) string { return h.publicURL + r.URL.Path }

func (h Handler) newAccount(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, false)
	if err != nil {
		return err
	}
	if req.thumbprint == "" {
		return problemf(http.StatusBadRequest, ProblemMalformed,
			"a registration must be signed with the account key it is registering")
	}
	account, created, err := h.service.NewAccount(ctx, e, req, url)
	if err != nil {
		return err
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	w.Header().Set("Location", h.accountURL(e, account.ID))
	return h.writeJSON(ctx, w, e, status, accountJSON(account))
}

func (h Handler) account(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, true)
	if err != nil {
		return err
	}
	// An account resource is only ever its own to read or change. Comparing the
	// signer to the path is what stops one customer's client from reading, or
	// deactivating, another's account.
	if req.account.ID != r.PathValue("accountID") {
		return problemf(http.StatusForbidden, ProblemUnauthorized,
			"this request is not signed by the account it names")
	}
	if req.jws.postAsGet {
		return h.writeJSON(ctx, w, e, http.StatusOK, accountJSON(req.account))
	}
	account, err := h.service.UpdateAccount(ctx, e, req.account, req.jws.payload)
	if err != nil {
		return err
	}
	return h.writeJSON(ctx, w, e, http.StatusOK, accountJSON(account))
}

func (h Handler) keyChange(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, true)
	if err != nil {
		return err
	}
	if err := h.service.KeyChange(ctx, e, req, url); err != nil {
		return err
	}
	account, err := h.repo.Account(ctx, e.ID, req.account.ID)
	if err != nil {
		return err
	}
	w.Header().Set("Location", h.accountURL(e, account.ID))
	return h.writeJSON(ctx, w, e, http.StatusOK, accountJSON(account))
}

func (h Handler) newOrder(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, true)
	if err != nil {
		return err
	}
	order, authorizations, err := h.service.NewOrder(ctx, e, req.account, req.jws.payload)
	if err != nil {
		return err
	}
	w.Header().Set("Location", h.orderURL(e, order.ID))
	return h.writeJSON(ctx, w, e, http.StatusCreated, h.orderJSON(e, order, authorizations))
}

func (h Handler) order(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, true)
	if err != nil {
		return err
	}
	order, err := h.repo.Order(ctx, e.ID, r.PathValue("orderID"))
	if err != nil || order.AccountID != req.account.ID {
		return problemf(http.StatusNotFound, ProblemMalformed, "no such order")
	}
	authorizations, err := h.repo.Authorizations(ctx, order.ID)
	if err != nil {
		return err
	}
	return h.writeJSON(ctx, w, e, http.StatusOK, h.orderJSON(e, order, authorizations))
}

func (h Handler) finalize(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, true)
	if err != nil {
		return err
	}
	order, err := h.service.Finalize(ctx, e, req.account, r.PathValue("orderID"), req.jws.payload)
	if err != nil {
		return err
	}
	authorizations, err := h.repo.Authorizations(ctx, order.ID)
	if err != nil {
		return err
	}
	w.Header().Set("Location", h.orderURL(e, order.ID))
	return h.writeJSON(ctx, w, e, http.StatusOK, h.orderJSON(e, order, authorizations))
}

func (h Handler) certificate(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, true)
	if err != nil {
		return err
	}
	chain, err := h.service.Certificate(ctx, e, req.account, r.PathValue("orderID"))
	if err != nil {
		return err
	}
	if err := h.setNonce(ctx, w, e); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, chain)
	return nil
}

func (h Handler) authorization(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, true)
	if err != nil {
		return err
	}
	a, err := h.repo.Authorization(ctx, e.ID, r.PathValue("authzID"))
	if err != nil {
		return problemf(http.StatusNotFound, ProblemMalformed, "no such authorization")
	}
	order, err := h.repo.Order(ctx, e.ID, a.OrderID)
	if err != nil || order.AccountID != req.account.ID {
		return problemf(http.StatusNotFound, ProblemMalformed, "no such authorization")
	}
	c, err := h.repo.ChallengeFor(ctx, a.ID)
	if err != nil {
		return err
	}
	return h.writeJSON(ctx, w, e, http.StatusOK, h.authorizationJSON(e, a, c))
}

// challenge answers a client that posted to a challenge to "respond" to it.
// There is nothing to trigger — the authorization was valid the moment it was
// created — so this returns the challenge's current state, which is what a
// client polling for completion is waiting to see.
func (h Handler) challenge(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, true)
	if err != nil {
		return err
	}
	c, err := h.repo.Challenge(ctx, e.ID, r.PathValue("challengeID"))
	if err != nil {
		return problemf(http.StatusNotFound, ProblemMalformed, "no such challenge")
	}
	a, err := h.repo.Authorization(ctx, e.ID, c.AuthorizationID)
	if err != nil {
		return problemf(http.StatusNotFound, ProblemMalformed, "no such challenge")
	}
	order, err := h.repo.Order(ctx, e.ID, a.OrderID)
	if err != nil || order.AccountID != req.account.ID {
		return problemf(http.StatusNotFound, ProblemMalformed, "no such challenge")
	}
	// §7.5.1 requires a link back to the authorization on a challenge response.
	w.Header().Set("Link", `<`+h.authorizationURL(e, a.ID)+`>;rel="up"`)
	return h.writeJSON(ctx, w, e, http.StatusOK, h.challengeJSON(e, c))
}

// revokeCert accepts either signing form (§7.6), so it authenticates without
// requiring an account and lets the service decide which form it got.
func (h Handler) revokeCert(ctx context.Context, w http.ResponseWriter, r *http.Request,
	e Endpoint, body []byte, url string) error {
	req, err := h.service.Authenticate(ctx, e, body, url, false)
	if err != nil {
		return err
	}
	if err := h.service.Revoke(ctx, e, req); err != nil {
		return err
	}
	if err := h.setNonce(ctx, w, e); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// ---------------------------------------------------------------------------
// Response shaping
// ---------------------------------------------------------------------------

func (h Handler) accountURL(e Endpoint, id string) string {
	return h.service.endpointURL(e.ID) + "/accounts/" + id
}
func (h Handler) orderURL(e Endpoint, id string) string {
	return h.service.endpointURL(e.ID) + "/orders/" + id
}
func (h Handler) authorizationURL(e Endpoint, id string) string {
	return h.service.endpointURL(e.ID) + "/authorizations/" + id
}

func accountJSON(a Account) map[string]any {
	out := map[string]any{"status": a.Status, "orders": ""}
	if contacts := enroll.SplitCSV(a.Contact); len(contacts) > 0 {
		out["contact"] = contacts
	}
	return out
}

func (h Handler) orderJSON(e Endpoint, o Order, authorizations []Authorization) map[string]any {
	identifiers := make([]Identifier, 0, len(authorizations))
	urls := make([]string, 0, len(authorizations))
	for _, a := range authorizations {
		identifiers = append(identifiers, Identifier{Type: a.IdentifierType, Value: a.IdentifierValue})
		urls = append(urls, h.authorizationURL(e, a.ID))
	}
	out := map[string]any{
		"status":         o.Status,
		"expires":        o.ExpiresAt.UTC().Format(time.RFC3339),
		"identifiers":    identifiers,
		"authorizations": urls,
		"finalize":       h.orderURL(e, o.ID) + "/finalize",
	}
	if o.NotBefore != nil {
		out["notBefore"] = o.NotBefore.UTC().Format(time.RFC3339)
	}
	if o.NotAfter != nil {
		out["notAfter"] = o.NotAfter.UTC().Format(time.RFC3339)
	}
	if o.Status == StatusValid && o.CertificateID != "" {
		out["certificate"] = h.service.endpointURL(e.ID) + "/certificates/" + o.ID
	}
	// A failed order carries the reason it failed, which is where an unattended
	// client's operator goes looking after the fact.
	if o.ErrorType != "" {
		out["error"] = map[string]any{"type": o.ErrorType, "detail": o.ErrorDetail}
	}
	return out
}

func (h Handler) authorizationJSON(e Endpoint, a Authorization, c Challenge) map[string]any {
	return map[string]any{
		"status":     a.Status,
		"expires":    a.ExpiresAt.UTC().Format(time.RFC3339),
		"identifier": Identifier{Type: a.IdentifierType, Value: a.IdentifierValue},
		"challenges": []map[string]any{h.challengeJSON(e, c)},
	}
}

func (h Handler) challengeJSON(e Endpoint, c Challenge) map[string]any {
	out := map[string]any{
		"type":   c.Type,
		"url":    h.service.endpointURL(e.ID) + "/challenges/" + c.ID,
		"token":  c.Token,
		"status": c.Status,
	}
	if c.ValidatedAt != nil {
		out["validated"] = c.ValidatedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// setNonce puts a fresh replay nonce on a response. Every reply carries one,
// success or failure: a client that cannot get a nonce back has no way to retry,
// which would turn a transient rejection into a permanent one.
func (h Handler) setNonce(ctx context.Context, w http.ResponseWriter, e Endpoint) error {
	nonce, err := h.service.NewNonce(ctx, e)
	if err != nil {
		return err
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", `<`+h.service.endpointURL(e.ID)+`/directory>;rel="index"`)
	return nil
}

func (h Handler) writeJSON(ctx context.Context, w http.ResponseWriter, e Endpoint, status int, body any) error {
	if err := h.setNonce(ctx, w, e); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(body)
}

// problem writes an RFC 8555 §6.7 error document.
//
// Only a Problem reaches the client as itself. Anything else — a failed query, a
// KMS call that timed out — becomes an opaque 500, because the text of an
// internal failure is not something to hand an unauthenticated caller.
//
// The nonce is minted on its own transaction: the request's has been rolled
// back by the time this runs, and a nonce written into a discarded transaction
// would be one the client could never spend.
func (h Handler) problem(w http.ResponseWriter, r *http.Request, e Endpoint, err error) {
	p, ok := err.(Problem)
	if !ok {
		p = Problem{Type: ProblemServerInternal, Status: http.StatusInternalServerError,
			Detail: "the request could not be completed"}
	}
	if tx, txErr := h.db.BeginTx(r.Context(), nil); txErr == nil {
		ctx := database.WithTx(r.Context(), tx)
		if database.SetLocal(ctx, "app.organization_id", e.OrganizationID) == nil {
			if nonce, nErr := h.service.NewNonce(ctx, e); nErr == nil && tx.Commit() == nil {
				w.Header().Set("Replay-Nonce", nonce)
			} else {
				_ = tx.Rollback()
			}
		} else {
			_ = tx.Rollback()
		}
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": p.Type, "detail": p.Detail, "status": p.Status,
	})
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

// endpointPath is where an endpoint is administered. Like SCEP's it sits under
// /protocols rather than under the protocol's own prefix, which the middleware
// treats as unconditionally public for the client paths.
func endpointPath(id string) string { return "/protocols/acme/" + id }

// endpointFromPath resolves the endpoint named in the URL, scoped to the
// session's organization so an ID belonging to another customer is simply not
// found.
func (h Handler) endpointFromPath(w http.ResponseWriter, r *http.Request, s auth.Session) (Endpoint, bool) {
	id := r.PathValue("endpointID")
	if _, err := uuid.Parse(id); err != nil {
		enroll.FormError(w, r, errors.New("unknown ACME endpoint"))
		return Endpoint{}, false
	}
	e, err := h.repo.EndpointByID(r.Context(), s.OrgID, id)
	if errors.Is(err, sql.ErrNoRows) {
		enroll.FormError(w, r, errors.New("unknown ACME endpoint"))
		return e, false
	}
	if err != nil {
		http.Error(w, "ACME lookup failed", http.StatusInternalServerError)
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
	h.record(r, s, audit.ActionACMEEndpointCreated, e.Name, "")
	web.Done(w, r, endpointPath(e.ID), "ACME endpoint “"+e.Name+"” created")
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
	if err := h.repo.SetEnabled(r.Context(), s.OrgID, e.ID, enabled); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	action := audit.ActionACMEEndpointPaused
	message := "ACME endpoint “" + e.Name + "” paused. Clients can no longer order certificates."
	if enabled {
		action = audit.ActionACMEEndpointEnabled
		message = "ACME endpoint “" + e.Name + "” is now issuing certificates"
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
	// The EKU checkboxes name the usages to allow. The endpoint's ceiling is
	// narrowed against the CA's own issuance profile in the service, so nothing
	// selected here can widen what the CA will sign.
	update := PolicyUpdate{
		Name:           r.FormValue("name"),
		ValidityDays:   days,
		SubjectPattern: strings.TrimSpace(r.FormValue("subject_pattern")),
		SANPattern:     strings.TrimSpace(r.FormValue("san_pattern")),
		AllowedEKUs:    strings.Join(r.Form["allowed_eku"], ","),
	}
	if err := h.service.UpdatePolicy(r.Context(), s.OrgID, e.ID, update); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionACMEEndpointPolicy, update.Name, "")
	web.Done(w, r, endpointPath(e.ID), "Issuance policy saved")
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
	if err := h.repo.DeleteEndpoint(r.Context(), s.OrgID, e.ID); err != nil {
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionACMEEndpointDeleted, e.Name, "")
	web.Done(w, r, "/protocols", "ACME endpoint “"+e.Name+"” deleted")
}

// createCredential mints an External Account Binding credential and shows it
// once. Like scep.Handler.createChallenge this serves both the htmx dialog and
// JSON automation from one route, because an organization that provisions
// clients from a script needs the same operation an administrator gets a form
// for.
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
			Label       string   `json:"label"`
			Identifiers []string `json:"identifiers"`
			SingleUse   bool     `json:"single_use"`
			TTLHours    int      `json:"ttl_hours"`
		}
		if err := web.DecodeJSON(r, &body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		spec = CredentialSpec{Label: body.Label, Identifiers: body.Identifiers, SingleUse: body.SingleUse,
			TTL: time.Duration(body.TTLHours) * time.Hour}
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
		spec = CredentialSpec{Label: r.FormValue("label"), SingleUse: r.FormValue("single_use") == "true",
			Identifiers: enroll.SplitCSV(r.FormValue("identifiers")), TTL: time.Duration(hours) * time.Hour}
	}

	credential, macKey, err := h.service.CreateCredential(r.Context(), e, spec)
	if err != nil {
		if wantsJSON {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionACMECredentialIssued, e.Name, credential.Label)

	if wantsJSON {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = writeJSONBody(w, map[string]any{
			"directory":  h.service.endpointURL(e.ID) + "/directory",
			"kid":        credential.KID,
			"hmac_key":   macKey,
			"single_use": credential.SingleUse,
		})
		return
	}
	// The secret is swapped into the dialog rather than redirected to, because
	// this is the only moment it exists in a readable form.
	w.Header().Set("Cache-Control", "no-store")
	_ = homeview.ACMECredentialSecret(h.service.endpointURL(e.ID)+"/directory", credential.KID, macKey,
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
	if err := h.repo.RevokeCredential(r.Context(), s.OrgID, e.ID, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			enroll.FormError(w, r, errors.New("unknown credential"))
			return
		}
		enroll.FormError(w, r, err)
		return
	}
	h.record(r, s, audit.ActionACMECredentialRevoked, e.Name, id)
	web.Done(w, r, endpointPath(e.ID), "External account key revoked. Clients using it can no longer register.")
}

func writeJSONBody(w http.ResponseWriter, body any) error {
	return json.NewEncoder(w).Encode(body)
}
