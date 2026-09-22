package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

// store is the narrow slice of Repository this service needs. It exists so
// tests can substitute a fake and assert on side effects — that a rejected
// binding does not spend a single-use credential, that a rejected CSR never
// reaches the issuer — without a database. Repository satisfies it structurally.
type store interface {
	Endpoint(ctx context.Context, id string) (Endpoint, error)
	EndpointByID(ctx context.Context, orgID, id string) (Endpoint, error)
	Endpoints(ctx context.Context, orgID string) ([]Endpoint, error)
	InsertEndpoint(ctx context.Context, e Endpoint) error
	DeleteEndpoint(ctx context.Context, orgID, id string) error
	SetEnabled(ctx context.Context, orgID, id string, enabled bool) error
	UpdatePolicy(ctx context.Context, orgID, id string, p PolicyUpdate) error
	LiveCertificateCount(ctx context.Context, endpointID string) (int, error)

	CreateCredential(ctx context.Context, c EABCredential) error
	CredentialByKID(ctx context.Context, endpointID, kid string) (EABCredential, error)
	Credentials(ctx context.Context, endpointID string) ([]EABCredential, error)
	UseCredential(ctx context.Context, id string) error
	RevokeCredential(ctx context.Context, orgID, endpointID, id string) error

	Account(ctx context.Context, endpointID, id string) (Account, error)
	AccountByThumbprint(ctx context.Context, endpointID, thumbprint string) (Account, error)
	CreateAccount(ctx context.Context, a Account) error
	UpdateAccount(ctx context.Context, endpointID, id, contact, status string) error
	RekeyAccount(ctx context.Context, endpointID, id, thumbprint, jwkJSON string) error

	Order(ctx context.Context, endpointID, id string) (Order, error)
	OrderForUpdate(ctx context.Context, endpointID, id string) (Order, error)
	CreateOrder(ctx context.Context, o Order) error
	CompleteOrder(ctx context.Context, id, certificateID string) error
	FailOrder(ctx context.Context, id, problemType, detail string) error
	Orders(ctx context.Context, endpointID string, limit int) ([]Order, error)
	CertificateOrderedBy(ctx context.Context, accountID, certificateID string) (bool, error)

	Authorization(ctx context.Context, endpointID, id string) (Authorization, error)
	Authorizations(ctx context.Context, orderID string) ([]Authorization, error)
	CreateAuthorization(ctx context.Context, a Authorization, c Challenge) error
	Challenge(ctx context.Context, endpointID, id string) (Challenge, error)
	ChallengeFor(ctx context.Context, authorizationID string) (Challenge, error)

	IssueNonce(ctx context.Context, orgID, endpointID string, value []byte) error
	ConsumeNonce(ctx context.Context, endpointID string, value []byte) error
	LockOrganization(ctx context.Context, orgID string) error
}

// issuer is the one call a protocol module makes into the PKI.
type issuer interface {
	Issue(ctx context.Context, req appPKI.IssueRequest) (appPKI.Certificate, error)
	Revoke(ctx context.Context, req appPKI.RevokeRequest) error
}

// certificates is the read side of the PKI a revocation needs: ACME identifies a
// certificate by its DER, and pki.Service.Revoke identifies one by its row id.
type certificates interface {
	CertificateBySerial(ctx context.Context, orgID, caID, serial string) (appPKI.Certificate, error)
	Certificate(ctx context.Context, orgID, id string) (appPKI.Certificate, error)
}

type Service struct {
	repo      store
	pki       issuer
	pkiRepo   certificates
	keys      appPKI.KeyProvider
	publicURL string
}

func NewService(repo store, pki issuer, pkiRepo certificates, keys appPKI.KeyProvider, publicURL string) Service {
	return Service{repo: repo, pki: pki, pkiRepo: pkiRepo, keys: keys, publicURL: publicURL}
}

// ---------------------------------------------------------------------------
// Endpoint administration
// ---------------------------------------------------------------------------

// CreateEndpointRequest describes a new ACME endpoint.
type CreateEndpointRequest struct {
	OrgID, UserID, CAID, Name string
}

// CreateEndpoint mints an ACME endpoint. There is no registration authority to
// generate, so unlike scep.Service.CreateEndpoint this costs no KMS operation —
// but the checks stay in the same order anyway, because the cheapest rejection
// is still the one that never touched the database.
func (s Service) CreateEndpoint(ctx context.Context, req CreateEndpointRequest) (Endpoint, error) {
	name, err := validEndpointName(req.Name)
	if err != nil {
		return Endpoint{}, err
	}
	caID := strings.TrimSpace(req.CAID)
	if caID == "" {
		return Endpoint{}, fmt.Errorf("select an issuing certificate authority")
	}
	existing, err := s.repo.Endpoints(ctx, req.OrgID)
	if err != nil {
		return Endpoint{}, err
	}
	// Checked here as well as by the unique index so the common collision gets
	// the message that names the endpoint; the index is the backstop for a race.
	for _, e := range existing {
		if strings.EqualFold(e.Name, name) {
			return Endpoint{}, fmt.Errorf("an endpoint called %q already exists; pick another name", name)
		}
	}
	// SANPattern starts permissive rather than at its zero value. An empty SAN
	// pattern issues nothing at all (see checkIdentifier), which is the right
	// default for an endpoint an administrator has deliberately locked down, but
	// the wrong one for an endpoint that was just created and has not been
	// configured either way — that should work out of the box and be narrowed
	// from here, not start silently refusing every order.
	e := Endpoint{ID: uuid.NewString(), OrganizationID: req.OrgID, CAID: caID, Name: name,
		ValidityDays: DefaultValidityDays, AllowedEKUs: appPKI.EKUServerAuth, SANPattern: ".*"}
	return e, s.repo.InsertEndpoint(ctx, e)
}

// validEndpointName normalizes an administrator-supplied endpoint name. The name
// is a link label and a page title, never part of a URL or a query, so beyond
// length and control characters it is left alone.
func validEndpointName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("name the endpoint")
	}
	if len([]rune(name)) > 64 {
		return "", fmt.Errorf("the endpoint name must be 64 characters or fewer")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("the endpoint name contains invalid characters")
		}
	}
	return name, nil
}

// UpdatePolicy changes what an endpoint will issue. The EKU pin is narrowed
// against the CA's own issuance profile so an endpoint can never widen what its
// CA is willing to sign.
func (s Service) UpdatePolicy(ctx context.Context, orgID, id string, p PolicyUpdate) error {
	name, err := validEndpointName(p.Name)
	if err != nil {
		return err
	}
	p.Name = name
	if p.ValidityDays < 1 || p.ValidityDays > 3650 {
		return fmt.Errorf("certificate validity must be between 1 and 3650 days")
	}
	for label, pattern := range map[string]string{"subject": p.SubjectPattern, "SAN": p.SANPattern} {
		if pattern == "" {
			continue
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("the %s pattern is not a valid regular expression", label)
		}
	}
	if _, err := appPKI.ValidateEKUs(enroll.SplitCSV(p.AllowedEKUs)); err != nil {
		return err
	}
	return s.repo.UpdatePolicy(ctx, orgID, id, p)
}

// ---------------------------------------------------------------------------
// External Account Binding credentials
// ---------------------------------------------------------------------------

// CreateCredential mints an External Account Binding credential and returns the
// MAC key in plaintext. This is the only time it is ever readable: what is
// stored is the sealed form, because verifying a binding is an HMAC computation
// and needs the key material back — the argon2id verifier scep_challenge uses
// would be useless here.
func (s Service) CreateCredential(ctx context.Context, e Endpoint, spec CredentialSpec) (EABCredential, string, error) {
	label := strings.TrimSpace(spec.Label)
	if len([]rune(label)) > 64 {
		return EABCredential{}, "", fmt.Errorf("the label must be 64 characters or fewer")
	}
	var pinned []string
	for _, id := range spec.Identifiers {
		id = strings.TrimSpace(strings.ToLower(id))
		if id == "" {
			continue
		}
		if strings.ContainsAny(id, ", ") {
			return EABCredential{}, "", fmt.Errorf("%q is not a single identifier", id)
		}
		pinned = append(pinned, id)
	}

	// The kid is what the client sends and what the credential is looked up by,
	// so it has to be unguessable as well as unique: a kid that could be
	// enumerated would tell an attacker which credentials exist to attack.
	kid, err := enroll.RandomSecret()
	if err != nil {
		return EABCredential{}, "", err
	}
	macKey := make([]byte, 32)
	if _, err := rand.Read(macKey); err != nil {
		return EABCredential{}, "", err
	}

	id := uuid.NewString()
	ciphertext, err := s.keys.Protect(ctx, credentialPurpose(id), macKey)
	if err != nil {
		return EABCredential{}, "", err
	}
	c := EABCredential{ID: id, OrganizationID: e.OrganizationID, EndpointID: e.ID, Label: label,
		KID: kid, MACKeyCiphertext: ciphertext, IdentifierPin: strings.Join(pinned, ","),
		SingleUse: spec.SingleUse}
	if spec.TTL > 0 {
		expires := time.Now().Add(spec.TTL)
		c.ExpiresAt = &expires
	}
	if err := s.repo.CreateCredential(ctx, c); err != nil {
		return EABCredential{}, "", err
	}
	// Clients take the MAC key base64url-encoded, which is what RFC 8555 §7.3.4
	// makes it on the wire, so it is handed over in that form rather than as hex
	// an operator would have to convert.
	return c, base64.RawURLEncoding.EncodeToString(macKey), nil
}

func credentialPurpose(id string) string { return "acme-eab/" + id }

// ---------------------------------------------------------------------------
// Directory and nonces
// ---------------------------------------------------------------------------

// Directory is the RFC 8555 §7.1.1 resource, the one URL a client is configured
// with. externalAccountRequired is what tells a client it needs a credential
// before it tries to register.
func (s Service) Directory(e Endpoint) map[string]any {
	base := s.endpointURL(e.ID)
	return map[string]any{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		"newOrder":   base + "/new-order",
		"revokeCert": base + "/revoke-cert",
		"keyChange":  base + "/key-change",
		"meta": map[string]any{
			"website":                 s.publicURL,
			"externalAccountRequired": true,
		},
	}
	// renewalInfo is deliberately absent. A client that does not find it falls
	// back to its own renewal timer, which is the correct behaviour until ARI
	// (RFC 9773) is implemented.
}

func (s Service) endpointURL(id string) string {
	return strings.TrimRight(s.publicURL, "/") + "/acme/" + id
}

// NewNonce mints a replay nonce. Nonces are stored rather than derived because
// single use has to hold across every instance serving the endpoint, and a
// signed-but-stateless nonce cannot be spent.
func (s Service) NewNonce(ctx context.Context, e Endpoint) (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	if err := s.repo.IssueNonce(ctx, e.OrganizationID, e.ID, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// consumeNonce spends the nonce in a parsed request. Anything that is not a
// clean spend is badNonce, which every client responds to by fetching a fresh
// one and retrying — so this is a soft failure rather than an error an operator
// ever needs to see.
func (s Service) consumeNonce(ctx context.Context, e Endpoint, j *jws) error {
	stale := problemf(http.StatusBadRequest, ProblemBadNonce,
		"the replay nonce is missing, expired, or has already been used")
	value, err := base64.RawURLEncoding.DecodeString(j.header.Nonce)
	if err != nil || len(value) == 0 {
		return stale
	}
	if err := s.repo.ConsumeNonce(ctx, e.ID, value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return stale
		}
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Request authentication
// ---------------------------------------------------------------------------

// request is a verified ACME request: the signature checked, the nonce spent,
// and — for a kid-signed request — the account it came from resolved.
type request struct {
	jws     *jws
	account Account
	// jwkJSON is the raw account key for a jwk-signed request. newAccount and
	// key-change need it; everything else identifies itself by kid.
	jwkJSON    string
	thumbprint string
}

// Authenticate performs every check RFC 8555 §6 requires of an inbound request,
// in an order chosen so nothing expensive runs on behalf of an unverified
// client.
//
// requireAccount is false only for newAccount and for a revocation signed by the
// certificate's own key, which are the two requests that legitimately arrive
// without an account to name.
func (s Service) Authenticate(ctx context.Context, e Endpoint, body []byte, url string,
	requireAccount bool) (*request, error) {
	j, err := parseJWS(body)
	if err != nil {
		return nil, err
	}
	if err := j.checkOuter(url); err != nil {
		return nil, err
	}
	// The nonce is spent before the signature is checked. That ordering is
	// deliberate: a nonce that is only spent on success would let an attacker
	// probe signatures indefinitely against one nonce, and the client's response
	// to badNonce is a retry either way.
	if err := s.consumeNonce(ctx, e, j); err != nil {
		return nil, err
	}

	req := &request{jws: j}
	if len(j.header.JWK) > 0 {
		if requireAccount {
			return nil, problemf(http.StatusBadRequest, ProblemMalformed,
				"this request must be signed with the account's key identifier, not an embedded key")
		}
		key, err := parseJWK(j.header.JWK)
		if err != nil {
			return nil, err
		}
		if err := j.verify(key); err != nil {
			return nil, err
		}
		thumbprint, err := jwkThumbprint(j.header.JWK)
		if err != nil {
			return nil, err
		}
		req.jwkJSON, req.thumbprint = string(j.header.JWK), thumbprint
		return req, nil
	}

	// A kid is the account URL. Only the last path element identifies the
	// account, and it is matched against this endpoint's own prefix so a kid
	// naming another endpoint's account cannot be presented here.
	accountID, ok := s.accountFromKID(e, j.header.KID)
	if !ok {
		return nil, problemf(http.StatusBadRequest, ProblemAccountDoesNotExist,
			"the key identifier is not an account on this endpoint")
	}
	account, err := s.repo.Account(ctx, e.ID, accountID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, problemf(http.StatusBadRequest, ProblemAccountDoesNotExist, "no such account")
		}
		return nil, err
	}
	if account.Status != StatusValid {
		return nil, problemf(http.StatusForbidden, ProblemUnauthorized,
			"this account is %s and can no longer be used", account.Status)
	}
	key, err := parseJWK([]byte(account.JWKJSON))
	if err != nil {
		return nil, err
	}
	if err := j.verify(key); err != nil {
		return nil, err
	}
	req.account, req.jwkJSON, req.thumbprint = account, account.JWKJSON, account.JWKThumbprint
	return req, nil
}

func (s Service) accountFromKID(e Endpoint, kid string) (string, bool) {
	prefix := s.endpointURL(e.ID) + "/accounts/"
	if !strings.HasPrefix(kid, prefix) {
		return "", false
	}
	id := strings.TrimPrefix(kid, prefix)
	if _, err := uuid.Parse(id); err != nil {
		return "", false
	}
	return id, true
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

type newAccountPayload struct {
	Contact                []string        `json:"contact"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
}

// NewAccount registers a client, or returns the account its key already owns.
//
// Every registration must carry an External Account Binding. That is the whole
// authorization model: there is no challenge a client can complete to prove it
// belongs here, so the credential an administrator handed it is the proof, and
// the constraints on that credential become the constraints on the account.
func (s Service) NewAccount(ctx context.Context, e Endpoint, req *request, url string) (Account, bool, error) {
	var payload newAccountPayload
	if err := json.Unmarshal(req.jws.payload, &payload); err != nil {
		return Account{}, false, problemf(http.StatusBadRequest, ProblemMalformed,
			"the account registration is not a JSON object")
	}
	contact, err := validContacts(payload.Contact)
	if err != nil {
		return Account{}, false, err
	}

	existing, err := s.repo.AccountByThumbprint(ctx, e.ID, req.thumbprint)
	switch {
	case err == nil:
		if existing.Status != StatusValid {
			return Account{}, false, problemf(http.StatusForbidden, ProblemUnauthorized,
				"the account for this key is %s", existing.Status)
		}
		return existing, false, nil
	case !errors.Is(err, sql.ErrNoRows):
		return Account{}, false, err
	}
	// onlyReturnExisting asks for a lookup, not a registration (§7.3.1), so a
	// miss is an answer rather than a reason to create anything.
	if payload.OnlyReturnExisting {
		return Account{}, false, problemf(http.StatusBadRequest, ProblemAccountDoesNotExist,
			"no account is registered for that key")
	}

	credential, err := s.bindExternalAccount(ctx, e, payload.ExternalAccountBinding, req.jwkJSON, url)
	if err != nil {
		return Account{}, false, err
	}

	account := Account{ID: uuid.NewString(), OrganizationID: e.OrganizationID, EndpointID: e.ID,
		JWKThumbprint: req.thumbprint, JWKJSON: req.jwkJSON, Status: StatusValid, Contact: contact,
		EABCredentialID: credential.ID, IdentifierPin: credential.IdentifierPin}
	// The credential is spent before the account is written. If the two cannot
	// both happen the transaction rolls back, but the ordering means a
	// single-use credential can never be left spendable next to an account it
	// already bound.
	if err := s.repo.UseCredential(ctx, credential.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Account{}, false, problemf(http.StatusForbidden, ProblemUnauthorized,
				"that external account credential has already been used")
		}
		return Account{}, false, err
	}
	if err := s.repo.CreateAccount(ctx, account); err != nil {
		return Account{}, false, err
	}
	return account, true, nil
}

// bindExternalAccount verifies the binding in a registration (§7.3.4).
//
// The inner JWS is signed with the credential's MAC key over the account key the
// outer JWS carries. Verifying it proves the client holds a credential this
// organization issued, and — because the payload is the account key — that the
// binding was made for this key rather than replayed from another registration.
func (s Service) bindExternalAccount(ctx context.Context, e Endpoint, raw json.RawMessage,
	accountJWK, url string) (EABCredential, error) {
	if len(raw) == 0 {
		return EABCredential{}, problemf(http.StatusBadRequest, ProblemExternalAccountRequired,
			"this endpoint requires an external account binding; configure your client with the key identifier and HMAC key from the SimpleSCEP console")
	}
	inner, err := parseJWS(raw)
	if err != nil {
		return EABCredential{}, err
	}
	if inner.header.KID == "" || len(inner.header.JWK) > 0 {
		return EABCredential{}, problemf(http.StatusBadRequest, ProblemMalformed,
			"the external account binding must identify its credential by kid and carry no embedded key")
	}
	// The inner JWS is bound to the same newAccount URL as the outer one, so a
	// binding captured against one endpoint cannot be presented to another.
	if inner.header.URL != url {
		return EABCredential{}, problemf(http.StatusBadRequest, ProblemUnauthorized,
			"the external account binding was not signed for this address")
	}

	credential, err := s.repo.CredentialByKID(ctx, e.ID, inner.header.KID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Deliberately the same message an unusable credential gets: which
			// kids exist is not something an unauthenticated caller should be
			// able to learn by comparing responses.
			return EABCredential{}, problemf(http.StatusUnauthorized, ProblemUnauthorized,
				"that external account credential is not valid for this endpoint")
		}
		return EABCredential{}, err
	}
	if !credential.Usable(time.Now()) {
		return EABCredential{}, problemf(http.StatusUnauthorized, ProblemUnauthorized,
			"that external account credential is not valid for this endpoint")
	}

	macKey, err := s.keys.Unprotect(ctx, credentialPurpose(credential.ID), credential.MACKeyCiphertext)
	if err != nil {
		return EABCredential{}, err
	}
	if err := inner.verifyHMAC(macKey); err != nil {
		return EABCredential{}, err
	}
	// The binding's payload must be the account key being registered. Without
	// this the MAC would prove only that somebody once held the credential, and
	// a captured binding could be replayed to register an attacker's key.
	bound, err := jwkThumbprint(inner.payload)
	if err != nil {
		return EABCredential{}, err
	}
	mine, err := jwkThumbprint([]byte(accountJWK))
	if err != nil {
		return EABCredential{}, err
	}
	if bound != mine {
		return EABCredential{}, problemf(http.StatusUnauthorized, ProblemUnauthorized,
			"the external account binding does not cover the key this request was signed with")
	}
	return credential, nil
}

// UpdateAccount applies a §7.3.2 account update. Contact details can change and
// an account can deactivate itself; nothing else about it is a client's to
// modify, and fields outside those are ignored rather than refused, as the
// specification requires.
func (s Service) UpdateAccount(ctx context.Context, e Endpoint, account Account, payload []byte) (Account, error) {
	var update struct {
		Contact []string `json:"contact"`
		Status  string   `json:"status"`
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &update); err != nil {
			return Account{}, problemf(http.StatusBadRequest, ProblemMalformed,
				"the account update is not a JSON object")
		}
	}
	contact := account.Contact
	if update.Contact != nil {
		c, err := validContacts(update.Contact)
		if err != nil {
			return Account{}, err
		}
		contact = c
	}
	status := account.Status
	switch update.Status {
	case "":
	case StatusDeactivated:
		status = StatusDeactivated
	default:
		return Account{}, problemf(http.StatusBadRequest, ProblemMalformed,
			"an account can only be set to deactivated")
	}
	if err := s.repo.UpdateAccount(ctx, e.ID, account.ID, contact, status); err != nil {
		return Account{}, err
	}
	account.Contact, account.Status = contact, status
	return account, nil
}

// KeyChange rotates the key an account authenticates with (§7.3.5).
//
// The request is doubly signed: the outer JWS by the old key, proving the
// request comes from the account's current owner, and an inner JWS by the new
// key over {account, oldKey}, proving whoever asked for the change actually
// holds the key they are asking to move to. Either signature alone would be a
// way to lock an account out.
func (s Service) KeyChange(ctx context.Context, e Endpoint, req *request, url string) error {
	inner, err := parseJWS(req.jws.payload)
	if err != nil {
		return err
	}
	if err := inner.checkOuter(url); err != nil {
		return err
	}
	if len(inner.header.JWK) == 0 {
		return problemf(http.StatusBadRequest, ProblemMalformed,
			"the key change request must carry the new key in its protected header")
	}
	newKey, err := parseJWK(inner.header.JWK)
	if err != nil {
		return err
	}
	if err := inner.verify(newKey); err != nil {
		return err
	}

	var payload struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if err := json.Unmarshal(inner.payload, &payload); err != nil {
		return problemf(http.StatusBadRequest, ProblemMalformed, "the key change payload is not a JSON object")
	}
	// Both fields are checked against the outer request rather than trusted.
	// Omitting either check would let a signed key-change be replayed against a
	// different account.
	id, ok := s.accountFromKID(e, payload.Account)
	if !ok || id != req.account.ID {
		return problemf(http.StatusBadRequest, ProblemMalformed,
			"the key change names a different account than the one that signed it")
	}
	oldThumbprint, err := jwkThumbprint(payload.OldKey)
	if err != nil {
		return err
	}
	if oldThumbprint != req.account.JWKThumbprint {
		return problemf(http.StatusBadRequest, ProblemMalformed,
			"the key change does not name the account's current key")
	}

	thumbprint, err := jwkThumbprint(inner.header.JWK)
	if err != nil {
		return err
	}
	if thumbprint == req.account.JWKThumbprint {
		return problemf(http.StatusBadRequest, ProblemMalformed, "the new key is the same as the old one")
	}
	err = s.repo.RekeyAccount(ctx, e.ID, req.account.ID, thumbprint, string(inner.header.JWK))
	if database.DuplicateKey(err) {
		return problemf(http.StatusConflict, ProblemMalformed,
			"that key already belongs to another account on this endpoint")
	}
	return err
}

// validContacts checks the contact URIs on a registration. Only mailto: is
// accepted, which is all any client sends and all this product could act on.
func validContacts(raw []string) (string, error) {
	var out []string
	for _, c := range raw {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.HasPrefix(c, "mailto:") {
			return "", problemf(http.StatusBadRequest, ProblemUnsupportedIdentifier,
				"%q is not a contact address this server accepts; use a mailto: URI", c)
		}
		if strings.ContainsAny(c, ",") {
			return "", problemf(http.StatusBadRequest, ProblemMalformed, "a contact address may not contain a comma")
		}
		out = append(out, c)
	}
	return strings.Join(out, ","), nil
}

// ---------------------------------------------------------------------------
// Orders
// ---------------------------------------------------------------------------

type newOrderPayload struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore"`
	NotAfter    string       `json:"notAfter"`
}

// NewOrder creates an order and the authorizations under it.
//
// The authorizations are created valid. Under the external-account model there
// is nothing left for the client to prove: it already proved it may enroll here
// when it bound its account, and what it may enroll *for* is decided here, by the
// credential's identifier pin and the endpoint's SAN policy. Checking that now
// rather than only at finalize means a client whose configuration asks for the
// wrong name is told so immediately, naming the identifier, which is the only
// diagnostic an unattended client leaves in its log.
func (s Service) NewOrder(ctx context.Context, e Endpoint, account Account, payload []byte) (Order, []Authorization, error) {
	var body newOrderPayload
	if err := json.Unmarshal(payload, &body); err != nil {
		return Order{}, nil, problemf(http.StatusBadRequest, ProblemMalformed, "the order is not a JSON object")
	}
	if len(body.Identifiers) == 0 {
		return Order{}, nil, problemf(http.StatusBadRequest, ProblemMalformed,
			"an order must name at least one identifier")
	}
	if len(body.Identifiers) > 100 {
		return Order{}, nil, problemf(http.StatusBadRequest, ProblemMalformed,
			"an order may name at most 100 identifiers")
	}

	identifiers, err := normalizeIdentifiers(body.Identifiers)
	if err != nil {
		return Order{}, nil, err
	}
	for _, id := range identifiers {
		if err := checkIdentifier(e, account, id); err != nil {
			return Order{}, nil, err
		}
	}

	now := time.Now()
	order := Order{ID: uuid.NewString(), OrganizationID: e.OrganizationID, EndpointID: e.ID,
		AccountID: account.ID, Status: StatusReady, ExpiresAt: now.Add(OrderTTL)}
	if body.NotBefore != "" {
		t, err := time.Parse(time.RFC3339, body.NotBefore)
		if err != nil {
			return Order{}, nil, problemf(http.StatusBadRequest, ProblemMalformed, "notBefore is not an RFC 3339 timestamp")
		}
		order.NotBefore = &t
	}
	if body.NotAfter != "" {
		t, err := time.Parse(time.RFC3339, body.NotAfter)
		if err != nil {
			return Order{}, nil, problemf(http.StatusBadRequest, ProblemMalformed, "notAfter is not an RFC 3339 timestamp")
		}
		order.NotAfter = &t
	}
	if err := s.repo.CreateOrder(ctx, order); err != nil {
		return Order{}, nil, err
	}

	authorizations := make([]Authorization, 0, len(identifiers))
	for _, id := range identifiers {
		a := Authorization{ID: uuid.NewString(), OrganizationID: e.OrganizationID, OrderID: order.ID,
			IdentifierType: id.Type, IdentifierValue: id.Value, Status: StatusValid,
			ExpiresAt: order.ExpiresAt, ValidatedAt: &now}
		token, err := enroll.RandomSecret()
		if err != nil {
			return Order{}, nil, err
		}
		c := Challenge{ID: uuid.NewString(), OrganizationID: e.OrganizationID, AuthorizationID: a.ID,
			Type: ChallengeExternal, Token: token, Status: StatusValid, ValidatedAt: &now}
		if err := s.repo.CreateAuthorization(ctx, a, c); err != nil {
			return Order{}, nil, err
		}
		authorizations = append(authorizations, a)
	}
	return order, authorizations, nil
}

// normalizeIdentifiers lowercases and de-duplicates the names an order asks for,
// so the set comparison finalize makes against the CSR is not defeated by case
// or by a repeat.
func normalizeIdentifiers(raw []Identifier) ([]Identifier, error) {
	seen := map[string]bool{}
	out := make([]Identifier, 0, len(raw))
	for _, id := range raw {
		value := strings.TrimSpace(strings.ToLower(id.Value))
		if value == "" {
			return nil, problemf(http.StatusBadRequest, ProblemMalformed, "an identifier may not be empty")
		}
		switch id.Type {
		case IdentifierDNS:
			// A wildcard would have to be proven by dns-01, which this server
			// does not run, so accepting one would be issuing a wildcard on no
			// evidence at all.
			if strings.HasPrefix(value, "*.") {
				return nil, problemf(http.StatusBadRequest, ProblemRejectedIdentifier,
					"wildcard identifiers are not issued by this server; name each host explicitly")
			}
			if strings.ContainsAny(value, " ,\t\n") {
				return nil, problemf(http.StatusBadRequest, ProblemMalformed, "%q is not a valid DNS name", value)
			}
		case IdentifierIP:
			if net.ParseIP(value) == nil {
				return nil, problemf(http.StatusBadRequest, ProblemMalformed, "%q is not a valid IP address", value)
			}
		default:
			return nil, problemf(http.StatusBadRequest, ProblemUnsupportedIdentifier,
				"%q is not an identifier type this server issues for", id.Type)
		}
		key := id.Type + ":" + value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Identifier{Type: id.Type, Value: value})
	}
	if len(out) == 0 {
		return nil, problemf(http.StatusBadRequest, ProblemMalformed, "an order must name at least one identifier")
	}
	return out, nil
}

// checkIdentifier is the authorization decision this server makes in place of a
// challenge: may this account ask for this name?
//
// The credential's pin is checked first and is absolute — a credential minted
// for one host cannot order another even if the endpoint policy would allow it.
// The endpoint's SAN pattern is the broader limit that applies to everyone.
func checkIdentifier(e Endpoint, account Account, id Identifier) error {
	if pinned := enroll.SplitCSV(account.IdentifierPin); len(pinned) > 0 {
		if !slices.Contains(pinned, id.Value) {
			return problemf(http.StatusForbidden, ProblemRejectedIdentifier,
				"this account's credential is not permitted to order %q", id.Value)
		}
	}
	// An unset SAN pattern permits nothing, matching pki.NamePolicy. An ACME
	// order names the identifiers that become the certificate's SANs, so an
	// endpoint with no SAN rule orders nothing at all until an administrator
	// writes one — which is the whole point of the default being closed, and is
	// said plainly here so the client is not left guessing at a 403.
	if e.SANPattern == "" {
		return problemf(http.StatusForbidden, ProblemRejectedIdentifier,
			"this endpoint has no SAN policy configured, so it permits no identifiers")
	}
	re, err := regexp.Compile(e.SANPattern)
	if err != nil {
		return fmt.Errorf("the endpoint's SAN policy is not a valid regular expression")
	}
	if !re.MatchString(id.Value) {
		return problemf(http.StatusForbidden, ProblemRejectedIdentifier,
			"%q is not permitted by this endpoint's issuance policy", id.Value)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Finalize
// ---------------------------------------------------------------------------

// Finalize turns a ready order into a certificate.
//
// The step order follows scep.Service.PKIOperation for the same reason: every
// cheap local check runs before anything that costs a KMS signing operation, and
// the advisory lock serialises the idempotency check with the issuance so two
// clients finalizing the same order cannot both reach the issuer.
func (s Service) Finalize(ctx context.Context, e Endpoint, account Account, orderID string,
	payload []byte) (Order, error) {
	var body struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &body); err != nil || body.CSR == "" {
		return Order{}, problemf(http.StatusBadRequest, ProblemMalformed,
			"the finalize request must carry a base64url-encoded CSR")
	}

	if err := s.repo.LockOrganization(ctx, e.OrganizationID); err != nil {
		return Order{}, err
	}
	order, err := s.repo.OrderForUpdate(ctx, e.ID, orderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Order{}, problemf(http.StatusNotFound, ProblemMalformed, "no such order")
		}
		return Order{}, err
	}
	if order.AccountID != account.ID {
		// Not found rather than forbidden: another account's order is not this
		// client's business to learn the existence of.
		return Order{}, problemf(http.StatusNotFound, ProblemMalformed, "no such order")
	}
	// A repeated finalize returns what the first one produced. Clients retry on
	// a dropped connection, and re-issuing would spend a KMS operation and a
	// certificate slot for a certificate the client already has.
	if order.Status == StatusValid {
		return order, nil
	}
	if order.Status != StatusReady {
		return Order{}, problemf(http.StatusForbidden, ProblemOrderNotReady,
			"this order is %s and cannot be finalized", order.Status)
	}
	if !order.ExpiresAt.After(time.Now()) {
		return Order{}, problemf(http.StatusForbidden, ProblemMalformed, "this order has expired; create a new one")
	}

	authorizations, err := s.repo.Authorizations(ctx, order.ID)
	if err != nil {
		return Order{}, err
	}
	csr, err := parseCSR(body.CSR)
	if err != nil {
		return Order{}, err
	}
	// pki refuses a key below the floor as well, but this yields a badCSR problem
	// document naming the key rather than a generic refusal out of Issue, which
	// is what an ACME client can act on.
	if err := appPKI.ValidatePublicKey(csr.PublicKey); err != nil {
		return Order{}, problemf(http.StatusBadRequest, ProblemBadCSR, "%s", err.Error())
	}
	if err := checkCSRNames(csr, authorizations); err != nil {
		return Order{}, err
	}
	if err := checkSubjectPolicy(e, csr); err != nil {
		return Order{}, err
	}

	cert, err := s.pki.Issue(ctx, appPKI.IssueRequest{
		OrgID: e.OrganizationID, CAID: e.CAID,
		CSRPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})),
		Days:    e.ValidityDays,
		EKUs:    enroll.SplitCSV(e.AllowedEKUs),
		Purpose: "acme",
		Profile: appPKI.CertProfileACME,
	})
	if err != nil {
		// The issuer's refusal is the customer's own policy talking — a CSR the
		// CA will not sign — so the reason is recorded on the order, which is
		// where an unattended client's operator will go looking for it.
		_ = s.repo.FailOrder(ctx, order.ID, ProblemBadCSR, err.Error())
		return Order{}, problemf(http.StatusForbidden, ProblemBadCSR, "%s", err.Error())
	}
	if err := s.repo.CompleteOrder(ctx, order.ID, cert.ID); err != nil {
		return Order{}, err
	}
	order.Status, order.CertificateID = StatusValid, cert.ID
	return order, nil
}

func parseCSR(encoded string) (*x509.CertificateRequest, error) {
	bad := func(detail string) error {
		return problemf(http.StatusBadRequest, ProblemBadCSR, "%s", detail)
	}
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, bad("the CSR is not base64url-encoded DER")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, bad("the CSR could not be parsed")
	}
	// A CSR is a self-signed assertion of key possession; without this check it
	// asserts nothing, and anyone could order a certificate for a key they do
	// not hold.
	if err := csr.CheckSignature(); err != nil {
		return nil, bad("the CSR's signature does not verify against the key it carries")
	}
	return csr, nil
}

// checkCSRNames enforces RFC 8555 §7.4: the CSR must ask for exactly the
// identifiers the order was authorized for. Not a subset, not a superset.
//
// This is the single most important check in the package. pki.Service.Issue
// reads the subject and SANs out of the CSR's DER verbatim rather than from any
// parameter it is passed, so nothing downstream will notice that the certificate
// being signed covers a name the order never mentioned. A superset here is an
// unauthorized issuance; a subset is a client bug worth failing loudly rather
// than quietly issuing something narrower than asked for.
func checkCSRNames(csr *x509.CertificateRequest, authorizations []Authorization) error {
	authorized := map[string]bool{}
	for _, a := range authorizations {
		if a.Status != StatusValid {
			return problemf(http.StatusForbidden, ProblemUnauthorized,
				"the authorization for %q is %s", a.IdentifierValue, a.Status)
		}
		authorized[a.IdentifierType+":"+a.IdentifierValue] = true
	}

	requested := map[string]bool{}
	for _, name := range csr.DNSNames {
		requested[IdentifierDNS+":"+strings.ToLower(name)] = true
	}
	for _, ip := range csr.IPAddresses {
		requested[IdentifierIP+":"+ip.String()] = true
	}
	// Anything the CSR carries beyond DNS names and IP addresses would reach the
	// certificate too — pki copies the SAN extension through, including
	// otherName forms — and no order can authorize it, because those are not
	// identifier types this server issues for.
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 ||
		len(appPKI.UnparsedSANs(appPKI.SubjectAltName(csr))) > 0 {
		return problemf(http.StatusBadRequest, ProblemBadCSR,
			"the CSR carries subject alternative names of a kind this server does not issue")
	}

	for key := range requested {
		if !authorized[key] {
			return problemf(http.StatusForbidden, ProblemUnauthorized,
				"the CSR asks for %q, which this order is not authorized for", strings.SplitN(key, ":", 2)[1])
		}
	}
	for key := range authorized {
		if !requested[key] {
			return problemf(http.StatusBadRequest, ProblemBadCSR,
				"the CSR omits %q, which this order covers", strings.SplitN(key, ":", 2)[1])
		}
	}

	// A common name is copied into the certificate's subject, so it has to be
	// covered by an authorization like any other name. An empty CN is fine and
	// is what most ACME clients send.
	if cn := strings.ToLower(strings.TrimSpace(csr.Subject.CommonName)); cn != "" {
		if !authorized[IdentifierDNS+":"+cn] && !authorized[IdentifierIP+":"+cn] {
			return problemf(http.StatusForbidden, ProblemUnauthorized,
				"the CSR's common name %q is not one of this order's identifiers", cn)
		}
	}
	return nil
}

// checkSubjectPolicy applies the endpoint's subject pattern. The SAN pattern was
// already applied to each identifier at order time, which is where a client gets
// a useful message; this is the subject half, which only a CSR can carry.
func checkSubjectPolicy(e Endpoint, csr *x509.CertificateRequest) error {
	if e.SubjectPattern == "" {
		return nil
	}
	re, err := regexp.Compile(e.SubjectPattern)
	if err != nil {
		return fmt.Errorf("the endpoint's subject policy is not a valid regular expression")
	}
	if !re.MatchString(appPKI.RenderSubject(csr.RawSubject, csr.Subject)) {
		return problemf(http.StatusForbidden, ProblemRejectedIdentifier,
			"the CSR's subject is not permitted by this endpoint's issuance policy")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Certificate retrieval and revocation
// ---------------------------------------------------------------------------

// Certificate returns the PEM chain for a finalized order: the leaf first, then
// the issuing CA, which is what application/pem-certificate-chain means and what
// a client installs.
func (s Service) Certificate(ctx context.Context, e Endpoint, account Account, orderID string) (string, error) {
	order, err := s.repo.Order(ctx, e.ID, orderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", problemf(http.StatusNotFound, ProblemMalformed, "no such certificate")
		}
		return "", err
	}
	if order.AccountID != account.ID || order.Status != StatusValid || order.CertificateID == "" {
		return "", problemf(http.StatusNotFound, ProblemMalformed, "no such certificate")
	}
	cert, err := s.pkiRepo.Certificate(ctx, e.OrganizationID, order.CertificateID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", problemf(http.StatusNotFound, ProblemMalformed, "no such certificate")
		}
		return "", err
	}
	chain := strings.TrimRight(cert.CertificatePEM, "\n")
	if cert.ChainPEM != "" {
		chain += "\n" + strings.TrimRight(cert.ChainPEM, "\n")
	}
	return chain + "\n", nil
}

type revokePayload struct {
	Certificate string `json:"certificate"`
	Reason      *int   `json:"reason"`
}

// Revoke implements §7.6.
//
// The two APIs identify a certificate differently — ACME by its DER, the PKI by
// its row — so this bridges them through the serial, which both sides write as
// big.Int.Text(16).
//
// A request may be signed either by the account that ordered the certificate or
// by the certificate's own key. The second form is what a client uses when it
// has lost its account but still holds the key it wants to disown, and req.account
// is empty in that case.
func (s Service) Revoke(ctx context.Context, e Endpoint, req *request) error {
	var payload revokePayload
	if err := json.Unmarshal(req.jws.payload, &payload); err != nil || payload.Certificate == "" {
		return problemf(http.StatusBadRequest, ProblemMalformed,
			"the revocation must carry a base64url-encoded certificate")
	}
	der, err := base64.RawURLEncoding.DecodeString(payload.Certificate)
	if err != nil {
		return problemf(http.StatusBadRequest, ProblemMalformed, "the certificate is not base64url-encoded DER")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return problemf(http.StatusBadRequest, ProblemMalformed, "the certificate could not be parsed")
	}

	reason := "unspecified"
	if payload.Reason != nil {
		mapped, ok := RevocationReasons[*payload.Reason]
		if !ok {
			return problemf(http.StatusBadRequest, ProblemBadRevocationReason,
				"revocation reason %d has no equivalent in this product; use 0, 1, 3, 4, or 5", *payload.Reason)
		}
		reason = mapped
	}

	cert, err := s.pkiRepo.CertificateBySerial(ctx, e.OrganizationID, e.CAID, parsed.SerialNumber.Text(16))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return problemf(http.StatusNotFound, ProblemMalformed,
				"that certificate was not issued by this endpoint's certificate authority")
		}
		return err
	}
	if err := s.authorizeRevocation(ctx, req, cert, der); err != nil {
		return err
	}
	if cert.Status == "revoked" {
		return problemf(http.StatusBadRequest, ProblemAlreadyRevoked, "that certificate is already revoked")
	}
	return s.pki.Revoke(ctx, appPKI.RevokeRequest{OrgID: e.OrganizationID, CertificateID: cert.ID, Reason: reason})
}

// authorizeRevocation decides whether this signer may revoke this certificate.
//
// Two ways in. An account-signed request must be the account that ordered it:
// holding *an* account on this endpoint is not authority over another
// customer's — or another tenant's — certificate. A jwk-signed request must
// carry the certificate's own public key, which proves possession of the subject
// key and is the escape hatch for a client that has lost its account.
func (s Service) authorizeRevocation(ctx context.Context, req *request,
	cert appPKI.Certificate, der []byte) error {
	unauthorized := problemf(http.StatusForbidden, ProblemUnauthorized,
		"this request is not authorized to revoke that certificate")

	if req.account.ID != "" {
		ordered, err := s.repo.CertificateOrderedBy(ctx, req.account.ID, cert.ID)
		if err != nil {
			return err
		}
		if !ordered {
			return unauthorized
		}
		return nil
	}

	// The jwk form: the key that signed the request must be the key in the
	// certificate. Comparing the encoded SubjectPublicKeyInfo is the whole test
	// — same bytes, same key.
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return problemf(http.StatusBadRequest, ProblemMalformed, "the certificate could not be parsed")
	}
	signer, err := parseJWK([]byte(req.jwkJSON))
	if err != nil {
		return err
	}
	signerDER, err := x509.MarshalPKIXPublicKey(signer)
	if err != nil {
		return unauthorized
	}
	certDER, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
	if err != nil {
		return unauthorized
	}
	if string(signerDER) != string(certDER) {
		return unauthorized
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
