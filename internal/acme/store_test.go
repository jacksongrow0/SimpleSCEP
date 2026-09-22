package acme

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

const (
	testOrg      = "11111111-1111-1111-1111-111111111111"
	testEndpoint = "22222222-2222-2222-2222-222222222222"
	testCA       = "33333333-3333-3333-3333-333333333333"
	testURL      = "https://pki.example.test"
)

// fakeStore records what the service did as well as answering it, so tests can
// assert on the side effects that matter: that a rejected registration does not
// spend a single-use credential, that a rejected CSR never reaches the issuer,
// and that a nonce is spendable exactly once.
type fakeStore struct {
	mu sync.Mutex

	endpoints   map[string]Endpoint
	credentials map[string]EABCredential // keyed by id
	byKID       map[string]string        // kid -> credential id
	accounts    map[string]Account
	orders      map[string]Order
	authz       map[string][]Authorization
	challenges  map[string]Challenge
	nonces      map[string]bool

	// usedCredentialIDs is the assertion surface for single use: a rejected
	// binding must leave this empty.
	usedCredentialIDs []string
	consumedNonces    []string
	orderedCerts      map[string]string // certificateID -> accountID
}

var _ store = (*fakeStore)(nil)

func newFakeStore() *fakeStore {
	return &fakeStore{
		// SANPattern is set because an unset one now permits no identifiers at
		// all, and an ACME order is nothing but identifiers. Leaving it blank
		// would make every test in this package a test of the empty policy.
		// TestNewOrderRefusesEveryIdentifierWhenNoSANPatternIsSet covers that
		// state on purpose.
		endpoints: map[string]Endpoint{testEndpoint: {
			ID: testEndpoint, OrganizationID: testOrg, CAID: testCA, Name: "Test", Enabled: true,
			ValidityDays: DefaultValidityDays, AllowedEKUs: appPKI.EKUServerAuth,
			SubjectPattern: `.+`, SANPattern: `.+`,
		}},
		credentials:  map[string]EABCredential{},
		byKID:        map[string]string{},
		accounts:     map[string]Account{},
		orders:       map[string]Order{},
		authz:        map[string][]Authorization{},
		challenges:   map[string]Challenge{},
		nonces:       map[string]bool{},
		orderedCerts: map[string]string{},
	}
}

func (f *fakeStore) Endpoint(_ context.Context, id string) (Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.endpoints[id]
	if !ok {
		return Endpoint{}, sql.ErrNoRows
	}
	return e, nil
}

func (f *fakeStore) EndpointByID(_ context.Context, orgID, id string) (Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.endpoints[id]
	if !ok || e.OrganizationID != orgID {
		return Endpoint{}, sql.ErrNoRows
	}
	return e, nil
}

func (f *fakeStore) Endpoints(_ context.Context, orgID string) ([]Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Endpoint
	for _, e := range f.endpoints {
		if e.OrganizationID == orgID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeStore) InsertEndpoint(_ context.Context, e Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endpoints[e.ID] = e
	return nil
}

func (f *fakeStore) DeleteEndpoint(_ context.Context, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.endpoints, id)
	return nil
}

func (f *fakeStore) SetEnabled(_ context.Context, _, id string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.endpoints[id]
	e.Enabled = enabled
	f.endpoints[id] = e
	return nil
}

func (f *fakeStore) UpdatePolicy(_ context.Context, _, id string, p PolicyUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.endpoints[id]
	e.Name, e.ValidityDays = p.Name, p.ValidityDays
	e.SubjectPattern, e.SANPattern, e.AllowedEKUs = p.SubjectPattern, p.SANPattern, p.AllowedEKUs
	f.endpoints[id] = e
	return nil
}

func (f *fakeStore) LiveCertificateCount(context.Context, string) (int, error) { return 0, nil }

func (f *fakeStore) CreateCredential(_ context.Context, c EABCredential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.credentials[c.ID] = c
	f.byKID[c.KID] = c.ID
	return nil
}

func (f *fakeStore) CredentialByKID(_ context.Context, endpointID, kid string) (EABCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.byKID[kid]
	if !ok {
		return EABCredential{}, sql.ErrNoRows
	}
	c := f.credentials[id]
	if c.EndpointID != endpointID {
		return EABCredential{}, sql.ErrNoRows
	}
	return c, nil
}

func (f *fakeStore) Credentials(_ context.Context, endpointID string) ([]EABCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []EABCredential
	for _, c := range f.credentials {
		if c.EndpointID == endpointID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeStore) UseCredential(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.credentials[id]
	if !ok {
		return sql.ErrNoRows
	}
	if c.SingleUse && c.UsedAt != nil {
		return sql.ErrNoRows
	}
	now := time.Now()
	c.UsedAt = &now
	f.credentials[id] = c
	f.usedCredentialIDs = append(f.usedCredentialIDs, id)
	return nil
}

func (f *fakeStore) RevokeCredential(_ context.Context, _, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.credentials[id]
	if !ok {
		return sql.ErrNoRows
	}
	now := time.Now()
	c.RevokedAt = &now
	f.credentials[id] = c
	return nil
}

func (f *fakeStore) Account(_ context.Context, endpointID, id string) (Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[id]
	if !ok || a.EndpointID != endpointID {
		return Account{}, sql.ErrNoRows
	}
	return a, nil
}

func (f *fakeStore) AccountByThumbprint(_ context.Context, endpointID, thumbprint string) (Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.accounts {
		if a.EndpointID == endpointID && a.JWKThumbprint == thumbprint {
			return a, nil
		}
	}
	return Account{}, sql.ErrNoRows
}

func (f *fakeStore) CreateAccount(_ context.Context, a Account) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[a.ID] = a
	return nil
}

func (f *fakeStore) UpdateAccount(_ context.Context, _, id, contact, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[id]
	if !ok {
		return sql.ErrNoRows
	}
	a.Contact, a.Status = contact, status
	f.accounts[id] = a
	return nil
}

func (f *fakeStore) RekeyAccount(_ context.Context, _, id, thumbprint, jwkJSON string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[id]
	if !ok {
		return sql.ErrNoRows
	}
	a.JWKThumbprint, a.JWKJSON = thumbprint, jwkJSON
	f.accounts[id] = a
	return nil
}

func (f *fakeStore) Order(_ context.Context, endpointID, id string) (Order, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.orders[id]
	if !ok || o.EndpointID != endpointID {
		return Order{}, sql.ErrNoRows
	}
	return o, nil
}

func (f *fakeStore) OrderForUpdate(ctx context.Context, endpointID, id string) (Order, error) {
	return f.Order(ctx, endpointID, id)
}

func (f *fakeStore) CreateOrder(_ context.Context, o Order) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orders[o.ID] = o
	return nil
}

func (f *fakeStore) CompleteOrder(_ context.Context, id, certificateID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.orders[id]
	if !ok {
		return sql.ErrNoRows
	}
	o.Status, o.CertificateID = StatusValid, certificateID
	f.orders[id] = o
	f.orderedCerts[certificateID] = o.AccountID
	return nil
}

func (f *fakeStore) FailOrder(_ context.Context, id, problemType, detail string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.orders[id]
	if !ok {
		return sql.ErrNoRows
	}
	o.Status, o.ErrorType, o.ErrorDetail = StatusInvalid, problemType, detail
	f.orders[id] = o
	return nil
}

func (f *fakeStore) Orders(_ context.Context, endpointID string, _ int) ([]Order, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Order
	for _, o := range f.orders {
		if o.EndpointID == endpointID {
			out = append(out, o)
		}
	}
	return out, nil
}

func (f *fakeStore) CertificateOrderedBy(_ context.Context, accountID, certificateID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orderedCerts[certificateID] == accountID, nil
}

func (f *fakeStore) Authorization(_ context.Context, _, id string) (Authorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, list := range f.authz {
		for _, a := range list {
			if a.ID == id {
				return a, nil
			}
		}
	}
	return Authorization{}, sql.ErrNoRows
}

func (f *fakeStore) Authorizations(_ context.Context, orderID string) ([]Authorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authz[orderID], nil
}

func (f *fakeStore) CreateAuthorization(_ context.Context, a Authorization, c Challenge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authz[a.OrderID] = append(f.authz[a.OrderID], a)
	f.challenges[a.ID] = c
	return nil
}

func (f *fakeStore) Challenge(_ context.Context, _, id string) (Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.challenges {
		if c.ID == id {
			return c, nil
		}
	}
	return Challenge{}, sql.ErrNoRows
}

func (f *fakeStore) ChallengeFor(_ context.Context, authorizationID string) (Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.challenges[authorizationID]
	if !ok {
		return Challenge{}, sql.ErrNoRows
	}
	return c, nil
}

func (f *fakeStore) IssueNonce(_ context.Context, _, _ string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonces[string(value)] = true
	return nil
}

func (f *fakeStore) ConsumeNonce(_ context.Context, _ string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.nonces[string(value)] {
		return sql.ErrNoRows
	}
	delete(f.nonces, string(value))
	f.consumedNonces = append(f.consumedNonces, string(value))
	return nil
}

func (f *fakeStore) LockOrganization(context.Context, string) error { return nil }

// fakeIssuer counts issuances so a test can assert that a rejected request never
// reached the CA — which in production is a KMS signing operation that would
// have been billed and audited.
type fakeIssuer struct {
	mu       sync.Mutex
	issued   int
	revoked  []appPKI.RevokeRequest
	lastReq  appPKI.IssueRequest
	issueErr error
}

func (f *fakeIssuer) Issue(_ context.Context, req appPKI.IssueRequest) (appPKI.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReq = req
	if f.issueErr != nil {
		return appPKI.Certificate{}, f.issueErr
	}
	f.issued++
	return appPKI.Certificate{ID: "cert-1", OrganizationID: req.OrgID, CAID: req.CAID,
		Serial: "abc123", Status: appPKI.CertStatusIssued, CertificatePEM: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
		ChainPEM: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"}, nil
}

func (f *fakeIssuer) Revoke(_ context.Context, req appPKI.RevokeRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, req)
	return nil
}

// fakeCertificates is the PKI read side a revocation goes through.
type fakeCertificates struct {
	bySerial map[string]appPKI.Certificate
	byID     map[string]appPKI.Certificate
}

func (f fakeCertificates) CertificateBySerial(_ context.Context, _, _, serial string) (appPKI.Certificate, error) {
	c, ok := f.bySerial[strings.ToLower(serial)]
	if !ok {
		return appPKI.Certificate{}, sql.ErrNoRows
	}
	return c, nil
}

func (f fakeCertificates) Certificate(_ context.Context, _, id string) (appPKI.Certificate, error) {
	c, ok := f.byID[id]
	if !ok {
		return appPKI.Certificate{}, sql.ErrNoRows
	}
	return c, nil
}

// newTestService wires a service over the fakes with a real key provider, so
// the External Account Binding path exercises actual sealing rather than a stub
// that would hide a purpose-string mismatch.
func newTestService(repo *fakeStore) (Service, *fakeIssuer) {
	issuer := &fakeIssuer{}
	certs := fakeCertificates{bySerial: map[string]appPKI.Certificate{}, byID: map[string]appPKI.Certificate{}}
	return NewService(repo, issuer, certs, appPKI.NewFakeProvider(), testURL), issuer
}
