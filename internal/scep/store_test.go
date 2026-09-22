package scep

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

type pkiCertificate = appPKI.Certificate

// fakeStore is an in-memory store so authorization can be exercised without a
// database. Only the methods the tests reach are meaningfully implemented.
type fakeStore struct {
	endpoints map[string]Endpoint
	// endpointOrder keeps Endpoints deterministic, which the create tests rely
	// on when they assert on a replay collision or uniqueness constraint.
	endpointOrder []string
	methods       map[string]AuthMethod
	challenges    map[string]Challenge // keyed by hex lookup digest
	transactions  map[string]Transaction
	// issuedBy maps a certificate to the endpoint that issued it, so tests can
	// tell "this endpoint issued it" from "a sibling endpoint did".
	issuedBy   map[string]string
	createdRAs int
	usedIDs    []string
	// tenant is the organization's connected Entra directory; empty means none.
	tenant string
}

func newFakeStore() *fakeStore {
	return &fakeStore{endpoints: map[string]Endpoint{}, methods: map[string]AuthMethod{},
		challenges: map[string]Challenge{}, transactions: map[string]Transaction{}, issuedBy: map[string]string{}}
}

func (f *fakeStore) enable(method string, m AuthMethod) {
	m.Method, m.Enabled = method, true
	f.methods[method] = m
}

func (f *fakeStore) Endpoints(context.Context, string) ([]Endpoint, error) {
	out := make([]Endpoint, 0, len(f.endpoints))
	for _, id := range f.endpointOrder {
		out = append(out, f.endpoints[id])
	}
	return out, nil
}

func (f *fakeStore) EndpointByID(_ context.Context, _, id string) (Endpoint, error) {
	e, ok := f.endpoints[id]
	if !ok {
		return Endpoint{}, sql.ErrNoRows
	}
	return e, nil
}

func (f *fakeStore) EndpointCount(context.Context, string) (int, error) { return len(f.endpoints), nil }

func (f *fakeStore) InsertEndpoint(_ context.Context, e Endpoint) error {
	for _, existing := range f.endpoints {
		if strings.EqualFold(existing.Name, e.Name) {
			return fmt.Errorf("an endpoint called %q already exists; pick another name", e.Name)
		}
	}
	f.endpoints[e.ID] = e
	f.endpointOrder = append(f.endpointOrder, e.ID)
	f.createdRAs++
	return nil
}

func (f *fakeStore) DeleteEndpoint(_ context.Context, _, id string) error {
	if _, ok := f.endpoints[id]; !ok {
		return sql.ErrNoRows
	}
	delete(f.endpoints, id)
	f.endpointOrder = slices.DeleteFunc(f.endpointOrder, func(v string) bool { return v == id })
	return nil
}

func (f *fakeStore) LiveCertificateCount(_ context.Context, endpointID string) (int, error) {
	n := 0
	for _, issuer := range f.issuedBy {
		if issuer == endpointID {
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) SeedAuthMethods(_ context.Context, e Endpoint) error {
	for _, name := range Methods {
		if _, ok := f.methods[name]; !ok {
			f.methods[name] = AuthMethod{EndpointID: e.ID, Method: name}
		}
	}
	return nil
}

func (f *fakeStore) AuthMethods(context.Context, string) ([]AuthMethod, error) {
	out := make([]AuthMethod, 0, len(f.methods))
	for _, name := range Methods {
		if m, ok := f.methods[name]; ok {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeStore) AuthMethod(_ context.Context, _, method string) (AuthMethod, error) {
	m, ok := f.methods[method]
	if !ok {
		return AuthMethod{}, sql.ErrNoRows
	}
	return m, nil
}

func (f *fakeStore) SetMethodEnabled(_ context.Context, _, method string, enabled bool) error {
	m, ok := f.methods[method]
	if !ok {
		return sql.ErrNoRows
	}
	m.Enabled = enabled
	f.methods[method] = m
	return nil
}

func (f *fakeStore) UpsertStaticSecret(_ context.Context, _ Endpoint, hash string) error {
	m := f.methods[AuthStatic]
	m.Method, m.SecretHash = AuthStatic, hash
	now := time.Now().UTC()
	m.ConfiguredAt = &now
	f.methods[AuthStatic] = m
	return nil
}

func (f *fakeStore) IntuneConnection(_ context.Context, orgID string) (IntuneConnection, error) {
	if f.tenant == "" {
		return IntuneConnection{}, sql.ErrNoRows
	}
	return IntuneConnection{OrganizationID: orgID, TenantID: f.tenant, ConnectedAt: time.Now().UTC()}, nil
}

func (f *fakeStore) IntuneConnected(context.Context, string) (bool, error) {
	return f.tenant != "", nil
}

func (f *fakeStore) ConnectIntuneTenant(_ context.Context, _, tenantID string) error {
	f.tenant = tenantID
	m := f.methods[AuthIntune]
	m.Method, m.IntuneConnected = AuthIntune, true
	now := time.Now().UTC()
	m.ConfiguredAt = &now
	f.methods[AuthIntune] = m
	return nil
}

func (f *fakeStore) DisconnectIntuneTenant(context.Context, string) error {
	f.tenant = ""
	f.methods[AuthIntune] = AuthMethod{Method: AuthIntune}
	return nil
}

func (f *fakeStore) UpsertJamf(_ context.Context, _ Endpoint, username, passwordHash string) error {
	m := f.methods[AuthJamf]
	m.Method, m.Username, m.PasswordHash = AuthJamf, username, passwordHash
	now := time.Now().UTC()
	m.ConfiguredAt = &now
	f.methods[AuthJamf] = m
	return nil
}

func (f *fakeStore) CreateChallenge(_ context.Context, c Challenge, lookup []byte) error {
	f.challenges[hex.EncodeToString(lookup)] = c
	return nil
}

func (f *fakeStore) ChallengeForUpdate(_ context.Context, _ string, lookup []byte) (Challenge, error) {
	c, ok := f.challenges[hex.EncodeToString(lookup)]
	if !ok {
		return Challenge{}, sql.ErrNoRows
	}
	return c, nil
}

func (f *fakeStore) UseChallenge(_ context.Context, id string) error {
	f.usedIDs = append(f.usedIDs, id)
	return nil
}

func (f *fakeStore) Transaction(_ context.Context, _, transactionID string) (Transaction, error) {
	t, ok := f.transactions[transactionID]
	if !ok {
		return Transaction{}, sql.ErrNoRows
	}
	return t, nil
}

func (f *fakeStore) CreateTransaction(_ context.Context, _ string, t Transaction) error {
	f.transactions[t.TransactionID] = t
	return nil
}

func (f *fakeStore) CertificateIssuedByEndpoint(_ context.Context, endpointID, certificateID string) (bool, error) {
	return f.issuedBy[certificateID] == endpointID, nil
}

func (f *fakeStore) CertificateIssuedByEndpoints(_ context.Context, endpointIDs []string, certificateID string) (bool, error) {
	return slices.Contains(endpointIDs, f.issuedBy[certificateID]), nil
}

func (f *fakeStore) LockOrganization(context.Context, string) error { return nil }

var _ store = (*fakeStore)(nil)

// fakeIssuer stands in for the PKI service so endpoint creation can be
// exercised without a KMS. The certificate is not parsed by anything the
// creation path touches.
type fakeIssuer struct{ issued int }

func (f *fakeIssuer) Issue(context.Context, appPKI.IssueRequest) (appPKI.Certificate, error) {
	f.issued++
	return appPKI.Certificate{ID: "cert-" + strconv.Itoa(f.issued), CertificatePEM: "-----BEGIN CERTIFICATE-----\n"}, nil
}

var _ issuer = (*fakeIssuer)(nil)

// stubIntune records what Intune was asked to validate and returns err.
type stubIntune struct {
	calls      int
	err        error
	failures   []string
	tenantErrs []error // consumed one per CheckTenant call, then nil
	checks     int
}

func (s *stubIntune) Validate(context.Context, Integration, string, []byte) error {
	s.calls++
	return s.err
}

func (s *stubIntune) NotifySuccess(context.Context, Integration, string, []byte, pkiCertificate) error {
	return nil
}

func (s *stubIntune) NotifyFailure(_ context.Context, _ Integration, _ string, _ []byte, reason string) error {
	s.failures = append(s.failures, reason)
	return nil
}

func (s *stubIntune) CheckTenant(context.Context, Integration) error {
	s.checks++
	if s.checks <= len(s.tenantErrs) {
		return s.tenantErrs[s.checks-1]
	}
	return nil
}
