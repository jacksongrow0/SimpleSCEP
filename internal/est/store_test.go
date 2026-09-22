package est

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

const (
	testURL = "https://pki.example.test"
	testOrg = "org-1"
	testCA  = "33333333-3333-3333-3333-333333333333"
)

// fakeStore is an in-memory stand-in for Repository. Where a query carries a
// rule in its predicate, the rule is mirrored here rather than assumed away, so
// a unit test cannot pass on behaviour the database would not allow.
type fakeStore struct {
	mu          sync.Mutex
	endpoints   map[string]Endpoint
	credentials map[string]Credential
	enrollments []Enrollment
	// renewable is what RenewableCertificate returns, keyed
	// endpointID|credentialID|subject. The credential is part of the key because
	// the query requires the prior enrollment to belong to the credential now
	// presenting: matching on subject alone would let any credential on the
	// endpoint renew any subject the endpoint ever issued.
	renewable map[string]RenewableCert
	touched   []string
	insertErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		endpoints:   map[string]Endpoint{},
		credentials: map[string]Credential{},
		renewable:   map[string]RenewableCert{},
	}
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

func (f *fakeStore) EndpointByID(_ context.Context, orgID, id string) (Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.endpoints[id]
	if !ok || e.OrganizationID != orgID {
		return Endpoint{}, sql.ErrNoRows
	}
	return e, nil
}

func (f *fakeStore) InsertEndpoint(_ context.Context, e Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertErr != nil {
		return f.insertErr
	}
	// Mirrors est_endpoint_org_name_key, which is case-insensitive.
	for _, existing := range f.endpoints {
		if existing.OrganizationID == e.OrganizationID && strings.EqualFold(existing.Name, e.Name) {
			return sql.ErrNoRows
		}
	}
	f.endpoints[e.ID] = e
	return nil
}

func (f *fakeStore) DeleteEndpoint(_ context.Context, orgID, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.endpoints[id]; !ok || e.OrganizationID != orgID {
		return sql.ErrNoRows
	}
	delete(f.endpoints, id)
	return nil
}

func (f *fakeStore) SetEnabled(_ context.Context, orgID, id string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.endpoints[id]
	if !ok || e.OrganizationID != orgID {
		return sql.ErrNoRows
	}
	e.Enabled = enabled
	f.endpoints[id] = e
	return nil
}

func (f *fakeStore) UpdatePolicy(_ context.Context, orgID, id string, p PolicyUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.endpoints[id]
	if !ok || e.OrganizationID != orgID {
		return sql.ErrNoRows
	}
	e.Name, e.ValidityDays, e.RenewalWindowDays = p.Name, p.ValidityDays, p.RenewalWindowDays
	e.SubjectPattern, e.SANPattern, e.AllowedEKUs = p.SubjectPattern, p.SANPattern, p.AllowedEKUs
	f.endpoints[id] = e
	return nil
}

func (f *fakeStore) CreateCredential(_ context.Context, c Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Mirrors est_credential_endpoint_username_key, which is partial on
	// revoked_at: a revoked credential releases its username so the secret behind
	// that identity can be rotated.
	for _, existing := range f.credentials {
		if existing.EndpointID == c.EndpointID && strings.EqualFold(existing.Username, c.Username) &&
			existing.RevokedAt == nil {
			return sql.ErrNoRows
		}
	}
	f.credentials[c.ID] = c
	return nil
}

func (f *fakeStore) CredentialByUsername(_ context.Context, endpointID, username string) (Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Mirrors the query's revoked_at predicate, which is what makes the row
	// unique once revoked credentials may share a username.
	for _, c := range f.credentials {
		if c.EndpointID == endpointID && strings.EqualFold(c.Username, username) && c.RevokedAt == nil {
			return c, nil
		}
	}
	return Credential{}, sql.ErrNoRows
}

func (f *fakeStore) Credentials(_ context.Context, endpointID string) ([]Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Credential
	for _, c := range f.credentials {
		if c.EndpointID == endpointID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeStore) TouchCredential(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, id)
	return nil
}

func (f *fakeStore) RevokeCredential(_ context.Context, orgID, endpointID, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.credentials[id]
	if !ok || c.OrganizationID != orgID || c.EndpointID != endpointID || c.RevokedAt != nil {
		return sql.ErrNoRows
	}
	now := time.Now()
	c.RevokedAt = &now
	f.credentials[id] = c
	return nil
}

func (f *fakeStore) CreateEnrollment(_ context.Context, n Enrollment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrollments = append(f.enrollments, n)
	return nil
}

func (f *fakeStore) RenewableCertificate(_ context.Context, endpointID, credentialID, username, subject string) (RenewableCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rc, ok := f.renewable[endpointID+"|"+credentialID+"|"+subject]; ok {
		return rc, nil
	}
	// The second arm of the query's credential test: a replacement credential
	// with the same username inherits what the one it replaced enrolled, so
	// rotating a credential does not orphan a fleet's renewals.
	for key, rc := range f.renewable {
		endpoint, rest, _ := strings.Cut(key, "|")
		credID, subj, _ := strings.Cut(rest, "|")
		if endpoint != endpointID || subj != subject {
			continue
		}
		if prev, ok := f.credentials[credID]; ok && strings.EqualFold(prev.Username, username) {
			return rc, nil
		}
	}
	return RenewableCert{}, sql.ErrNoRows
}

// seedRenewable records that cred already enrolled subject on e, holding a
// certificate that expires at the given time.
func (f *fakeStore) seedRenewable(e Endpoint, cred Credential, subject string, expires time.Time, certPEM string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewable[e.ID+"|"+cred.ID+"|"+subject] = RenewableCert{ExpiresAt: expires, CertificatePEM: certPEM}
}

var _ store = (*fakeStore)(nil)

type fakeIssuer struct {
	mu       sync.Mutex
	issued   int
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
		Serial: "abc123", Status: appPKI.CertStatusIssued,
		CertificatePEM: testMaterial().leafPEM}, nil
}

var _ issuer = (*fakeIssuer)(nil)

// fakeCertificates is the PKI read side /cacerts and /csrattrs go through.
type fakeCertificates struct {
	ca  appPKI.CertificateAuthority
	err error
}

func (f fakeCertificates) CA(context.Context, string, string) (appPKI.CertificateAuthority, error) {
	if f.err != nil {
		return appPKI.CertificateAuthority{}, f.err
	}
	return f.ca, nil
}

var _ certificates = fakeCertificates{}

func newTestService(repo *fakeStore) (Service, *fakeIssuer) {
	issuer := &fakeIssuer{}
	certs := fakeCertificates{ca: appPKI.CertificateAuthority{ID: testCA,
		CertificatePEM: testMaterial().caPEM, ChainPEM: testMaterial().rootPEM}}
	return NewService(repo, issuer, certs, testURL), issuer
}

// endpointOf seeds one enabled endpoint with permissive defaults and returns it.
func (f *fakeStore) seedEndpoint() Endpoint {
	e := Endpoint{
		ID: testEndpointID, OrganizationID: testOrg, CAID: testCA, Name: "Gateways",
		Enabled: true, ValidityDays: DefaultValidityDays, RenewalWindowDays: DefaultRenewalWindowDays,
		AllowedEKUs: appPKI.EKUClientAuth,
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endpoints[e.ID] = e
	return e
}
