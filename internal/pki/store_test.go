package pki

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

// memStore is an in-memory Store used by service tests.
type memStore struct {
	mu       sync.Mutex
	nextID   int
	cas      map[string]CertificateAuthority
	certs    map[string]Certificate
	jobs     map[string]CAImportJob
	signings []signingRecord // recorded audit rows, in order
	events   []signingRecord // RecordCAEvent rows, in order
	// revocations records RevokeCertificate calls, in order.
	revocations  []revocationRecord
	publications map[string]CRLPublication
	ocspCache    map[string]OCSPCacheEntry
}

type signingRecord struct {
	CAID, UserID, KeyVersion, Purpose string
}

type revocationRecord struct {
	CertID, Reason string
}

func newMemStore() *memStore {
	return &memStore{
		cas:          map[string]CertificateAuthority{},
		certs:        map[string]Certificate{},
		jobs:         map[string]CAImportJob{},
		publications: map[string]CRLPublication{},
		ocspCache:    map[string]OCSPCacheEntry{},
	}
}

func (m *memStore) id() string {
	m.nextID++
	return fmt.Sprintf("id-%d", m.nextID)
}

func (m *memStore) CreateCA(_ context.Context, ca CertificateAuthority) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ca.ID = m.id()
	ca.CreatedAt = time.Now().UTC()
	m.cas[ca.ID] = ca
	return ca.ID, nil
}

func (m *memStore) CA(_ context.Context, orgID, id string) (CertificateAuthority, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ca, ok := m.cas[id]
	if !ok || ca.OrganizationID != orgID || ca.Status == CAStatusDeleted {
		return CertificateAuthority{}, sql.ErrNoRows
	}
	return ca, nil
}

func (m *memStore) CAs(_ context.Context, orgID string) ([]CertificateAuthority, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var cas []CertificateAuthority
	for _, ca := range m.cas {
		if ca.OrganizationID == orgID && ca.Status != CAStatusDeleted {
			cas = append(cas, ca)
		}
	}
	return cas, nil
}

func (m *memStore) UpdateCAStatus(_ context.Context, orgID, id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ca, ok := m.cas[id]
	if !ok || ca.OrganizationID != orgID || ca.Status == CAStatusDeleted {
		return sql.ErrNoRows
	}
	ca.Status = status
	m.cas[id] = ca
	return nil
}

func (m *memStore) IssuingCACount(_ context.Context, orgID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, ca := range m.cas {
		if ca.OrganizationID == orgID && ca.Type == CATypeIssuing && (ca.Status == CAStatusActive || ca.Status == CAStatusInactive) {
			n++
		}
	}
	return n, nil
}

func (m *memStore) EnabledSCEPEndpointCount(context.Context, string, string) (int, error) {
	return 0, nil
}

func (m *memStore) EnabledACMEEndpointCount(context.Context, string, string) (int, error) {
	return 0, nil
}

func (m *memStore) EnabledESTEndpointCount(context.Context, string, string) (int, error) {
	return 0, nil
}

func (m *memStore) RootCA(_ context.Context, orgID string) (CertificateAuthority, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ca := range m.cas {
		if ca.OrganizationID == orgID && ca.Type == CATypeRoot && ca.Status != CAStatusDeleted {
			return ca, nil
		}
	}
	return CertificateAuthority{}, sql.ErrNoRows
}

func (m *memStore) MarkCADeleted(_ context.Context, orgID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ca, ok := m.cas[id]
	if !ok || ca.OrganizationID != orgID || ca.Status == CAStatusDeleted {
		return sql.ErrNoRows
	}
	ca.Status = CAStatusDeleted
	m.cas[id] = ca
	return nil
}

func (m *memStore) ActiveChildCount(_ context.Context, orgID, id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, ca := range m.cas {
		if ca.OrganizationID == orgID && ca.ParentID == id && ca.Status != CAStatusDeleted {
			n++
		}
	}
	return n, nil
}

func (m *memStore) RecordCertificate(_ context.Context, cert Certificate) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert.ID = m.id()
	m.certs[cert.ID] = cert
	return cert.ID, nil
}

func (m *memStore) Certificate(_ context.Context, orgID, id string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert, ok := m.certs[id]
	if !ok || cert.OrganizationID != orgID {
		return Certificate{}, sql.ErrNoRows
	}
	return cert, nil
}

func (m *memStore) Certificates(_ context.Context, orgID string) ([]Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var certs []Certificate
	for _, cert := range m.certs {
		if cert.OrganizationID == orgID {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func (m *memStore) CertificateBySerial(_ context.Context, orgID, caID, serial string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cert := range m.certs {
		if cert.OrganizationID == orgID && cert.CAID == caID && strings.EqualFold(cert.Serial, serial) {
			return cert, nil
		}
	}
	return Certificate{}, sql.ErrNoRows
}

func (m *memStore) Revocations(_ context.Context, orgID string) ([]Revocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Revocation
	for _, record := range m.revocations {
		cert := m.certs[record.CertID]
		if cert.OrganizationID == orgID {
			out = append(out, Revocation{Certificate: cert, Reason: record.Reason})
		}
	}
	return out, nil
}

func (m *memStore) CRLPublication(_ context.Context, orgID, caID string) (CRLPublication, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.publications[caID]
	if !ok || p.OrganizationID != orgID {
		return CRLPublication{}, sql.ErrNoRows
	}
	return p, nil
}

func (m *memStore) LockCRL(context.Context, string) error { return nil }
func (m *memStore) SaveCRL(_ context.Context, p CRLPublication) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publications[p.CAID] = p
	return nil
}
func (m *memStore) SaveCRLError(_ context.Context, orgID, caID, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.publications[caID]
	p.OrganizationID, p.CAID, p.LastError = orgID, caID, message
	// The real statement stamps last_attempt_at in the same UPSERT, and
	// EnsureFreshCRL's retry cooldown reads it. A fake that left it nil would make
	// the cooldown untestable and, worse, would pass a test the real repository
	// fails.
	now := time.Now().UTC()
	p.LastAttemptAt = &now
	m.publications[caID] = p
	return nil
}
func (m *memStore) CachedOCSP(_ context.Context, orgID, caID, serial string, hash int, status string, now time.Time) (OCSPCacheEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.ocspCache[fmt.Sprintf("%s/%s/%s/%d", orgID, caID, serial, hash)]
	if !ok || e.Status != status || !e.NextUpdate.After(now) {
		return OCSPCacheEntry{}, sql.ErrNoRows
	}
	return e, nil
}
func (m *memStore) SaveOCSP(_ context.Context, orgID, caID, serial string, hash int, e OCSPCacheEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ocspCache[fmt.Sprintf("%s/%s/%s/%d", orgID, caID, serial, hash)] = e
	return nil
}

func (m *memStore) RevokeCertificate(_ context.Context, orgID, id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert, ok := m.certs[id]
	if !ok || cert.OrganizationID != orgID || cert.Status != CertStatusIssued {
		return sql.ErrNoRows
	}
	now := time.Now().UTC()
	cert.Status = CertStatusRevoked
	cert.RevokedAt = &now
	m.certs[id] = cert
	m.revocations = append(m.revocations, revocationRecord{CertID: id, Reason: reason})
	return nil
}

// live mirrors the liveCertificates predicate the repository counts over.
func (m *memStore) live(cert Certificate, orgID string) bool {
	return cert.OrganizationID == orgID && cert.Status == CertStatusIssued &&
		cert.ExpiresAt.After(time.Now().UTC()) && cert.Profile != CertProfileInfrastructure
}

// identity mirrors identityExpr: the subject, or the row when there is none.
func (m *memStore) identity(cert Certificate) string {
	if cert.Subject != "" {
		return cert.Subject
	}
	return cert.ID
}

func (m *memStore) ActiveIdentityCount(_ context.Context, orgID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	for _, cert := range m.certs {
		if m.live(cert, orgID) {
			seen[m.identity(cert)] = true
		}
	}
	return len(seen), nil
}

func (m *memStore) RecordSigning(_ context.Context, _, caID, userID, keyVersion, _, _, purpose string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signings = append(m.signings, signingRecord{CAID: caID, UserID: userID, KeyVersion: keyVersion, Purpose: purpose})
	return nil
}

func (m *memStore) RecordCAEvent(_ context.Context, _, caID, userID, keyVersion, purpose string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, signingRecord{CAID: caID, UserID: userID, KeyVersion: keyVersion, Purpose: purpose})
	return nil
}

func (m *memStore) CreateCAImportJob(_ context.Context, job CAImportJob) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job.ID = m.id()
	job.CreatedAt = time.Now().UTC()
	m.jobs[job.ID] = job
	return job.ID, nil
}

func (m *memStore) CAImportJob(_ context.Context, orgID, id string) (CAImportJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok || job.OrganizationID != orgID {
		return CAImportJob{}, sql.ErrNoRows
	}
	return job, nil
}

func (m *memStore) CAImportJobs(_ context.Context, orgID string) ([]CAImportJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var jobs []CAImportJob
	for _, job := range m.jobs {
		if job.OrganizationID == orgID {
			jobs = append(jobs, job)
		}
	}
	return jobs, nil
}

func (m *memStore) UpdateCAImportJobState(_ context.Context, orgID, id, state, failureReason string) error {
	return m.updateJob(orgID, id, func(job *CAImportJob) {
		job.State = state
		job.FailureReason = failureReason
	})
}

func (m *memStore) SetCAImportJobWrapping(_ context.Context, orgID, id, state, wrappingPEM, method string, expiresAt time.Time) error {
	return m.updateJob(orgID, id, func(job *CAImportJob) {
		job.State = state
		job.WrappingPublicKeyPEM = wrappingPEM
		job.WrappingMethod = method
		job.ExpiresAt = &expiresAt
	})
}

func (m *memStore) SetCAImportJobKeyVersion(_ context.Context, orgID, id, keyVersion string) error {
	return m.updateJob(orgID, id, func(job *CAImportJob) {
		job.KMSKeyVersion = keyVersion
		job.State = ImportStateImporting
	})
}

func (m *memStore) CompleteCAImportJob(_ context.Context, orgID, id, caID string) error {
	return m.updateJob(orgID, id, func(job *CAImportJob) {
		job.State = ImportStateCompleted
		job.CertificateAuthorityID = caID
	})
}

func (m *memStore) CancelCAImportJob(_ context.Context, orgID, id, _ string) error {
	return m.updateJob(orgID, id, func(job *CAImportJob) {
		job.State = ImportStateCancelled
		job.FailureReason = ""
	})
}

func (m *memStore) updateJob(orgID, id string, fn func(*CAImportJob)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok || job.OrganizationID != orgID {
		return sql.ErrNoRows
	}
	fn(&job)
	m.jobs[id] = job
	return nil
}
