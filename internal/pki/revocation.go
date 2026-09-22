package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

const revocationValidity = 24 * time.Hour

var reasonCodes = map[string]int{
	"unspecified": 0, "key_compromise": 1, "affiliation_changed": 3,
	"superseded": 4, "cessation_of_operation": 5,
}

func (s Service) PublicEndpoint(orgID, caID, resource string) string {
	return fmt.Sprintf("%s/pki/%s/%s/%s", s.publicURL, orgID, caID, resource)
}

func (s Service) PublishCRL(ctx context.Context, orgID, caID string) error {
	if err := s.repo.LockCRL(ctx, caID); err != nil {
		return err
	}
	ca, err := s.repo.CA(ctx, orgID, caID)
	if err != nil {
		return err
	}
	if ca.Type != CATypeIssuing {
		return fmt.Errorf("CRLs are available only for issuing CAs")
	}
	issuer, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return s.crlError(ctx, orgID, caID, err)
	}
	key, err := s.provider.KeyInfo(ctx, ca.KMSKeyVersion)
	if err != nil {
		return s.crlError(ctx, orgID, caID, err)
	}
	revocations, err := s.repo.Revocations(ctx, orgID)
	if err != nil {
		return s.crlError(ctx, orgID, caID, err)
	}
	entries := make([]x509.RevocationListEntry, 0, len(revocations))
	for _, rev := range revocations {
		if rev.CAID != caID || rev.RevokedAt == nil {
			continue
		}
		serial, ok := new(big.Int).SetString(rev.Serial, 16)
		if !ok {
			return s.crlError(ctx, orgID, caID, fmt.Errorf("invalid serial %q", rev.Serial))
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: *rev.RevokedAt, ReasonCode: reasonCodes[rev.Reason]})
	}
	number := int64(1)
	if current, err := s.repo.CRLPublication(ctx, orgID, caID); err == nil {
		number = current.Number + 1
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := time.Now().UTC().Truncate(time.Minute)
	next := now.Add(revocationValidity)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: now, NextUpdate: next, RevokedCertificateEntries: entries,
	}, issuer, NewKMSSigner(ctx, s.provider, key))
	if err != nil {
		return s.crlError(ctx, orgID, caID, err)
	}
	return s.repo.SaveCRL(ctx, CRLPublication{OrganizationID: orgID, CAID: caID, DER: der, Number: number, ThisUpdate: &now, NextUpdate: &next})
}

func (s Service) crlError(ctx context.Context, orgID, caID string, err error) error {
	_ = s.repo.SaveCRLError(ctx, orgID, caID, err.Error())
	return err
}

// crlRetryCooldown is how long a failed publication is allowed to stand before
// a request may attempt another.
//
// Without it, LastError != "" fell straight through to PublishCRL, so a CA whose
// last publication failed signed a new CRL on *every* request — and the
// distribution point is printed into every certificate this service issues, so
// the URL is public by construction and the callers are a device fleet with
// retry logic. One transient KMS failure therefore turned into a KMS signing
// operation per request: billed, rate-limited against other workloads sharing
// the key provider, and each one holding LockCRL long enough to stall the worker
// that would have fixed it.
//
// Five minutes is short enough that a transient failure clears on the next
// request rather than waiting for the hourly worker, and long enough that a
// persistent one costs twelve attempts an hour instead of thousands.
const crlRetryCooldown = 5 * time.Minute

func (s Service) EnsureFreshCRL(ctx context.Context, orgID, caID string) (CRLPublication, error) {
	p, err := s.repo.CRLPublication(ctx, orgID, caID)
	now := time.Now().UTC()
	if err == nil && p.LastError == "" && len(p.DER) > 0 && p.NextUpdate != nil && p.NextUpdate.After(now.Add(time.Hour)) {
		return p, nil
	}
	if err == nil && p.LastError != "" && p.LastAttemptAt != nil && now.Sub(*p.LastAttemptAt) < crlRetryCooldown {
		// A CRL that is stale but still inside its own nextUpdate is what every
		// relying party is already caching, so serving it is strictly better than
		// answering 503 — it is the same bytes they would use anyway, and it keeps
		// revocation checking working while the underlying failure is dealt with.
		if len(p.DER) > 0 && p.NextUpdate != nil && p.NextUpdate.After(now) {
			return p, nil
		}
		return CRLPublication{}, fmt.Errorf("CRL publication for CA %s failed and is in cooldown: %s", caID, p.LastError)
	}
	if err := s.PublishCRL(ctx, orgID, caID); err != nil {
		return CRLPublication{}, err
	}
	return s.repo.CRLPublication(ctx, orgID, caID)
}

func (s Service) OCSPResponse(ctx context.Context, orgID, caID string, req *ocsp.Request) ([]byte, time.Time, error) {
	ca, err := s.repo.CA(ctx, orgID, caID)
	if err != nil || ca.Type != CATypeIssuing {
		return nil, time.Time{}, sql.ErrNoRows
	}
	issuer, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return nil, time.Time{}, err
	}
	dummy := &x509.Certificate{SerialNumber: req.SerialNumber}
	wantDER, err := ocsp.CreateRequest(dummy, issuer, &ocsp.RequestOptions{Hash: req.HashAlgorithm})
	if err != nil {
		return nil, time.Time{}, sql.ErrNoRows
	}
	want, err := ocsp.ParseRequest(wantDER)
	if err != nil || !equalBytes(want.IssuerNameHash, req.IssuerNameHash) || !equalBytes(want.IssuerKeyHash, req.IssuerKeyHash) {
		return nil, time.Time{}, sql.ErrNoRows
	}
	serial := req.SerialNumber.Text(16)
	cert, err := s.repo.CertificateBySerial(ctx, orgID, caID, serial)
	if err != nil {
		return nil, time.Time{}, sql.ErrNoRows
	}
	now := time.Now().UTC().Truncate(time.Minute)
	if cached, err := s.repo.CachedOCSP(ctx, orgID, caID, serial, int(req.HashAlgorithm), cert.Status, now.Add(time.Hour)); err == nil {
		return cached.DER, cached.NextUpdate, nil
	}
	key, err := s.provider.KeyInfo(ctx, ca.KMSKeyVersion)
	if err != nil {
		return nil, time.Time{}, err
	}
	template := ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber, ThisUpdate: now, NextUpdate: now.Add(revocationValidity), IssuerHash: req.HashAlgorithm}
	if cert.Status == CertStatusRevoked {
		template.Status = ocsp.Revoked
		if cert.RevokedAt != nil {
			template.RevokedAt = *cert.RevokedAt
		}
		revs, err := s.repo.Revocations(ctx, orgID)
		if err != nil {
			return nil, time.Time{}, err
		}
		for _, rev := range revs {
			if rev.ID == cert.ID {
				template.RevocationReason = reasonCodes[rev.Reason]
				break
			}
		}
	}
	// Signed by the CA itself — RFC 6960 §2.6's direct responder — rather than by
	// a delegated responder certificate. RFC 5280 defines no keyUsage bit for
	// OCSP signing, and OpenSSL, Windows CryptoAPI and NSS all accept a
	// directly-signed response from a certSign|cRLSign CA, so the absent
	// digitalSignature bit is not the problem it looks like.
	//
	// A delegated responder would need a leaf carrying id-kp-OCSPSigning, which
	// is exactly the escalation eku.go refuses to expose: anything holding such a
	// certificate can assert "good" for every certificate this CA has issued,
	// including revoked ones. Not worth introducing to satisfy a stricter reading
	// no client here has been observed to hold.
	der, err := ocsp.CreateResponse(issuer, issuer, template, NewKMSSigner(ctx, s.provider, key))
	if err != nil {
		return nil, time.Time{}, err
	}
	entry := OCSPCacheEntry{DER: der, Status: cert.Status, ThisUpdate: now, NextUpdate: template.NextUpdate}
	if err := s.repo.SaveOCSP(ctx, orgID, caID, serial, int(req.HashAlgorithm), entry); err != nil {
		return nil, time.Time{}, err
	}
	return der, template.NextUpdate, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
