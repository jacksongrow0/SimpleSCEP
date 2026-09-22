package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"golang.org/x/crypto/ocsp"
)

func TestRevocationDiscoveryCRLAndOCSP(t *testing.T) {
	store := newMemStore()
	svc := NewServiceWithURL(store, NewFakeProvider(), "https://pki.example.test/")
	root := createRoot(t, svc, 0)
	issuing := createIssuingWithEKUs(t, svc, root.ID, "Online Issuing", []string{EKUClientAuth})
	cert, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, UserID: "user-1", CAID: issuing.ID, CSRPEM: testCSR(t)})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCert(t, cert.CertificatePEM)
	base := "https://pki.example.test/pki/" + testOrg + "/" + issuing.ID + "/"
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != base+"crl" {
		t.Errorf("CRL URLs = %v", leaf.CRLDistributionPoints)
	}
	if len(leaf.OCSPServer) != 1 || leaf.OCSPServer[0] != base+"ocsp" {
		t.Errorf("OCSP URLs = %v", leaf.OCSPServer)
	}
	if len(leaf.IssuingCertificateURL) != 1 || leaf.IssuingCertificateURL[0] != base+"issuer" {
		t.Errorf("issuer URLs = %v", leaf.IssuingCertificateURL)
	}

	initial, err := store.CRLPublication(context.Background(), testOrg, issuing.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(initial.DER)
	if err != nil {
		t.Fatal(err)
	}
	issuer := mustParseCert(t, issuing.CertificatePEM)
	if err := parsed.CheckSignatureFrom(issuer); err != nil {
		t.Fatal(err)
	}
	if len(parsed.RevokedCertificateEntries) != 0 || parsed.Number.Int64() != 1 {
		t.Fatalf("initial CRL entries=%d number=%v", len(parsed.RevokedCertificateEntries), parsed.Number)
	}
	requestDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	request, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		t.Fatal(err)
	}
	responseDER, _, err := svc.OCSPResponse(context.Background(), testOrg, issuing.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ocsp.ParseResponseForCert(responseDER, leaf, issuer)
	if err != nil || response.Status != ocsp.Good {
		t.Fatalf("initial OCSP response=%+v err=%v", response, err)
	}

	if err := svc.Revoke(context.Background(), RevokeRequest{OrgID: testOrg, UserID: "user-1", CertificateID: cert.ID, Reason: "key_compromise"}); err != nil {
		t.Fatal(err)
	}
	published, err := store.CRLPublication(context.Background(), testOrg, issuing.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = x509.ParseRevocationList(published.DER)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Number.Int64() != 2 || len(parsed.RevokedCertificateEntries) != 1 || parsed.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Fatalf("published CRL number=%v entries=%+v", parsed.Number, parsed.RevokedCertificateEntries)
	}

	responseDER, _, err = svc.OCSPResponse(context.Background(), testOrg, issuing.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	response, err = ocsp.ParseResponseForCert(responseDER, leaf, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != ocsp.Revoked || response.RevocationReason != 1 {
		t.Errorf("OCSP status=%d reason=%d", response.Status, response.RevocationReason)
	}

	request.SerialNumber.SetInt64(999)
	if _, _, err := svc.OCSPResponse(context.Background(), testOrg, issuing.ID, request); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown serial error=%v", err)
	}
}

func TestRevocationPageData(t *testing.T) {
	now := time.Now().UTC()
	service, _ := newTestService()
	data := revocationPageData(service, auth.Session{OrgID: testOrg}, []CertificateAuthority{{ID: "ca-1", Name: "Issuer", Type: CATypeIssuing}}, []Revocation{{
		Certificate: Certificate{ID: "cert-1", CAID: "ca-1", CAName: "Issuer", Subject: "CN=device.example", Serial: "abc", RevokedAt: &now}, Reason: "superseded",
	}}, func(string) (CRLPublication, error) {
		next := now.Add(time.Hour)
		return CRLPublication{PublishedAt: &now, NextUpdate: &next}, nil
	})
	if data.RevokedCount != "1" || data.AffectedCAs != "1" || len(data.Rows) != 1 || data.Rows[0].CN != "device.example" || data.Rows[0].Reason != "superseded" {
		t.Fatalf("dashboard data = %+v", data)
	}
}

// TestEnsureFreshCRLDoesNotResignWhileInCooldown is the KMS cost bug.
//
// The freshness test requires LastError to be empty, so a CA whose last
// publication failed fell through to PublishCRL on every request — and the
// distribution point URL is inside every certificate this CA has issued, so the
// callers are a retrying device fleet. Each attempt is a billed KMS signature
// against a key ring shared with every other tenant.
func TestEnsureFreshCRLDoesNotResignWhileInCooldown(t *testing.T) {
	store := newMemStore()
	service := NewService(store, NewFakeProvider())

	const orgID, caID = "org-1", "ca-1"
	now := time.Now().UTC()
	stale := now.Add(30 * time.Minute) // inside its own nextUpdate, outside the 1h freshness margin
	attempt := now.Add(-time.Minute)
	if err := store.SaveCRL(context.Background(), CRLPublication{
		OrganizationID: orgID, CAID: caID, DER: []byte("previous crl"), Number: 7,
		ThisUpdate: &now, NextUpdate: &stale, LastAttemptAt: &attempt, LastError: "kms unavailable",
	}); err != nil {
		t.Fatal(err)
	}

	// No CA row exists, so any attempt to publish fails outright. Getting the
	// stale bytes back is therefore proof that nothing was signed.
	p, err := service.EnsureFreshCRL(context.Background(), orgID, caID)
	if err != nil {
		t.Fatalf("a still-valid stale CRL was not served during cooldown: %v", err)
	}
	if string(p.DER) != "previous crl" {
		t.Errorf("served %q, want the previously published CRL", p.DER)
	}
}

// TestEnsureFreshCRLRetriesAfterTheCooldown pins the other half: the cooldown
// must expire, or one transient failure would wedge the CRL until the hourly
// worker happened to fix it.
func TestEnsureFreshCRLRetriesAfterTheCooldown(t *testing.T) {
	store := newMemStore()
	service := NewService(store, NewFakeProvider())

	const orgID, caID = "org-1", "ca-1"
	now := time.Now().UTC()
	stale := now.Add(30 * time.Minute)
	attempt := now.Add(-2 * crlRetryCooldown)
	if err := store.SaveCRL(context.Background(), CRLPublication{
		OrganizationID: orgID, CAID: caID, DER: []byte("previous crl"), Number: 7,
		ThisUpdate: &now, NextUpdate: &stale, LastAttemptAt: &attempt, LastError: "kms unavailable",
	}); err != nil {
		t.Fatal(err)
	}

	// Still no CA row, so the retry fails — which is what proves it was attempted.
	if _, err := service.EnsureFreshCRL(context.Background(), orgID, caID); err == nil {
		t.Error("the cooldown never expired: a stale CRL was served instead of a retry being attempted")
	}
}

// TestEnsureFreshCRLRefusesWhenTheStaleCRLHasAlsoExpired covers the case where
// there is nothing safe to serve. A CRL past its own nextUpdate is one a relying
// party will reject anyway, so handing it out would only move the failure.
func TestEnsureFreshCRLRefusesWhenTheStaleCRLHasAlsoExpired(t *testing.T) {
	store := newMemStore()
	service := NewService(store, NewFakeProvider())

	const orgID, caID = "org-1", "ca-1"
	now := time.Now().UTC()
	expired := now.Add(-time.Hour)
	attempt := now.Add(-time.Minute)
	if err := store.SaveCRL(context.Background(), CRLPublication{
		OrganizationID: orgID, CAID: caID, DER: []byte("previous crl"), Number: 7,
		ThisUpdate: &expired, NextUpdate: &expired, LastAttemptAt: &attempt, LastError: "kms unavailable",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnsureFreshCRL(context.Background(), orgID, caID); err == nil {
		t.Error("a CRL past its own nextUpdate was served")
	}
}
