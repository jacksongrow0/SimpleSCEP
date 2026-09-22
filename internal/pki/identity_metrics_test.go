package pki

import (
	"context"
	"testing"
)

// A SCEP endpoint's registration authority certificate is SimpleSCEP's own.
// The endpoint operator did not request it and it must not count toward the
// operator-facing identity metrics.
func TestInfrastructureCertificatesAreNotActiveIdentities(t *testing.T) {
	svc, store := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := createIssuing(t, svc, root.ID, "Issuer")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := svc.Issue(ctx, IssueRequest{OrgID: testOrg, CAID: issuing.ID, CSRPEM: testCSR(t),
			Purpose: "scep_ra", Profile: CertProfileInfrastructure}); err != nil {
			t.Fatal(err)
		}
	}
	count, err := store.ActiveIdentityCount(ctx, testOrg)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("active identity count = %d, want 0: infrastructure certificates are internal", count)
	}
}

// A subject-less certificate has nothing stable to be recognized by, so each
// one counts separately rather than silently collapsing into a single
// identity. The default SCEP subject policy rejects these outright; this pins
// the behaviour for the CSR flow, where an administrator can still submit one.
func TestSubjectlessCertificatesCountIndividually(t *testing.T) {
	svc, store := newTestService()
	ctx := context.Background()
	root := createRoot(t, svc, 0)
	issuing, err := createIssuing(t, svc, root.ID, "Issuer")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := svc.Issue(ctx, IssueRequest{OrgID: testOrg, CAID: issuing.ID, CSRPEM: testCSR(t)}); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := store.ActiveIdentityCount(ctx, testOrg); n != 2 {
		t.Errorf("identity count = %d, want 2: a subject-less certificate cannot be recognized again", n)
	}
}

// A certificate issued without an explicit profile is CSR-based, which is what
// every SCEP enrollment and hand-submitted CSR has always been recorded as.
func TestIssueDefaultsToTheCSRProfile(t *testing.T) {
	svc, store := newTestService()
	root := createRoot(t, svc, 0)
	issuing, err := createIssuing(t, svc, root.ID, "Issuer")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := svc.Issue(context.Background(), IssueRequest{OrgID: testOrg, CAID: issuing.ID, CSRPEM: testCSR(t)})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Profile != CertProfileCSR {
		t.Errorf("profile = %q, want %q", cert.Profile, CertProfileCSR)
	}
	if n, _ := store.ActiveIdentityCount(context.Background(), testOrg); n != 1 {
		t.Errorf("active certificate count = %d, want 1", n)
	}
}
