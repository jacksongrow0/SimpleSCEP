package scep

import (
	"context"
	"errors"
	"testing"
)

// The revocation queue is filtered by issuer name, so every endpoint on one
// issuing CA sees the same requests. A "certificate not found" verdict is
// acknowledged to Microsoft and never retried, so reporting it for a
// certificate a sibling endpoint issued means that certificate is never
// revoked. This is the whole reason the worker aggregates by CA.
func TestRevocationMatchesAnyEndpointOnTheCA(t *testing.T) {
	const endpointA, endpointB, certID = "endpoint-a", "endpoint-b", "cert-1"
	f := newFakeStore()
	f.issuedBy[certID] = endpointB
	ctx := context.Background()

	group := []string{endpointA, endpointB}
	issued, err := f.CertificateIssuedByEndpoints(ctx, group, certID)
	if err != nil {
		t.Fatal(err)
	}
	if !issued {
		t.Fatal("a certificate issued by a sibling endpoint on the same CA must be recognized")
	}
	// The single-endpoint question stays available for the renewal path, where
	// the endpoint that issued the certificate is exactly what must match.
	if only, _ := f.CertificateIssuedByEndpoint(ctx, endpointA, certID); only {
		t.Fatal("the per-endpoint check must not match a sibling's certificate")
	}

	// A serial from a different CA's queue still has no endpoint here.
	if issued, _ := f.CertificateIssuedByEndpoints(ctx, group, "cert-elsewhere"); issued {
		t.Fatal("an unknown certificate must not be claimed by this group")
	}
}

func TestClassifyRevocation(t *testing.T) {
	request := IntuneRevocationRequest{RequestContext: "ctx-1", SerialNumber: "ab"}
	revokeOK := func() error { return nil }
	revokeFails := func() error { return errors.New("kms unavailable") }

	for name, tc := range map[string]struct {
		found, issuedInGroup, alreadyRevoked bool
		revoke                               func() error
		wantSucceeded                        bool
		wantCode                             string
	}{
		"revokes a certificate the group issued": {true, true, false, revokeOK, true, ""},
		"already revoked is a success":           {true, true, true, revokeFails, true, ""},
		// Retryable, not not-found: Microsoft re-sends it next cycle.
		"revocation failure is retryable": {true, true, false, revokeFails, false, RevokeErrorRetryable},
		"unknown serial is not found":     {false, false, false, revokeOK, false, RevokeErrorCertificateNotFound},
		// The regression: a certificate that exists but belongs to no endpoint
		// in this group is genuinely not ours to revoke.
		"outside the group is not found": {true, false, false, revokeOK, false, RevokeErrorCertificateNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			got := classifyRevocation(request, tc.found, tc.issuedInGroup, tc.alreadyRevoked, tc.revoke)
			if got.RequestContext != request.RequestContext {
				t.Fatalf("RequestContext = %q, want %q", got.RequestContext, request.RequestContext)
			}
			if got.Succeeded != tc.wantSucceeded {
				t.Fatalf("Succeeded = %t, want %t", got.Succeeded, tc.wantSucceeded)
			}
			if got.ErrorCode != tc.wantCode {
				t.Fatalf("ErrorCode = %q, want %q", got.ErrorCode, tc.wantCode)
			}
		})
	}
}
