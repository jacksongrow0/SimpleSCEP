package home

import (
	"strings"
	"testing"
	"time"
)

// TestESTPanelExplainsTheAuthenticationModel: a device authenticating with a
// password rather than the client certificate RFC 7030 describes is the most
// surprising thing about this implementation, so the explanation has to be on
// the page and not only in the documentation.
func TestESTPanelExplainsTheAuthenticationModel(t *testing.T) {
	html := panelOf(t, render(t, Protocols(testSession(), ProtocolPage{
		EST: ESTPage{CAs: []ProtocolCA{{ID: "ca-1", Name: "Issuing CA"}}},
	})), "est")

	for _, want := range []string{"HTTP Basic", "TLS client certificate", "renewal window"} {
		if !strings.Contains(html, want) {
			t.Errorf("the panel does not mention %q", want)
		}
	}
}

func TestESTSetupIsUnavailableWithoutACA(t *testing.T) {
	html := panelOf(t, render(t, Protocols(testSession(), ProtocolPage{
		EST: ESTPage{},
	})), "est")

	if strings.Contains(html, "est-setup-dialog').showModal()") {
		t.Error("the setup dialog is offered with no issuing CA to bind to")
	}
	if !strings.Contains(html, "Create an active issuing CA first") {
		t.Error("the panel does not say what to do first")
	}
}

func TestESTEndpointViewShowsTheBaseURL(t *testing.T) {
	html := render(t, ESTEndpointView(testSession(), ESTEndpointData{
		Endpoint: ESTEndpoint{ID: "e-1", Name: "Branch VPN gateways", CAName: "Issuing CA",
			BaseURL: "https://pki.example.test/.well-known/est/e-1",
			APIBase: "/api/est/endpoints/e-1", Enabled: true,
			ValidityDays: 365, RenewalWindowDays: 73},
	}))

	if !strings.Contains(html, "https://pki.example.test/.well-known/est/e-1") {
		t.Error("the base URL a client is configured with is not shown")
	}
	// /cacerts being open is the thing that makes first enrollment possible at
	// all, so an operator has to be able to learn it from the page.
	if !strings.Contains(html, "needs no credentials") {
		t.Error("the page does not say that /cacerts needs no credentials")
	}
}

// TestESTEnrollmentLogShowsRefusalsAndWhy: a refused device is the case an
// operator opens this page for, so the row has to say both that it was refused
// and what the device was told.
func TestESTEnrollmentLogShowsRefusalsAndWhy(t *testing.T) {
	html := render(t, ESTEndpointView(testSession(), ESTEndpointData{
		Endpoint: ESTEndpoint{ID: "e-1", Name: "Branch VPN gateways", APIBase: "/api/est/endpoints/e-1"},
		Enrollments: []ESTEnrollment{
			{Subject: "CN=gw-01.example.internal", Operation: "enroll", Credential: "Fleet A",
				Result: "issued", CertificateStatus: "issued", CreatedAt: time.Now()},
			{Subject: "CN=laptop.example.com", Operation: "enroll", Credential: "Fleet A",
				Result: "failed", FailureReason: "the request is not permitted by this endpoint's issuance policy",
				CreatedAt: time.Now()},
		},
	}))

	if !strings.Contains(html, "Refused") {
		t.Error("a refused enrollment is not marked as refused")
	}
	if !strings.Contains(html, "not permitted by this endpoint&#39;s issuance policy") {
		t.Error("the refusal does not say why")
	}
	if !strings.Contains(html, "CN=laptop.example.com") {
		t.Error("the refused subject is not shown")
	}
	// The successful row must still read as issued rather than borrowing the
	// failed row's styling.
	if !strings.Contains(html, "Issued") {
		t.Error("a successful enrollment is no longer shown as issued")
	}
}

func TestESTEnrollmentFailedPredicate(t *testing.T) {
	if !(ESTEnrollment{Result: "failed"}).Failed() {
		t.Error("a failed enrollment does not report itself as failed")
	}
	// An issued enrollment whose certificate was later revoked is not a failed
	// enrollment: the device did get in.
	if (ESTEnrollment{Result: "issued", CertificateStatus: "revoked"}).Failed() {
		t.Error("a revoked certificate is being reported as a failed enrollment")
	}
}

// TestESTDeleteDialogNamesTheSilentFailure: every consequence of deleting an
// endpoint is delayed, so the dialog has to say so or it reads as harmless.
func TestESTDeleteDialogNamesTheSilentFailure(t *testing.T) {
	html := render(t, ESTEndpointView(testSession(), ESTEndpointData{
		Endpoint: ESTEndpoint{ID: "e-1", Name: "Branch VPN gateways",
			APIBase: "/api/est/endpoints/e-1", LiveCertificates: 12},
	}))

	if !strings.Contains(html, "Re-enrollment fails silently") {
		t.Error("the delete dialog does not warn that renewal fails silently")
	}
	if !strings.Contains(html, "12 certificates") {
		t.Error("the delete dialog does not say how many certificates depend on the endpoint")
	}
	if !strings.Contains(html, "No certificate is revoked") {
		t.Error("the delete dialog does not say what deletion leaves alone")
	}
}

// TestESTCredentialSecretShowsBothHalves: the password exists in a readable form
// for exactly one response, so all three parts a client needs must be in it.
func TestESTCredentialSecretShowsBothHalves(t *testing.T) {
	html := render(t, ESTCredentialSecret("https://pki.example.test/.well-known/est/e-1",
		"branch-gateways", "s3cret-password", "/protocols/est/e-1"))

	for _, want := range []string{
		"https://pki.example.test/.well-known/est/e-1",
		"branch-gateways",
		"s3cret-password",
		"Copy this now",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the secret panel is missing %q", want)
		}
	}
}

func TestESTCredentialStatus(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		cred ESTCredential
		want string
	}{
		{"fresh", ESTCredential{}, "Active"},
		{"revoked", ESTCredential{Revoked: true}, "Revoked"},
		{"expired", ESTCredential{ExpiresAt: &past}, "Expired"},
		{"unexpired", ESTCredential{ExpiresAt: &future}, "Active"},
		// Revocation wins over an expiry that has not arrived yet.
		{"revoked and unexpired", ESTCredential{Revoked: true, ExpiresAt: &future}, "Revoked"},
	}
	for _, tc := range cases {
		if got := tc.cred.Status(); got != tc.want {
			t.Errorf("%s: Status() = %q, want %q", tc.name, got, tc.want)
		}
	}
}
