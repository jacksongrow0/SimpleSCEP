// Package est implements RFC 7030, Enrollment over Secure Transport: the
// protocol network infrastructure enrolls with when SCEP is too dated and ACME
// too web-shaped. VPN gateways, routers, and IoT fleets speak it.
//
// It deviates from the RFC in one place, deliberately. RFC 7030's primary
// client authentication is a TLS client certificate, but TLS terminates at a
// proxy ahead of this process — the server listens on plain HTTP and infers the
// scheme from X-Forwarded-Proto — so a client certificate never reaches here to
// be checked. Section 3.2.3 permits HTTP Basic over a server-authenticated TLS
// connection instead, and that is what this implements: per-endpoint
// credentials, argon2id-hashed, verified on every enrollment.
//
// The consequence lands on /simplereenroll, which the RFC authenticates by the
// certificate the client already holds. Here it is authenticated by the same
// Basic credential plus a binding check: the subject in the CSR must already
// hold a live certificate this endpoint issued, and the request must fall inside
// the endpoint's renewal window. That is the same shape as SCEP's renewal
// authorization, which faces the same problem for the same reason.
//
// Like acme.Endpoint and unlike scep.Endpoint, an EST endpoint owns no key
// material: responses are unsigned certs-only PKCS#7, so there is no
// registration authority certificate to mint or protect.
package est

import (
	"fmt"
	"net/http"
	"time"
)

const (
	// DefaultValidityDays matches SCEP's rather than ACME's. EST enrolls
	// long-lived infrastructure — gateways and appliances, not web servers
	// behind an automated renewal loop — so a year is the useful default.
	DefaultValidityDays = 365
	// DefaultRenewalWindowDays opens re-enrollment at 20% of the default
	// validity, the same proportion SCEP uses.
	DefaultRenewalWindowDays = 73

	// MaxMessageSize bounds a request body. It matches scep.maxMessageSize; a
	// PKCS#10 that does not fit in 2 MiB is not a certificate request.
	MaxMessageSize = 2 << 20

	// Operations, as they appear in the URL after the endpoint label.
	OpCACerts       = "cacerts"
	OpSimpleEnroll  = "simpleenroll"
	OpSimpleReenrol = "simplereenroll"
	OpCSRAttrs      = "csrattrs"

	// Content types from RFC 7030 §3.2.4.
	ContentTypePKCS10   = "application/pkcs10"
	ContentTypePKCS7    = "application/pkcs7-mime; smime-type=certs-only"
	ContentTypeCSRAttrs = "application/csrattrs"

	// OperationEnroll and OperationReenroll are what est_enrollment records.
	OperationEnroll   = "enroll"
	OperationReenroll = "reenroll"

	// StatusIssued and StatusFailed are est_enrollment.status.
	StatusIssued = "issued"
	StatusFailed = "failed"

	// maxFailureReason bounds what a refusal writes. The reason can quote a
	// subject a client chose, so it is not something this side controls.
	maxFailureReason = 500
)

// Error is a refusal a client is allowed to see. EST has no problem-document
// format — §4.2.3 says a failure is an HTTP status with a human-readable body —
// so the type carries just those two things.
//
// Only an *Error reaches the wire. Every other error is answered as an opaque
// 500, so a database or KMS failure cannot describe itself to an unauthenticated
// caller.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

func errorf(status int, format string, args ...any) *Error {
	return &Error{Status: status, Message: fmt.Sprintf(format, args...)}
}

// Endpoint is one EST server: a URL prefix bound to an issuing CA, with the
// issuance policy every certificate enrolled through it is held to.
type Endpoint struct {
	ID, OrganizationID, CAID, Name          string
	Enabled                                 bool
	ValidityDays, RenewalWindowDays         int
	AllowedEKUs, SubjectPattern, SANPattern string
	// ReenrollRequiresSameKey makes /simplereenroll demand the CSR carry the same
	// public key as the certificate being renewed. The CSR is self-signed, so a
	// matching key is a genuine proof of possession — the closest this service
	// gets to the mutual-TLS binding RFC 7030 assumes, given the client
	// certificate never reaches the process. Off by default, because rotating a
	// key at renewal is normal EST behaviour.
	ReenrollRequiresSameKey bool
	CreatedAt, UpdatedAt    time.Time
}

// RenewableCert is the live certificate a re-enrollment renews: when it expires,
// and the certificate itself, so key continuity can be checked against it.
type RenewableCert struct {
	ExpiresAt      time.Time
	CertificatePEM string
}

// Credential is one HTTP Basic identity an EST client presents.
//
// SecretHash is argon2id rather than sealed ciphertext, unlike
// acme.EABCredential's MAC key. Verification here is a comparison against a
// password the client sends, so the server needs a way to check a guess, not the
// material back.
type Credential struct {
	ID, OrganizationID, EndpointID string
	Label, Username                string
	SecretHash                     string
	// IdentifierPin is a comma-separated list of exact subject common names or
	// SANs this credential may enroll. Empty does not constrain, leaving the
	// endpoint's patterns as the only limit.
	IdentifierPin string
	ExpiresAt     *time.Time
	UsedAt        *time.Time
	RevokedAt     *time.Time
	CreatedAt     time.Time
}

// Usable reports whether the credential can still authenticate an enrollment.
// Unlike an ACME credential there is no single-use option: an EST client
// presents its credential again on every re-enrollment, for the life of the
// device.
func (c Credential) Usable(now time.Time) bool {
	switch {
	case c.RevokedAt != nil:
		return false
	case c.ExpiresAt != nil && !c.ExpiresAt.After(now):
		return false
	}
	return true
}

// Enrollment is one issuance this endpoint performed. It is the endpoint page's
// activity log, and the record /simplereenroll consults to decide whether a
// subject is one this endpoint has seen before.
type Enrollment struct {
	ID, OrganizationID, EndpointID string
	CredentialID                   string
	CertificateID                  string
	Subject                        string
	Operation                      string
	// Status is StatusIssued or StatusFailed; FailureReason is set only for the
	// latter. A refused enrollment has no certificate, so CertificateID is empty.
	Status        string
	FailureReason string
	CreatedAt     time.Time
}

// Failure describes a refused enrollment so the handler can record it after the
// request transaction has been rolled back.
//
// It is only ever built once a credential has authenticated. Recording refusals
// from unauthenticated callers would let anyone who can reach the endpoint write
// rows at will; those are rate-limited and logged instead. What is left is
// exactly the case an operator debugs — a device that is configured, gets in,
// and is then turned away by policy.
type Failure struct {
	CredentialID string
	Subject      string
	Operation    string
	Reason       string
}

// CredentialSpec is what the administration form asks for when minting one.
type CredentialSpec struct {
	Label, Username string
	Identifiers     string
	TTLHours        int
}

// Unauthorized is the 401 every failed Basic exchange produces. The message is
// deliberately the same whether the username was unknown, the password wrong, or
// the credential revoked: a caller learns only that it may not enroll.
func unauthorized() *Error {
	return errorf(http.StatusUnauthorized, "authentication required")
}
