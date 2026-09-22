// Package acme implements RFC 8555 enrollment against an organization's own
// issuing CA.
//
// It is the second enrollment protocol, alongside SCEP. Where SCEP serves
// MDM-managed devices, ACME serves everything that renews itself — cert-manager,
// Caddy, Traefik, acme.sh, lego — so a customer points an existing tool at a
// directory URL rather than writing an integration.
//
// The one place this deviates from a public ACME server is how a client proves
// it may ask for a name. SimpleSCEP issues from private CAs
// for names like vpn.example.internal: http-01 and tls-alpn-01 would need
// inbound reachability into the customer's network, and dns-01 would need the
// name to be resolvable in public DNS. Neither holds. So account creation
// requires External Account Binding (§7.3.4) against a credential an
// administrator mints — the direct analogue of SCEP's one-time challenge — and
// authorizations are issued already valid. What a client may ask for is then
// decided by the endpoint's subject and SAN policy plus the credential's
// optional identifier pin, which is the same answer SCEP gives.
//
// Every widely deployed client skips straight to finalize on an authorization
// that is already valid, so this is transparent to them. See docs/acme.md.
package acme

import (
	"fmt"
	"time"
)

const (
	// DefaultValidityDays is how long a new endpoint's certificates last. Short
	// where SCEP's default is a year: an ACME client renews unattended, so a
	// brief life costs nobody anything.
	DefaultValidityDays = 90

	// OrderTTL is how long a client has to finalize an order before it lapses,
	// and how long the authorizations under it live.
	OrderTTL = 7 * 24 * time.Hour

	// NonceTTL bounds how long an unspent nonce is worth keeping. Clients spend
	// them within a round trip; this is only what stops the table growing.
	NonceTTL = time.Hour
)

// ChallengeExternal is the type of the single challenge every authorization
// carries. RFC 8555 requires an authorization to offer at least one challenge
// for its wire form to be well-formed, and this one names why there is nothing
// to do: the account is bound to an external credential. Clients branch on the
// authorization's status, not on this string.
const ChallengeExternal = "external-account-binding-01"

// Order and authorization statuses (RFC 8555 §7.1.6).
const (
	StatusPending    = "pending"
	StatusReady      = "ready"
	StatusProcessing = "processing"
	StatusValid      = "valid"
	StatusInvalid    = "invalid"

	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusRevoked     = "revoked"
)

// Identifier types (§9.7.7). IP is accepted because internal services are
// routinely addressed by address rather than by name.
const (
	IdentifierDNS = "dns"
	IdentifierIP  = "ip"
)

// Problem types (§6.7). These are the error codes clients act on: badNonce
// triggers a retry with a fresh nonce, externalAccountRequired tells a client it
// needs EAB configured, and the rest surface to the operator as-is.
const (
	ProblemMalformed               = "urn:ietf:params:acme:error:malformed"
	ProblemBadNonce                = "urn:ietf:params:acme:error:badNonce"
	ProblemBadSignatureAlgorithm   = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	ProblemBadPublicKey            = "urn:ietf:params:acme:error:badPublicKey"
	ProblemBadCSR                  = "urn:ietf:params:acme:error:badCSR"
	ProblemBadRevocationReason     = "urn:ietf:params:acme:error:badRevocationReason"
	ProblemAccountDoesNotExist     = "urn:ietf:params:acme:error:accountDoesNotExist"
	ProblemUnauthorized            = "urn:ietf:params:acme:error:unauthorized"
	ProblemRejectedIdentifier      = "urn:ietf:params:acme:error:rejectedIdentifier"
	ProblemUnsupportedIdentifier   = "urn:ietf:params:acme:error:unsupportedIdentifier"
	ProblemExternalAccountRequired = "urn:ietf:params:acme:error:externalAccountRequired"
	ProblemOrderNotReady           = "urn:ietf:params:acme:error:orderNotReady"
	ProblemAlreadyRevoked          = "urn:ietf:params:acme:error:alreadyRevoked"
	ProblemServerInternal          = "urn:ietf:params:acme:error:serverInternal"
	ProblemUserActionRequired      = "urn:ietf:params:acme:error:userActionRequired"
)

// SignatureAlgorithms is what the outer JWS may be signed with.
//
// The omissions are the point. "none" needs no key at all. Every HS* algorithm
// is a MAC, and an outer JWS carries its own verification key in the jwk header
// for newAccount, so accepting HS256 there would let a client sign with a key it
// also chose — anyone could register as anyone. HS256 is verified in exactly one
// place, the External Account Binding inner JWS, where the key comes from the
// database. See verifyEAB.
var SignatureAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

// Problem is an error that already knows how it should reach the client: an RFC
// 8555 §6.7 problem document with a machine-readable type and an HTTP status.
//
// Errors that are not a Problem become a 500 with ProblemServerInternal and an
// opaque detail, so nothing an internal failure happens to say ends up in a
// client's logs. Anything a client is meant to act on has to be built here
// deliberately.
type Problem struct {
	Type   string
	Detail string
	Status int
}

func (p Problem) Error() string { return p.Detail }

func problemf(status int, typ, format string, args ...any) Problem {
	return Problem{Type: typ, Status: status, Detail: fmt.Sprintf(format, args...)}
}

// Endpoint is one ACME directory: a URL prefix bound to an issuing CA, with the
// issuance policy every certificate ordered through it is held to.
//
// There is no registration authority here, which is the structural difference
// from scep.Endpoint. SCEP wraps its exchange in PKCS#7 signed by an RA
// certificate the server holds; ACME signs at the account level with a key the
// client holds, so an endpoint owns no key material.
type Endpoint struct {
	ID, OrganizationID, CAID, Name          string
	Enabled                                 bool
	ValidityDays                            int
	AllowedEKUs, SubjectPattern, SANPattern string
	CreatedAt, UpdatedAt                    time.Time
}

// EABCredential is an External Account Binding credential: the key an
// administrator hands to whoever is configuring a client, which is what binds
// the account that client creates to this organization.
//
// MACKeyCiphertext is sealed rather than hashed, unlike scep.Challenge's
// argon2id verifier. Verification is an HMAC computation over the client's inner
// JWS, so the server needs the key material back, not a way to check a guess.
type EABCredential struct {
	ID, OrganizationID, EndpointID string
	Label, KID                     string
	MACKeyCiphertext               []byte
	// IdentifierPin is a comma-separated list of exact identifiers an account
	// bound with this credential may order. Empty does not constrain, leaving
	// the endpoint's SAN policy as the only limit.
	IdentifierPin string
	SingleUse     bool
	ExpiresAt     *time.Time
	UsedAt        *time.Time
	RevokedAt     *time.Time
	CreatedAt     time.Time
}

// Usable reports whether the credential can still bind a new account.
func (c EABCredential) Usable(now time.Time) bool {
	switch {
	case c.RevokedAt != nil:
		return false
	case c.ExpiresAt != nil && !c.ExpiresAt.After(now):
		return false
	case c.SingleUse && c.UsedAt != nil:
		return false
	}
	return true
}

// Account is one client's registration. The key it signs with is its identity;
// the thumbprint is how a client that kept its key but lost its account URL
// finds its way back.
type Account struct {
	ID, OrganizationID, EndpointID string
	JWKThumbprint, JWKJSON         string
	Status                         string
	// Contact is comma-separated URIs, matching how AllowedEKUs stores a list.
	Contact string
	// EABCredentialID is provenance only. IdentifierPin is copied off the
	// credential at registration and enforced from here, so revoking the
	// credential cannot silently widen what an account it already bound may ask
	// for.
	EABCredentialID      string
	IdentifierPin        string
	CreatedAt, UpdatedAt time.Time
}

// Order is one request for a certificate covering a set of identifiers.
type Order struct {
	ID, OrganizationID, EndpointID, AccountID string
	Status                                    string
	ExpiresAt                                 time.Time
	NotBefore, NotAfter                       *time.Time
	CertificateID                             string
	ErrorType, ErrorDetail                    string
	CreatedAt, UpdatedAt                      time.Time
}

// Authorization is the server's decision about one identifier on one order.
// Under the external-account model it is created valid; the row exists because
// the protocol's shape requires it and because it is the audit trail of what an
// order was actually permitted to cover.
type Authorization struct {
	ID, OrganizationID, OrderID string
	IdentifierType              string
	IdentifierValue             string
	Status                      string
	ExpiresAt                   time.Time
	ValidatedAt                 *time.Time
}

// Challenge is the placeholder every authorization carries. See
// ChallengeExternal.
type Challenge struct {
	ID, OrganizationID, AuthorizationID string
	Type, Token, Status                 string
	ValidatedAt                         *time.Time
}

// Identifier is one name an order covers. The tags are load-bearing: this
// struct is marshalled straight into order and authorization responses, and
// RFC 8555 spells the members "type" and "value". Clients that read the
// identifier out of an authorization by lowercase key see an empty name
// without them, and never reach finalize.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// CredentialSpec is what minting an External Account Binding credential takes.
// Every field is optional: the zero value is a reusable credential, valid
// forever, constrained only by the endpoint's policy.
type CredentialSpec struct {
	Label string
	// Identifiers pins the credential to exact names. Empty does not constrain.
	Identifiers []string
	SingleUse   bool
	TTL         time.Duration
}

// RevocationReasons maps RFC 5280 CRLReason codes onto the reasons the product
// records (pki.RevocationReasons). A code with no entry is refused rather than
// flattened onto "unspecified": a client asking for cessationOfOperation and
// silently getting something else is worse than a 400 naming the code.
//
// The gaps are deliberate. 2 (cACompromise) cannot apply to a leaf; 6
// (certificateHold) is a suspension, which this product does not model, and
// which RFC 8555 §7.6 forbids anyway; 7 is unassigned; 8 (removeFromCRL) is a
// CRL-management operation rather than a revocation; 9 (privilegeWithdrawn) and
// 10 (aACompromise) have no representation here.
var RevocationReasons = map[int]string{
	0: "unspecified",
	1: "key_compromise",
	3: "affiliation_changed",
	4: "superseded",
	5: "cessation_of_operation",
}
