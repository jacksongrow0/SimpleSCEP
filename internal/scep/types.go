package scep

import "time"

const (
	// AuthRenewal is a resolution result only; it is never a configurable method.
	AuthRenewal = "renewal"
	AuthOneTime = "one_time"
	AuthStatic  = "static"
	AuthIntune  = "intune"
	// AuthJamf mints one-time challenges over a webhook, so it authorizes
	// enrollments as one_time and never appears as a resolution result.
	AuthJamf = "jamf"
)

// Methods is the order the enrollment authorizer tries configured methods in.
// Cheap local checks run before the Intune round trip.
var Methods = []string{AuthOneTime, AuthStatic, AuthIntune, AuthJamf}

const (
	// DefaultValidityDays is how long a new endpoint's certificates last.
	DefaultValidityDays = 365
	// DefaultRenewalWindowDays opens renewal at 20% of the default validity,
	// which is what Intune and Jamf expect of a SCEP profile: devices that
	// check in monthly get several attempts before their certificate lapses.
	DefaultRenewalWindowDays = 73
)

type Endpoint struct {
	ID, OrganizationID, CAID, Name          string
	RACertificatePEM                        string
	RAPrivateKeyCiphertext                  []byte
	Enabled, AllowLegacyCrypto              bool
	ValidityDays, RenewalWindowDays         int
	AllowedEKUs, SubjectPattern, SANPattern string
	CreatedAt, UpdatedAt                    time.Time
}

type AuthMethod struct {
	ID, OrganizationID, EndpointID, Method string
	Enabled                                bool
	SecretHash                             string
	// IntuneConnected mirrors the organization's Entra connection rather than
	// anything on this row: one directory serves every endpoint the
	// organization runs. Callers that build an AuthMethod by hand rather than
	// reading one back must set it, or the method reports itself unconfigured.
	IntuneConnected        bool
	Username, PasswordHash string
	ConfiguredAt           *time.Time
	CreatedAt, UpdatedAt   time.Time
}

// Configured reports whether the method has the credentials it needs to be enabled.
// one_time needs nothing beyond the endpoint itself.
func (m AuthMethod) Configured() bool {
	switch m.Method {
	case AuthOneTime:
		return true
	case AuthStatic:
		return m.SecretHash != ""
	case AuthIntune:
		// The client credentials belong to SimpleSCEP's own multi-tenant
		// application, so the organization's connected tenant is the whole
		// configuration.
		return m.IntuneConnected
	case AuthJamf:
		return m.Username != "" && m.PasswordHash != ""
	}
	return false
}

// IntuneConnection is the single Microsoft Entra directory an organization has
// consented to. Every endpoint the organization runs enrols through it.
type IntuneConnection struct {
	OrganizationID, TenantID string
	ConnectedAt              time.Time
}

type Challenge struct {
	ID, OrganizationID, EndpointID, SecretHash string
	ExpectedSubject, ExpectedSANs, ExternalID  string
	// ExpectedEKUs pins the usages the authorized enrollment is issued with, as
	// a comma-separated list. Empty does not constrain, matching the fields
	// above.
	ExpectedEKUs string
	ExpiresAt    time.Time
	UsedAt       *time.Time
}

// ChallengeSpec is what a one-time challenge binds its enrollment to. Every
// constraint is optional; an empty field does not constrain. TTL defaults to
// fifteen minutes and is capped at a day.
type ChallengeSpec struct {
	ExpectedSubject, ExpectedSANs, ExternalID string
	ExpectedEKUs                              []string
	TTL                                       time.Duration
}

type Transaction struct {
	EndpointID, TransactionID, CSRDigest, CertificateID string
	Status, MessageType, AuthorizationSource            string
	FailureReason                                       string
	// SignerKeyDigest identifies the key that signed the PKIMessage which opened
	// this transaction, so a repeat can be recognised as the same device rather
	// than as anyone holding the same CSR. Empty on rows written before the
	// column existed. See Service.issue.
	SignerKeyDigest string
	CreatedAt       time.Time
}

// IntuneApp is the operator-managed multi-tenant Entra application that connected
// tenants grant admin consent to. One credential serves every organization, so
// it comes from the environment rather than the database.
type IntuneApp struct {
	ClientID, ClientSecret string
}

func (a IntuneApp) Deployed() bool { return a.ClientID != "" && a.ClientSecret != "" }

// integration is the credential set for calling Intune on one tenant's behalf.
func (a IntuneApp) integration(tenantID string) Integration {
	return Integration{Provider: AuthIntune, TenantID: tenantID, ApplicationID: a.ClientID, Secret: a.ClientSecret}
}

// Integration is the credential set used to call Intune for one tenant: the
// tenant's directory ID paired with our own application's credentials. It is
// assembled at request time and never persisted in this shape.
type Integration struct {
	Provider, TenantID, ApplicationID string
	Secret                            string
}
