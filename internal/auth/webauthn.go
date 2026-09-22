package auth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// maxCeremonyBody bounds an attestation or assertion body. A WebAuthn response
// is a few kilobytes; 64KB is generous and stops an unauthenticated caller
// streaming an unbounded body into memory. Same treatment startImport gives its
// uploads in internal/pki.
const maxCeremonyBody = 64 << 10

// RPDisplayName is what an authenticator shows at registration. It is the
// product's name, which is not a per-deployment fact.
const RPDisplayName = "SimpleSCEP"

// NewWebAuthn builds the relying party configuration from APP_URL.
//
// The RP ID is the DNS scope of every passkey ever registered against this
// service. Changing it invalidates all of them at once, silently — an
// authenticator simply reports that it holds no credential for the site — so it
// is derived from configuration rather than from a request, for the same reason
// Handler.link is. It is always the APP_URL host: an override existed for
// scoping credentials to a parent domain, but the only thing it could do
// correctly was what this already does, and the only thing it could do
// incorrectly was invalidate every passkey ever registered.
//
// Returning an error rather than falling back keeps a misconfigured deployment
// from registering passkeys that will stop working the first time the hostname
// is read differently.
func NewWebAuthn(appURL string) (*webauthn.WebAuthn, error) {
	parsed, err := url.Parse(appURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("passkeys need a valid APP_URL, got %q", appURL)
	}
	// Hostname strips the port. An RP ID is a bare domain and must not carry one;
	// an origin must.
	return webauthn.New(&webauthn.Config{
		RPID:          parsed.Hostname(),
		RPDisplayName: RPDisplayName,
		RPOrigins:     []string{parsed.Scheme + "://" + parsed.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Prefer a discoverable credential so browser password managers can
			// offer to store and sync the passkey. Preferred rather than Required
			// keeps hardware security keys with limited resident-key storage usable.
			ResidentKey: protocol.ResidentKeyRequirementPreferred,
			// Preferred rather than Required: a security key without a PIN or
			// biometric is still a genuine possession factor, and it is the second
			// factor rather than the only one.
			UserVerification: protocol.VerificationPreferred,
		},
	})
}

// webAuthnUser adapts a user to the library's interface.
//
// WebAuthnID is the raw UUID bytes rather than the email: it is stored by the
// authenticator and shown in its credential list, it must be stable for the
// lifetime of the account, and it must not be personal data. An email is
// mutable and is none of those things.
type webAuthnUser struct {
	id          uuid.UUID
	email, name string
	credentials []webauthn.Credential
}

func (u webAuthnUser) WebAuthnID() []byte { b := u.id; return b[:] }

func (u webAuthnUser) WebAuthnName() string { return u.email }

func (u webAuthnUser) WebAuthnDisplayName() string {
	if u.name != "" {
		return u.name
	}
	return u.email
}

func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// Passkey is one registered credential as this package stores it.
type Passkey struct {
	ID           uuid.UUID
	CredentialID []byte
	PublicKey    []byte
	Attestation  string
	AAGUID       []byte
	Transports   string
	SignCount    uint32
	BackupEli    bool
	BackupState  bool
	CloneWarning bool
	Label        string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// credential converts a stored row into the library's type.
func (p Passkey) credential() webauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	for _, t := range strings.Split(p.Transports, ",") {
		if t = strings.TrimSpace(t); t != "" {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}
	return webauthn.Credential{
		ID:              p.CredentialID,
		PublicKey:       p.PublicKey,
		AttestationType: p.Attestation,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: p.BackupEli,
			BackupState:    p.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       p.AAGUID,
			SignCount:    p.SignCount,
			CloneWarning: p.CloneWarning,
		},
	}
}

// fromCredential converts a freshly registered credential into a storable row.
func fromCredential(c *webauthn.Credential, label string) Passkey {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return Passkey{
		CredentialID: c.ID,
		PublicKey:    c.PublicKey,
		Attestation:  c.AttestationType,
		AAGUID:       c.Authenticator.AAGUID,
		Transports:   strings.Join(transports, ","),
		SignCount:    c.Authenticator.SignCount,
		BackupEli:    c.Flags.BackupEligible,
		BackupState:  c.Flags.BackupState,
		Label:        label,
	}
}

// encodeSessionData and decodeSessionData move a ceremony's state to and from
// the database.
//
// It is held server-side and never in a cookie because it carries the challenge
// the response is verified against. A challenge the client can read and rewrite
// is not a challenge — it would let an attacker replay a captured assertion
// against a challenge of their own choosing.
func encodeSessionData(data *webauthn.SessionData) ([]byte, error) {
	return json.Marshal(data)
}

func decodeSessionData(raw []byte) (*webauthn.SessionData, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("no ceremony in progress")
	}
	var data webauthn.SessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// passkeyLabel cleans up the name a user gives a key, falling back to something
// recognisable. It is display-only and never used to look a credential up.
func passkeyLabel(raw string) string {
	label := strings.TrimSpace(raw)
	if label == "" {
		return "Passkey"
	}
	if len(label) > 64 {
		label = label[:64]
	}
	return label
}
