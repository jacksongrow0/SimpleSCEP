// Package audit is the organization's record of who changed what.
//
// It reads from two places. Every use of a CA key already lands in
// certificate_signing_audit, which is written on the signing path and is the
// authoritative record of issuance and CA lifecycle; audit_event holds
// everything else — sign-ins, user and organization changes, SCEP endpoint
// administration. The reader presents both as one stream because the
// distinction is an implementation detail of where the write happened.
package audit

import (
	"net/http"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
)

// Actions recorded in audit_event. PKI actions are derived from the signing
// audit's purpose column instead; see actionForPurpose.
const (
	ActionSignedIn  = "user.signed_in"
	ActionSignedOut = "user.signed_out"

	ActionUserInvited = "user.invited"
	// Revoking a pending invitation is recorded because the invitation itself was:
	// an entry saying somebody was invited, with nothing saying the invitation was
	// withdrawn, reads as an outstanding grant that never happened.
	ActionUserInvitationRevoked = "user.invitation_revoked"
	ActionUserRoleChanged       = "user.role_changed"
	ActionUserRemoved           = "user.removed"
	// A display name is not an authorisation decision, but it is what every other
	// entry shows beside an actor, so a change to it is context a reader of those
	// entries needs. Only ever written by the person about themselves.
	ActionUserRenamed = "user.renamed"

	// Second factor. These are the events an investigation into a compromised
	// account reads first: when the factor was registered, when it was replaced,
	// and whether a recovery code was spent doing it.
	//
	// ActionMFAFailed is written only when a challenge runs out of attempts, not
	// on each wrong code. A mistyped digit is not an event, and recording every
	// one would let anyone fill an organization's log from the sign-in page.
	ActionMFAEnrolled     = "user.mfa_enrolled"
	ActionMFARemoved      = "user.mfa_removed"
	ActionMFAFailed       = "user.mfa_failed"
	ActionMFARecoveryUsed = "user.mfa_recovery_used"
	// ActionMFARecoveryRegenerated is no longer written by anything: recovery
	// codes are issued once, at enrolment, and there is no regeneration route.
	// It stays because the log is append-only and rows carrying it still exist —
	// removing the constant would render those rows with a raw action string and
	// drop the option from the audit filter that finds them.
	ActionMFARecoveryRegenerated = "user.mfa_recovery_regenerated"
	// There is deliberately no action for an administrator resetting someone
	// else's second factor: no such path exists yet. When one is built it belongs
	// here, and in Actions below so the audit filter offers it. Adding it before
	// anything writes it would put an option in that filter that never matches.

	ActionPasskeyRegistered   = "user.passkey_registered"
	ActionPasskeyRemoved      = "user.passkey_removed"
	ActionPasskeyCloneWarning = "user.passkey_clone_warning"

	ActionStepUpFailed = "user.step_up_failed"

	ActionOrganizationRenamed = "organization.renamed"

	ActionEndpointCreated = "scep_endpoint.created"
	ActionEndpointDeleted = "scep_endpoint.deleted"
	ActionEndpointEnabled = "scep_endpoint.enabled"
	ActionEndpointPaused  = "scep_endpoint.disabled"
	ActionEndpointPolicy  = "scep_endpoint.policy_changed"

	// The rest of SCEP endpoint administration. Everything below hands out or
	// changes the credential a device authenticates with, which is the same act
	// the ACME and EST credential events record; SCEP calls its credentials
	// challenges and shared secrets, so the names follow SCEP's vocabulary
	// rather than being forced into the other protocols'.
	//
	// The secret itself is never a target or a detail. What a reader needs is
	// that one was issued, to which endpoint, and by whom.
	ActionSCEPChallengeIssued    = "scep_challenge.created"
	ActionSCEPSecretRotated      = "scep_endpoint.secret_rotated"
	ActionSCEPAuthMethodChanged  = "scep_endpoint.auth_method_changed"
	ActionSCEPJamfConfigured     = "scep_endpoint.jamf_configured"
	ActionSCEPIntuneConnected    = "scep_intune.connected"
	ActionSCEPIntuneDisconnected = "scep_intune.disconnected"

	// The ACME constants carry the protocol in their names where the SCEP ones
	// above do not. SCEP was the only protocol when those were written; renaming
	// them now would churn every call site in internal/scep for no reader's
	// benefit, and the action strings themselves are already unambiguous.
	ActionACMEEndpointCreated   = "acme_endpoint.created"
	ActionACMEEndpointDeleted   = "acme_endpoint.deleted"
	ActionACMEEndpointEnabled   = "acme_endpoint.enabled"
	ActionACMEEndpointPaused    = "acme_endpoint.disabled"
	ActionACMEEndpointPolicy    = "acme_endpoint.policy_changed"
	ActionACMECredentialIssued  = "acme_credential.created"
	ActionACMECredentialRevoked = "acme_credential.revoked"

	ActionESTEndpointCreated   = "est_endpoint.created"
	ActionESTEndpointDeleted   = "est_endpoint.deleted"
	ActionESTEndpointEnabled   = "est_endpoint.enabled"
	ActionESTEndpointPaused    = "est_endpoint.disabled"
	ActionESTEndpointPolicy    = "est_endpoint.policy_changed"
	ActionESTCredentialIssued  = "est_credential.created"
	ActionESTCredentialRevoked = "est_credential.revoked"

	// Derived from certificate_signing_audit.
	ActionRootCACreated      = "ca.root_created"
	ActionIssuingCACreated   = "ca.issuing_created"
	ActionCAImported         = "ca.imported"
	ActionCADeleted          = "ca.deleted"
	ActionCAActivated        = "ca.activated"
	ActionCADeactivated      = "ca.deactivated"
	ActionCARetired          = "ca.retired"
	ActionCARotated          = "ca.rotated"
	ActionCertificateIssued  = "certificate.issued"
	ActionCertificateRevoked = "certificate.revoked"
	ActionOther              = "other"
)

// Event is one recorded change. Target names what was acted on and Detail
// carries whatever identifies it precisely — a serial, a former role.
type Event struct {
	ID             string
	OrganizationID string
	ActorUserID    string
	ActorEmail     string
	// ActorName is filled on read from the user record, and is empty for an
	// actor who has since been removed; ActorEmail survives them.
	ActorName string
	Action    string
	Target    string
	Detail    string
	At        time.Time
	// Where the action came from. Empty for events with no request behind them —
	// a background worker publishing a CRL, or a device enrolling over SCEP.
	// ActorSessionID is what distinguishes two sessions of the same account, so
	// it is stored as text and outlives the session row it names.
	ActorIP        string
	ActorUserAgent string
	ActorSessionID string
}

// From fills in where an action came from. Every audited administrator action
// has a request behind it, and this is the one place that knows how to read it,
// so call sites say what happened rather than how it arrived.
func (e Event) From(r *http.Request, sessionID string) Event {
	e.ActorIP = clientip.ClientIP(r)
	e.ActorUserAgent = r.UserAgent()
	e.ActorSessionID = sessionID
	return e
}

// Actor is the display name for whoever performed an event, falling back to the
// email the row carries and then to SimpleSCEP itself for events with no human
// behind them — a certificate issued to a device over SCEP, say.
func (e Event) Actor() string {
	switch {
	case e.ActorName != "":
		return e.ActorName
	case e.ActorEmail != "":
		return e.ActorEmail
	default:
		return "SimpleSCEP"
	}
}

// Filter narrows a log query. A zero field does not constrain.
type Filter struct {
	// Actor is a user id, or the sentinel SystemActor for events with no user.
	Actor  string
	Action string
	From   *time.Time
	To     *time.Time
	Limit  int
	// Offset skips this many matching events before the page begins. It is
	// applied to the merged log rather than pushed into either query — see
	// Repository.Events for why that distinction is the whole of correct
	// pagination here.
	Offset int
}

// SystemActor selects events that no user performed.
const SystemActor = "system"

// ActionLabel renders an action for a reader.
func ActionLabel(action string) string {
	switch action {
	case ActionSignedIn:
		return "Signed in"
	case ActionSignedOut:
		return "Signed out"
	case ActionUserInvited:
		return "User invited"
	case ActionUserInvitationRevoked:
		return "Invitation revoked"
	case ActionUserRoleChanged:
		return "User role changed"
	case ActionUserRemoved:
		return "User removed"
	case ActionUserRenamed:
		return "User renamed"
	case ActionMFAEnrolled:
		return "Authenticator registered"
	case ActionMFARemoved:
		return "Authenticator removed"
	case ActionMFAFailed:
		return "Two-factor attempts exhausted"
	case ActionMFARecoveryUsed:
		return "Recovery code used"
	case ActionMFARecoveryRegenerated:
		return "Recovery codes regenerated"
	case ActionPasskeyRegistered:
		return "Passkey registered"
	case ActionPasskeyRemoved:
		return "Passkey removed"
	case ActionPasskeyCloneWarning:
		return "Passkey refused: cloned authenticator"
	case ActionStepUpFailed:
		return "Confirmation failed"
	case ActionOrganizationRenamed:
		return "Organization renamed"
	case ActionEndpointCreated:
		return "SCEP endpoint created"
	case ActionEndpointDeleted:
		return "SCEP endpoint deleted"
	case ActionEndpointEnabled:
		return "SCEP endpoint enabled"
	case ActionEndpointPaused:
		return "SCEP endpoint disabled"
	case ActionEndpointPolicy:
		return "SCEP issuance policy changed"
	case ActionSCEPChallengeIssued:
		return "SCEP challenge issued"
	case ActionSCEPSecretRotated:
		return "SCEP shared secret rotated"
	case ActionSCEPAuthMethodChanged:
		return "SCEP authentication method changed"
	case ActionSCEPJamfConfigured:
		return "Jamf Pro connection configured"
	case ActionSCEPIntuneConnected:
		return "Microsoft Intune connected"
	case ActionSCEPIntuneDisconnected:
		return "Microsoft Intune disconnected"
	case ActionACMEEndpointCreated:
		return "ACME endpoint created"
	case ActionACMEEndpointDeleted:
		return "ACME endpoint deleted"
	case ActionACMEEndpointEnabled:
		return "ACME endpoint enabled"
	case ActionACMEEndpointPaused:
		return "ACME endpoint disabled"
	case ActionACMEEndpointPolicy:
		return "ACME issuance policy changed"
	case ActionACMECredentialIssued:
		return "ACME credential created"
	case ActionACMECredentialRevoked:
		return "ACME credential revoked"
	case ActionESTEndpointCreated:
		return "EST endpoint created"
	case ActionESTEndpointDeleted:
		return "EST endpoint deleted"
	case ActionESTEndpointEnabled:
		return "EST endpoint enabled"
	case ActionESTEndpointPaused:
		return "EST endpoint disabled"
	case ActionESTEndpointPolicy:
		return "EST issuance policy changed"
	case ActionESTCredentialIssued:
		return "EST credential created"
	case ActionESTCredentialRevoked:
		return "EST credential revoked"
	case ActionRootCACreated:
		return "Root CA created"
	case ActionIssuingCACreated:
		return "Issuing CA created"
	case ActionCAImported:
		return "CA imported"
	case ActionCADeleted:
		return "CA deleted"
	case ActionCAActivated:
		return "CA activated"
	case ActionCADeactivated:
		return "CA deactivated"
	case ActionCARetired:
		return "CA retired"
	case ActionCARotated:
		return "CA rotated"
	case ActionCertificateIssued:
		return "Certificate issued"
	case ActionCertificateRevoked:
		return "Certificate revoked"
	}
	return "Other activity"
}

// Actions is every action the filter offers, in the order it lists them.
var Actions = []string{
	ActionCertificateIssued,
	ActionCertificateRevoked,
	ActionRootCACreated,
	ActionIssuingCACreated,
	ActionCAImported,
	ActionCADeleted,
	ActionCAActivated,
	ActionCADeactivated,
	ActionCARetired,
	ActionCARotated,
	ActionEndpointCreated,
	ActionEndpointEnabled,
	ActionEndpointPaused,
	ActionEndpointPolicy,
	ActionEndpointDeleted,
	ActionSCEPChallengeIssued,
	ActionSCEPSecretRotated,
	ActionSCEPAuthMethodChanged,
	ActionSCEPJamfConfigured,
	ActionSCEPIntuneConnected,
	ActionSCEPIntuneDisconnected,
	ActionACMEEndpointCreated,
	ActionACMEEndpointEnabled,
	ActionACMEEndpointPaused,
	ActionACMEEndpointPolicy,
	ActionACMEEndpointDeleted,
	ActionACMECredentialIssued,
	ActionACMECredentialRevoked,
	ActionESTEndpointCreated,
	ActionESTEndpointEnabled,
	ActionESTEndpointPaused,
	ActionESTEndpointPolicy,
	ActionESTEndpointDeleted,
	ActionESTCredentialIssued,
	ActionESTCredentialRevoked,
	ActionUserInvited,
	ActionUserInvitationRevoked,
	ActionUserRoleChanged,
	ActionUserRemoved,
	ActionUserRenamed,
	ActionOrganizationRenamed,
	ActionSignedIn,
	ActionSignedOut,
	ActionMFAEnrolled,
	ActionMFARemoved,
	ActionMFAFailed,
	ActionMFARecoveryUsed,
	ActionMFARecoveryRegenerated,
	ActionPasskeyRegistered,
	ActionPasskeyRemoved,
	ActionPasskeyCloneWarning,
	ActionStepUpFailed,
	ActionOther,
}

// The signing audit's purpose column is mapped onto these actions in SQL — see
// unionEvents in repo.go — so that one filter applies to both event sources.
// Several purposes collapse onto certificate.issued: they are the same event to
// a reader and differ only in which form produced them.
