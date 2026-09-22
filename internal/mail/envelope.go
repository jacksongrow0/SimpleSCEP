package mail

import (
	"os"
	"strings"
)

// Envelope is a named mailbox this service sends under.
//
// It applies the operator-configured sender and, for notifications, the optional
// operator-configured reply address.
type Envelope struct {
	// ReplyToEnv optionally names the environment variable that provides the
	// destination for replies to this class of message.
	ReplyToEnv string
}

// The envelopes. Each display name is load-bearing: in an inbox listing it is
// what separates an automated warning from an authentication message.
var (
	// NoReply carries authentication mail: the sign-in link and the address
	// verification. It has no ReplyTo deliberately because a reply to a sign-in
	// link is meaningless.
	NoReply = Envelope{}

	// Notifications carries automated notices about an organization's
	// infrastructure: certificates approaching expiry, and invitations to join an
	// organization.
	//
	// Operators may route replies to a monitored address with MAIL_REPLY_TO.
	Notifications = Envelope{ReplyToEnv: "MAIL_REPLY_TO"}
)

// From is the address to send under.
//
// The value must be verified in the operator's Resend account.
func (e Envelope) From() string {
	return strings.TrimSpace(os.Getenv("MAIL_FROM"))
}

// Apply stamps the envelope onto a message, leaving anything the caller set
// alone. A message that already names its own ReplyTo keeps it.
func (e Envelope) Apply(msg Message) Message {
	if strings.TrimSpace(msg.From) == "" {
		msg.From = e.From()
	}
	if strings.TrimSpace(msg.ReplyTo) == "" && e.ReplyToEnv != "" {
		msg.ReplyTo = strings.TrimSpace(os.Getenv(e.ReplyToEnv))
	}
	return msg
}
