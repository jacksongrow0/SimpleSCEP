// Package mail is the transport-independent seam for outbound email. The
// Sender interface is what internal/resend implements and what tests
// substitute; Service holds the one rule that applies whatever the transport.
package mail

import (
	"context"
	"errors"
)

var ErrInvalidMessage = errors.New("to, subject, and body are required")

type Message struct {
	To      string
	Subject string
	Body    string
	// From overrides the envelope this message is sent under.
	//
	// Everything uses the operator-configured sender unless a message explicitly
	// overrides it.
	//
	// Optional, and it must be an address on a domain verified with the mail
	// provider — an unverified sender does not bounce, it lands in spam. Empty
	// means the transport's configured envelope, which is what almost everything
	// wants.
	From string
	// ReplyTo is who a reply should reach, when that is not the envelope this
	// service sends under. Notifications use the optional operator-configured
	// reply address; authentication messages deliberately omit it.
	ReplyTo string
	// Text is the plain-text alternative, sent alongside Body as a multipart
	// message.
	//
	// Every message used to be HTML only, and for the sign-in link that is a
	// deliverability problem rather than a presentation one: a single anchor tag
	// with no text part is one of the strongest spam signals there is, and the
	// only way into this service is a magic link. A message that lands in spam
	// looks exactly like login being broken.
	//
	// Optional. A message that sets only Body still sends, so nothing that has
	// not been given a text alternative regresses.
	Text string
}

type Sender interface {
	Send(context.Context, Message) error
}

type Service struct {
	sender Sender
}

func NewService(sender Sender) Service {
	return Service{sender: sender}
}

// Send rejects an incomplete message before it reaches the transport, so a
// provider is never asked to deliver something it would only reject later and
// less legibly.
func (s Service) Send(ctx context.Context, msg Message) error {
	if msg.To == "" || msg.Subject == "" || msg.Body == "" {
		return ErrInvalidMessage
	}
	return s.sender.Send(ctx, msg)
}
