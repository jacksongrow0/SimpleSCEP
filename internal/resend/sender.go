package resend

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/jacksongrow0/SimpleSCEP/internal/mail"
	"github.com/resend/resend-go/v2"
)

type Sender struct {
	APIKey string
	From   string
	Client *http.Client
}

// NewSender returns a Sender posting to Resend under the deployment's verified
// sender. Startup validates from before constructing the sender.
func NewSender(apiKey, from string) Sender {
	return Sender{APIKey: apiKey, From: from, Client: http.DefaultClient}
}

// Send delivers one message through Resend.
//
// A provider failure is returned, not panicked. It used to panic, which was
// survivable only because every caller ran inside a request that
// middleware.Recover wrapped: a rejected address turned into a 500 and the
// process carried on. That stopped being true when the sign-in path started
// mailing asynchronously — a panic in a detached goroutine has no recover above
// it and takes the whole server down, so one malformed address would be a
// denial of service on the entire service.
//
// The signature already said this returned an error; only the body disagreed.
// envelope prefers the message's own From, falling back to the transport's.
func envelope(messageFrom, senderFrom string) string {
	if from := strings.TrimSpace(messageFrom); from != "" {
		return from
	}
	return senderFrom
}

func (s Sender) Send(ctx context.Context, msg mail.Message) error {
	client := resend.NewClient(s.APIKey)

	params := &resend.SendEmailRequest{
		To: []string{msg.To},
		// The message's own envelope when it names one, so an automated notice can
		// use a different mailbox from authentication mail. See mail.Message.From.
		From:    envelope(msg.From, s.From),
		Subject: msg.Subject,
		// Set only when asked for. Resend treats an empty ReplyTo as a header to
		// omit rather than an error, but leaving it off entirely keeps the request
		// the same shape it has always been for the messages that do not need one.
		ReplyTo: msg.ReplyTo,
		Html:    msg.Body,
		// Sent alongside the HTML rather than instead of it, which makes the
		// message multipart/alternative. A mail client that prefers text gets
		// something readable, and — the reason this matters more than presentation
		// — an HTML-only message consisting of one anchor tag scores badly with
		// every spam filter worth the name. The only way into this service is a
		// magic link, so a message in the spam folder is indistinguishable from
		// login being broken.
		//
		// Empty for anything that has not been given a text alternative; Resend
		// omits the part rather than sending an empty one.
		Text: msg.Text,
	}

	if _, err := client.Emails.SendWithContext(ctx, params); err != nil {
		return fmt.Errorf("sending mail via Resend: %w", err)
	}
	return nil
}
