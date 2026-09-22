package mail

import (
	"strings"
	"unicode"
)

// Action builds a transactional message with one thing to do.
//
// Every message this service sent used to be a bare anchor tag and nothing else:
//
//	<a href="...">Verify your email and open SimpleSCEP</a>
//
// That was the whole body of the verification, sign-in and invitation emails —
// no greeting, no sender identity, no statement of how long the link lasts, no
// "if you did not ask for this", and no plain-text part. For a product whose only
// way in is a magic link, that is a deliverability problem before it is a
// presentation one, and it reads to a careful recipient exactly like phishing:
// an unexplained link from a name they may not recognise.
//
// What replaced it was a card, and the card was off-brand: a white panel on a
// light grey ground with a #3b5bdb indigo button, none of which appears anywhere
// in the product. SimpleSCEP is dark-only — input.css sets color-scheme: dark and
// gives :root and .dark identical values — so a recipient who pressed that button
// went from a light email to a near-black dashboard. It now renders in the
// application's own palette; see theme.go for where each colour comes from.
//
// The layout is still deliberately plain. Inline styles, tables, no images and no
// web fonts — every one of those is a rendering variable across Outlook, Gmail's
// clipper and Apple Mail, and none of them is worth a broken sign-in. The URL is
// also printed in full beneath the button, because a client that strips the
// anchor still leaves the person something to copy.
type Action struct {
	// Heading is the one-line statement of what this message is.
	Heading string
	// Body is the sentence or two before the button. Plain text; it is escaped.
	Body string
	// ButtonLabel is the imperative on the button.
	ButtonLabel string
	// URL is where the button goes.
	URL string
	// Expiry describes how long the link works, e.g. "15 minutes". Rendered as
	// "This link expires in 15 minutes." and omitted when empty — a link with no
	// stated lifetime is one people sit on until it stops working.
	Expiry string
	// Unrequested is the reassurance line, e.g. "If you did not request this, you
	// can ignore this email." Omitted when empty.
	Unrequested string
	// Preheader overrides the hidden line shown beside the subject in an inbox
	// listing. Optional: left empty it is taken from Body, which is what the
	// message is about and so is nearly always the right preview. Set it when the
	// first sentence of Body is not the best inbox preview.
	Preheader string
}

// Render returns the HTML body and the plain-text alternative.
func (a Action) Render() (body, text string) {
	var c strings.Builder
	c.WriteString(heading(a.Heading))
	c.WriteString(paragraph(a.Body))
	c.WriteString(button(a.ButtonLabel, a.URL))
	c.WriteString(linkFallback(a.URL))
	if a.Expiry != "" {
		c.WriteString(note("This link expires in " + a.Expiry + "."))
	}
	if a.Unrequested != "" {
		c.WriteString(note(a.Unrequested))
	}
	body = Shell{Preheader: a.preheader()}.Render(c.String())

	var t strings.Builder
	t.WriteString(a.Heading + "\n\n")
	t.WriteString(a.Body + "\n\n")
	t.WriteString(a.ButtonLabel + ":\n" + a.URL + "\n")
	if a.Expiry != "" {
		t.WriteString("\nThis link expires in " + a.Expiry + ".\n")
	}
	if a.Unrequested != "" {
		t.WriteString("\n" + a.Unrequested + "\n")
	}
	t.WriteString(footerText())
	return body, t.String()
}

// preheader is the explicit one when there is one, and the opening of Body
// otherwise.
func (a Action) preheader() string {
	if strings.TrimSpace(a.Preheader) != "" {
		return a.Preheader
	}
	return truncate(a.Body, 110)
}

// truncate cuts at a word boundary, because a preview line ending mid-word reads
// as a message that was itself cut off.
func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	cut := strings.LastIndexFunc(s[:max], unicode.IsSpace)
	if cut <= 0 {
		cut = max
	}
	return strings.TrimRight(s[:cut], " ,.;:") + "…"
}

// Message turns an Action into a sendable message.
func (a Action) Message(to, subject string) Message {
	body, text := a.Render()
	return Message{To: to, Subject: subject, Body: body, Text: text}
}
