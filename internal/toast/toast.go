// Package toast carries a one-sentence message from a handler to the shell that
// renders it.
//
// It holds the message type and nothing else — no cookie code, no HTTP. That is
// deliberate and load-bearing: view/layout has to read the pending message, and
// view/layout → internal/auth → view/auth → view/layout is an import cycle. Any
// package that reaches for the signing secret would drag that cycle in behind
// it, so the browser plumbing lives in internal/web instead, which nothing under
// view/ imports.
package toast

import (
	"context"
	"strings"
	"unicode/utf8"
)

// Tone selects how a toast is coloured and how long it stays. It mirrors the
// tones view/components already defines for pills, and the --color-success /
// --color-warning / --color-destructive tokens in input.css.
type Tone string

const (
	Success Tone = "success"
	Error   Tone = "error"
	Warning Tone = "warning"
	Info    Tone = "info"
)

// MaxText bounds a message. A toast is one sentence read in passing; anything
// longer belongs in the inline result element beside the form that produced it,
// where it can be read at leisure. The bound also keeps a message that rides an
// HX-Trigger header from growing one.
const MaxText = 200

// Message is what a handler raises and the shell renders.
type Message struct {
	Tone Tone   `json:"tone"`
	Text string `json:"text"`
}

// New normalises a message. An unrecognised tone becomes Info rather than an
// unstyled toast, and over-long text is cut at a rune boundary so a truncated
// multi-byte character cannot reach the page.
func New(tone Tone, text string) Message {
	switch tone {
	case Success, Error, Warning, Info:
	default:
		tone = Info
	}
	text = strings.TrimSpace(text)
	if utf8.RuneCountInString(text) > MaxText {
		runes := []rune(text)
		text = strings.TrimSpace(string(runes[:MaxText-1])) + "…"
	}
	return Message{Tone: tone, Text: text}
}

// Valid reports whether there is anything worth showing. An empty message is
// treated as no message everywhere rather than rendering an empty toast.
func (m Message) Valid() bool { return m.Text != "" }

type contextKey struct{}

// WithMessage attaches a message to the request, for the shell to render on the
// page this request is about to produce.
func WithMessage(ctx context.Context, m Message) context.Context {
	return context.WithValue(ctx, contextKey{}, m)
}

// FromContext returns the message this request carries, if any.
func FromContext(ctx context.Context) (Message, bool) {
	m, ok := ctx.Value(contextKey{}).(Message)
	return m, ok && m.Valid()
}
