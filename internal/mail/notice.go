package mail

import (
	"strings"
	"unicode/utf8"
)

// Notice is a transactional message that reports something.
//
// Action covers messages with exactly one thing to do, such as signing in or
// accepting an invitation. Notice covers operational reports such as a
// certificate expiry alert, with any link as a secondary offer.
//
// The field order is the render order. It is fixed rather than a list of
// arbitrary blocks because there are two callers and both want the same shape:
// say what happened, show the detail, offer the link, then the small print.
type Notice struct {
	// Heading is the one-line statement of what this message is.
	Heading string
	// Preheader is the hidden line shown beside the subject. Taken from the first
	// Body paragraph when empty.
	Preheader string
	// Body is the opening prose, one entry per paragraph.
	Body []string
	// Table is a grid of values — the expiring certificates. Omitted when Headers
	// is empty.
	Table Table
	// Panel is a block of label/value pairs for structured detail.
	Panel [][2]string
	// Quote is text played back to the recipient, rendered with their line breaks
	// intact. Omitted when empty.
	Quote string
	// Link is the offer at the end. Optional: unlike an Action, a Notice is
	// complete without one.
	Link Link
	// Notes are the closing small print, one entry per line.
	Notes []string
}

// Table is a grid of values inside a Notice.
type Table struct {
	Headers []string
	Rows    [][]string
	// Mono marks column indexes holding values read character by character —
	// serials, fingerprints — which are set in a monospace face so that 1 and l
	// are not the same shape.
	Mono map[int]bool
}

// Link is a Notice's call to action.
type Link struct {
	Label string
	URL   string
}

// Render returns the HTML body and the plain-text alternative.
func (n Notice) Render() (body, text string) {
	var c strings.Builder
	c.WriteString(heading(n.Heading))
	for _, p := range n.Body {
		c.WriteString(paragraph(p))
	}
	if len(n.Table.Headers) > 0 {
		c.WriteString(dataTable(n.Table.Headers, n.Table.Rows, n.Table.Mono))
	}
	if len(n.Panel) > 0 {
		c.WriteString(panel(n.Panel))
	}
	if n.Quote != "" {
		c.WriteString(quote(n.Quote))
	}
	if n.Link.URL != "" {
		c.WriteString(button(n.Link.Label, n.Link.URL))
	}
	if len(n.Notes) > 0 {
		c.WriteString(divider())
		for _, s := range n.Notes {
			c.WriteString(`<div style="padding-top:12px;"></div>` + note(s))
		}
	}
	return Shell{Preheader: n.preheader()}.Render(c.String()), n.text()
}

func (n Notice) preheader() string {
	if strings.TrimSpace(n.Preheader) != "" {
		return n.Preheader
	}
	if len(n.Body) > 0 {
		return truncate(n.Body[0], 110)
	}
	return n.Heading
}

// text is the plain-text alternative.
//
// It is written out rather than derived by stripping tags from the HTML, because
// a stripped table is every cell on its own line with nothing saying which
// column it came from — which for the expiry alert is a list of dates and
// serials in no stated relation to each other.
func (n Notice) text() string {
	var t strings.Builder
	t.WriteString(n.Heading + "\n\n")
	for _, p := range n.Body {
		t.WriteString(p + "\n\n")
	}
	if len(n.Table.Headers) > 0 {
		t.WriteString(textTable(n.Table) + "\n")
	}
	for _, pair := range n.Panel {
		t.WriteString(pair[0] + ": " + pair[1] + "\n")
	}
	if len(n.Panel) > 0 {
		t.WriteString("\n")
	}
	if n.Quote != "" {
		for _, line := range strings.Split(n.Quote, "\n") {
			t.WriteString("> " + line + "\n")
		}
		t.WriteString("\n")
	}
	if n.Link.URL != "" {
		t.WriteString(n.Link.Label + ":\n" + n.Link.URL + "\n")
	}
	for _, s := range n.Notes {
		t.WriteString("\n" + s + "\n")
	}
	t.WriteString(footerText())
	return t.String()
}

// textTable lays the grid out in fixed-width columns, so the plain-text part
// carries the same relationships the HTML one does. Widths are measured in runes
// rather than bytes: a certificate subject can hold anything an enrollee put in a
// CSR, and counting bytes would misalign every row containing one.
func textTable(tbl Table) string {
	widths := make([]int, len(tbl.Headers))
	for i, h := range tbl.Headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range tbl.Rows {
		for i, cell := range row {
			if i < len(widths) && utf8.RuneCountInString(cell) > widths[i] {
				widths[i] = utf8.RuneCountInString(cell)
			}
		}
	}
	var b strings.Builder
	writeRow := func(cells []string) {
		parts := make([]string, 0, len(cells))
		for i, cell := range cells {
			pad := 0
			if i < len(widths) {
				pad = widths[i] - utf8.RuneCountInString(cell)
			}
			if i == len(cells)-1 {
				parts = append(parts, cell)
				continue
			}
			parts = append(parts, cell+strings.Repeat(" ", pad))
		}
		b.WriteString(strings.Join(parts, "  ") + "\n")
	}
	writeRow(tbl.Headers)
	rule := make([]string, len(widths))
	for i, w := range widths {
		rule[i] = strings.Repeat("-", w)
	}
	b.WriteString(strings.Join(rule, "  ") + "\n")
	for _, row := range tbl.Rows {
		writeRow(row)
	}
	return b.String()
}

// Message turns a Notice into a sendable message.
func (n Notice) Message(to, subject string) Message {
	body, text := n.Render()
	return Message{To: to, Subject: subject, Body: body, Text: text}
}
