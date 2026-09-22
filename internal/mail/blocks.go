package mail

import (
	"html"
	"strconv"
	"strings"
)

// The pieces a message is built from. Keeping them here gives action messages
// and operational notices one definition of each visual element.
//
// Every one takes plain text and escapes it. The values passed through these are
// certificate subjects and organization names. Both are attacker-controlled in
// the sense that matters, and a subject containing a tag must arrive as text
// rather than as markup.
//
// Spacing is padding-bottom on the block itself rather than a margin, because
// Outlook's Word engine drops margins on block elements and would run every
// paragraph in a message together.

// heading is the one-line statement of what a message is.
func heading(s string) string {
	return `<div style="padding-bottom:12px;font-family:` + fontStack +
		`;font-size:20px;font-weight:700;line-height:1.3;letter-spacing:-0.015em;color:` +
		colorText + `;">` + html.EscapeString(s) + `</div>`
}

// paragraph is body copy.
func paragraph(s string) string {
	return `<div style="padding-bottom:20px;font-family:` + fontStack +
		`;font-size:15px;line-height:1.55;color:` + colorMutedText + `;">` +
		html.EscapeString(s) + `</div>`
}

// note is the small print: an expiry, a reassurance, a caveat. Same colour as
// body copy but smaller, which is the application's own convention for the
// difference between what you are reading and what you are checking.
func note(s string) string {
	return `<div style="padding-bottom:8px;font-family:` + fontStack +
		`;font-size:13px;line-height:1.5;color:` + colorMutedText + `;">` +
		html.EscapeString(s) + `</div>`
}

// divider is the rule above the closing lines of a message.
func divider() string {
	return `<div style="padding-top:8px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>` +
		`<td height="1" style="height:1px;line-height:1px;font-size:1px;background-color:` + colorBorder + `;">&nbsp;</td>` +
		`</tr></table></div>`
}

// button is the one thing a message is asking to be done.
//
// Two renderings of the same control. The anchor is the real one; the VML
// roundrect is for Outlook's desktop clients, which render through Word and
// support neither padding on an inline-block nor border-radius — without it the
// call to action in the sign-in mail degrades to an underlined blue link in a
// message that has one job.
//
// The VML needs a width in pixels because Word will not size a shape to its
// content. It is estimated from the label, which is approximate by construction:
// a little generous is a wider button, a little mean is a wrapped one, so the
// estimate errs high.
func button(label, url string) string {
	width := strconv.Itoa(len(label)*9 + 52)
	safeURL, safeLabel := html.EscapeString(url), html.EscapeString(label)
	var b strings.Builder
	b.WriteString(`<div style="padding-bottom:20px;">`)
	b.WriteString(`<!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="` +
		safeURL + `" style="height:44px;v-text-anchor:middle;width:` + width +
		`px;" arcsize="23%" stroke="f" fillcolor="` + colorPrimary + `"><w:anchorlock/><center style="color:` +
		colorOnPrimary + `;font-family:` + fontStack + `;font-size:15px;font-weight:600;">` +
		safeLabel + `</center></v:roundrect><![endif]-->`)
	// The comment pair below hides the anchor from Outlook and nothing else, so
	// the two renderings never both appear.
	b.WriteString(`<!--[if !mso]><!-->`)
	b.WriteString(`<a href="` + safeURL + `" style="display:inline-block;background-color:` + colorPrimary +
		`;color:` + colorOnPrimary + `;text-decoration:none;font-family:` + fontStack +
		`;font-size:15px;font-weight:600;line-height:20px;padding:12px 22px;border-radius:` +
		radiusButton + `;">` + safeLabel + `</a>`)
	b.WriteString(`<!--<![endif]-->`)
	b.WriteString(`</div>`)
	return b.String()
}

// linkFallback prints the destination in full beneath the button.
//
// A client that strips the anchor, a corporate gateway that rewrites it into
// something unrecognisable, a plain-text preference — in all three the button is
// gone and this is the only way in. For a service whose sole means of signing in
// is a link in an email, that is the difference between a cosmetic failure and a
// locked-out user.
func linkFallback(url string) string {
	return `<div style="padding-bottom:24px;font-family:` + fontStack +
		`;font-size:13px;line-height:1.5;color:` + colorMutedText + `;">Or paste this into your browser:<br>` +
		`<span style="word-break:break-all;color:` + colorLink + `;">` + html.EscapeString(url) + `</span></div>`
}

// dataTable is a grid of values, for the certificate expiry alert.
//
// A real <table> rather than a stack of divs, because this is tabular data and
// because Outlook lays out nothing else reliably. The header row is the
// application's own label treatment — small, uppercase, letter-spaced, muted —
// so the alert reads as a page of the dashboard rather than as a mail merge.
//
// mono marks the columns holding values a person reads character by character; a
// serial in a proportional font makes 1 and l the same shape.
func dataTable(headers []string, rows [][]string, mono map[int]bool) string {
	var b strings.Builder
	b.WriteString(`<div style="padding-bottom:20px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;border-collapse:collapse;">`)
	b.WriteString(`<tr>`)
	for _, h := range headers {
		b.WriteString(`<td bgcolor="` + colorSecondary + `" style="background-color:` + colorSecondary +
			`;padding:8px 10px;font-family:` + fontStack +
			`;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:` +
			colorMutedText + `;text-align:left;white-space:nowrap;">` + html.EscapeString(h) + `</td>`)
	}
	b.WriteString(`</tr>`)
	for _, row := range rows {
		b.WriteString(`<tr>`)
		for i, cell := range row {
			font := fontStack
			if mono[i] {
				font = monoStack
			}
			// The first column is the identifier — a certificate subject, which can
			// be a long FQDN or a full DN — and is the only one allowed to wrap. The
			// rest are short values whose meaning depends on staying whole: a serial
			// broken across two lines cannot be pasted into a search box, and a date
			// wrapped between the day and the year reads as two columns.
			wrap := "white-space:nowrap;"
			if i == 0 {
				wrap = ""
			}
			b.WriteString(`<td style="padding:9px 10px;border-bottom:1px solid ` + colorBorder +
				`;font-family:` + font + `;font-size:13px;line-height:1.4;color:` + colorText +
				`;text-align:left;` + wrap + `">` + html.EscapeString(cell) + `</td>`)
		}
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</table></div>`)
	return b.String()
}

// panel is an inset block of label/value pairs, modelled on the application's
// Info component: a small uppercase label above the value it names.
func panel(pairs [][2]string) string {
	var b strings.Builder
	b.WriteString(`<div style="padding-bottom:20px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;">`)
	b.WriteString(`<tr><td bgcolor="` + colorPanel + `" style="background-color:` + colorPanel +
		`;border:1px solid ` + colorBorder + `;border-radius:` + radiusPanel + `;padding:14px 16px;">`)
	for i, pair := range pairs {
		top := "10px"
		if i == 0 {
			top = "0"
		}
		b.WriteString(`<div style="padding-top:` + top + `;font-family:` + fontStack +
			`;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:` +
			colorMutedText + `;">` + html.EscapeString(pair[0]) + `</div>`)
		b.WriteString(`<div style="padding-top:2px;font-family:` + fontStack +
			`;font-size:14px;line-height:1.45;color:` + colorText + `;">` + html.EscapeString(pair[1]) + `</div>`)
	}
	b.WriteString(`</td></tr></table></div>`)
	return b.String()
}

// quote renders operator-provided preformatted text while preserving line breaks.
func quote(s string) string {
	return `<div style="padding-bottom:20px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;"><tr>` +
		`<td bgcolor="` + colorPanel + `" style="background-color:` + colorPanel +
		`;border-left:3px solid ` + colorAccent + `;border-radius:0 ` + radiusPanel + ` ` + radiusPanel +
		` 0;padding:14px 16px;font-family:` + fontStack + `;font-size:14px;line-height:1.55;color:` +
		colorText + `;white-space:pre-wrap;">` + html.EscapeString(s) + `</td></tr></table></div>`
}
