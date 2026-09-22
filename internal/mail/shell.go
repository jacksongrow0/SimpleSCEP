package mail

import (
	"html"
	"os"
	"strings"
)

// contentWidth is the card's maximum width.
//
// 600px because that is what Outlook's default reading pane fits without
// horizontal scrolling, and because the expiry alert puts a four-column table
// inside this — at the 520px the first version of this template used, the serial
// column wrapped mid-value on every row.
const contentWidth = "600"

// Shell is the branded chrome every user-facing message renders inside.
//
// The whole document is built here rather than composed from a template file
// because email HTML is not HTML: it is a subset that differs per client, and
// every constraint below is a client working around the standard rather than a
// stylistic choice.
type Shell struct {
	// Preheader is the hidden line a mail client shows next to the subject in an
	// inbox listing.
	//
	// Left unset, clients take the first visible text in the document instead,
	// which here is the wordmark — so every message previewed as "SimpleSCEP
	// SimpleSCEP" and the recipient had to open it to learn what it was. Set, it
	// is the second thing that decides whether the mail gets opened.
	Preheader string
}

// Render wraps a content fragment in the chrome and returns a whole document.
func (s Shell) Render(content string) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en" style="color-scheme:only light;supported-color-schemes:light;"><head>`)
	b.WriteString(`<meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	// "only light" is the strongest available instruction to a client not to apply
	// its own dark-mode transform, and it is the reason this design is light at
	// all. Two dark versions arrived in a real client as a grey wash, because
	// Outlook and Gmail remap a message's colours to fit their scheme and
	// declaring color-scheme: dark does not opt out — it is a hint they are free
	// to ignore, and Outlook does. "only light" is the one they honour.
	b.WriteString(`<meta name="color-scheme" content="only light">`)
	b.WriteString(`<meta name="supported-color-schemes" content="light">`)
	// Outlook renders through Word at 120dpi unless told otherwise, which scales
	// every pixel dimension in the document by 1.25 and turns a 600px card into a
	// 750px one that overflows the reading pane.
	b.WriteString(`<!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]-->`)
	// This block is a hint, never a source of colour. Gmail strips <head> from
	// every message it renders, so anything that only appears here is absent for
	// the largest client there is — which is why every element below carries its
	// own inline style as well.
	b.WriteString(`<style>:root{color-scheme:only light;supported-color-schemes:light;}`)
	b.WriteString(`body{margin:0;padding:0;width:100%!important;}`)
	b.WriteString(`a{color:` + colorLink + `;}`)
	b.WriteString(`@media (max-width:620px){.pad{padding:24px!important;}}`)
	b.WriteString(`</style></head>`)
	b.WriteString(`<body style="margin:0;padding:0;width:100%;background-color:` + colorPage + `;">`)
	b.WriteString(s.preheader())
	// The page ground comes from a table rather than from <body>, because Outlook
	// desktop ignores a background on <body> entirely and would render this card
	// on white. bgcolor as well as the inline style for the same reason: the
	// attribute is the older of the two and the one the Word engine honours most
	// reliably.
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + colorPage + `" style="width:100%;background-color:` + colorPage + `;">`)
	b.WriteString(`<tr><td align="center" bgcolor="` + colorPage + `" style="background-color:` + colorPage + `;padding:32px 12px;">`)
	b.WriteString(`<table role="presentation" width="` + contentWidth + `" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:` + contentWidth + `px;">`)
	b.WriteString(`<tr><td class="pad" bgcolor="` + colorCard + `" style="background-color:` + colorCard + `;border:1px solid ` + colorBorder + `;border-radius:` + radiusCard + `;padding:32px;font-family:` + fontStack + `;color:` + colorText + `;">`)
	b.WriteString(wordmark())
	b.WriteString(content)
	b.WriteString(`</td></tr>`)
	b.WriteString(footer())
	b.WriteString(`</table></td></tr></table></body></html>`)
	return b.String()
}

// preheader is the hidden preview line, followed by padding.
//
// The padding is not decorative. A client takes as much text as it needs to fill
// the preview strip, so a short preheader is topped up with whatever visible copy
// comes next — the wordmark, then the heading, run together without spaces. The
// entities are a figure space and a zero-width non-joiner: both render as nothing,
// and neither collapses the way a plain &nbsp; run does.
func (s Shell) preheader() string {
	if strings.TrimSpace(s.Preheader) == "" {
		return ""
	}
	return `<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:` + colorPage + `;opacity:0;">` +
		html.EscapeString(s.Preheader) +
		strings.Repeat("&#8199;&#65279;", 60) +
		`</div>`
}

// wordmarkFile is the logo as the mail can actually use it.
//
// The mark this product ships is an SVG, and no mail client of consequence
// renders SVG: Gmail, Outlook and Apple Mail all drop it. So it is exported to a
// PNG at twice its display size, for the same reason the application serves a 2x
// asset — a wordmark at 1x on a retina display is visibly soft, and softness in
// the one element carrying the brand is worse than no image.
//
// Transparent rather than flattened onto the card colour, so that changing the
// card does not silently leave the logo sitting on a rectangle of the old one.
const (
	wordmarkFile   = "/assets/logos/horizontal-dark.png"
	wordmarkWidth  = "176"
	wordmarkHeight = "27"
)

// wordmark is the sender's identity at the top of the card.
//
// The image is the mark, and the alt text is the fallback — and the fallback is
// the part that matters. Images are blocked by default for a sender the recipient
// has not corresponded with before, which is every recipient of a first sign-in
// link, so this renders as the word SimpleSCEP more often than it renders as the
// logo. Both have to identify us: a message whose only identification is an image
// that did not load is an unexplained link from a name nobody recognises, which
// is indistinguishable from phishing.
//
// The alt text is styled, which is not decoration — Gmail and Outlook render alt
// text in the colour and weight the img carries, so without this the fallback is
// small blue-black serif type on a dark card, i.e. invisible.
//
// A missing APP_URL leaves the image out entirely rather than emitting a broken
// reference: an img with a relative src in an email resolves against nothing, and
// a broken-image icon is worse than the text it replaced.
func wordmark() string {
	src := wordmarkURL()
	if src == "" {
		return `<div style="padding-bottom:24px;font-family:` + fontStack +
			`;font-size:18px;font-weight:700;letter-spacing:-0.01em;color:` + colorText + `;">SimpleSCEP</div>`
	}
	return `<div style="padding-bottom:24px;line-height:1;">` +
		`<img src="` + src + `" alt="SimpleSCEP" width="` + wordmarkWidth + `" height="` + wordmarkHeight +
		`" style="display:block;border:0;outline:none;text-decoration:none;width:` + wordmarkWidth +
		`px;height:` + wordmarkHeight + `px;font-family:` + fontStack +
		`;font-size:18px;font-weight:700;letter-spacing:-0.01em;color:` + colorText + `;"></div>`
}

// wordmarkURL is the absolute address of the logo.
//
// Absolute because there is no document base in an email to resolve against, and
// read from the environment for the same reason the envelopes are: the host this
// runs on is deployment configuration, and a hard-coded simplescep.com would
// leave every other deployment's mail pointing at ours.
func wordmarkURL() string {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("APP_URL")), "/")
	if base == "" {
		return ""
	}
	return base + wordmarkFile
}

// footer identifies the project. These messages are operational mail from the
// deployment, not mail from a hosted SimpleSCEP service, so they do not link to
// the project's former commercial agreements.
func footer() string {
	return `<tr><td style="padding:20px 10px 0;font-family:` + fontStack + `;font-size:12px;line-height:1.6;color:` + colorMutedText + `;">` +
		`SimpleSCEP &mdash; open-source private PKI` +
		`</td></tr>`
}

// footerText is the plain-text counterpart, so both parts of the message say the
// same things about who sent it.
func footerText() string {
	return "\n--\nSimpleSCEP - open-source private PKI\n"
}
