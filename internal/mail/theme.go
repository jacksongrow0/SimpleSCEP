package mail

// The email palette.
//
// This is light, and that is a decision made against evidence rather than a
// preference. Two dark versions shipped before it: one using the application's
// own surface tokens, one neutral charcoal. Both arrived in a real client as a
// grey wash — a "hazy overlay" over the whole message, with the cyan button
// dulled to teal and the near-white text sunk to mid-grey.
//
// The cause is the client's own dark-mode transform. Outlook and Gmail both
// remap the colours of a message to fit their scheme, and they are tuned for the
// case that is almost every message they handle: a light email being darkened.
// Handed a design that is already dark, the transform has nothing to inver and
// lands somewhere between the two, which is the mud. Declaring
// color-scheme: dark does not opt out of it — that is a hint the transform is
// free to ignore, and in Outlook it does.
//
// The one lever clients actually honour is "only light", and it only means
// anything on a light design. So the surfaces are light and the message says it
// supports nothing else. What carries the brand instead of the dark ground is
// the mark, the navy button and the teal from the logo's own gradient.
//
// The dashboard is still dark, and an email that does not match it is the
// correct trade: a message that renders as designed in every client beats one
// that matches a screenshot and turns to mud in the client the customer uses.
const (
	colorPage      = "#eef1f5" // the ground the card sits on
	colorCard      = "#ffffff" // the card itself
	colorBorder    = "#dde2e8" // card, table and panel edges
	colorText      = "#0d1b2a" // headings and values, 16.9:1 on the card
	colorMutedText = "#5b6672" // body copy and small print, 6.0:1 on the card
	colorSecondary = "#f4f6f8" // the table's header row
	colorPanel     = "#f7f9fb" // the ground for inset blocks

	// colorPrimary is the button's fill and colorOnPrimary its label. On a light
	// ground the brand cyan cannot be the fill — #44e1f9 behind dark text is a
	// glare on white, and behind white text it fails contrast outright. Inverting
	// the pair gives the button the dashboard's own navy with the cyan as its
	// label, which is both legible and unmistakably this product.
	colorPrimary   = "#0b1928" // the button fill
	colorOnPrimary = "#44e1f9" // --primary oklch(0.84 0.13 210), the button label

	// colorLink is for text links, which cannot use the brand cyan either:
	// #44e1f9 on white is 1.4:1 and effectively invisible. This is the darkest
	// stop of the logo's own gradient, so it is the brand's blue rather than a
	// generic one, and it clears AA on both the card and the page.
	colorLink = "#126b9d"

	// colorAccent is the logo gradient's teal, used where a rule or a marker
	// needs to read as ours rather than as a border: the bar down the side of a
	// quoted diagnostic detail.
	colorAccent = "#11b5b4"

	// fontStack is the application's own, from input.css:138. No web font: a
	// @font-face or a Google Fonts <link> is stripped by Gmail and ignored by
	// Outlook.
	//
	// The multi-word families are quoted with apostrophes, not double quotes.
	// Every one of these lands inside a style="..." attribute, so a double quote
	// closes the attribute early — the browser then reads the rest of the
	// declaration as a run of bogus attributes and drops every style after the
	// font, which in practice means an unstyled message. input.css can write
	// "Segoe UI" because a stylesheet is not inside an attribute; here it cannot.
	fontStack = `ui-sans-serif,system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif`

	// monoStack is for serials and fingerprints — values a person reads character
	// by character, where a proportional font makes 1/l and 0/O the same shape.
	monoStack = `ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace`
)

// The radii, all derived from --radius: 0.75rem the way the Tailwind theme
// derives them, so a card in an email is the same shape as a card in the app.
// Unlike the colours above these do still track the theme, because shape reads
// as brand at any tone.
//
// Outlook's desktop clients render through Word, which does not implement
// border-radius at all: every one of these is square there. That is a graceful
// loss rather than a broken layout, and it is not worth the VML scaffolding it
// would take to fix for anything except the button, which is the one element
// whose shape carries meaning.
const (
	radiusCard   = "16px" // rounded-xl,  calc(0.75rem + 4px)
	radiusPanel  = "12px" // rounded-lg,  var(--radius)
	radiusButton = "10px" // rounded-md,  calc(0.75rem - 2px)
)
