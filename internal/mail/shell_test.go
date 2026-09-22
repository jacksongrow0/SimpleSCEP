package mail

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"
)

func renderedShell(t *testing.T) string {
	t.Helper()
	return Shell{Preheader: "The first expires 4 Sep 2026."}.Render(
		heading("A certificate expires soon") + paragraph("One certificate expires within 30 days."))
}

// "only light" is the one instruction clients honour about their own dark-mode
// transform, and it is why this design is light. Two dark versions shipped
// before it and both arrived in a real client as a grey wash: Outlook and Gmail
// remap a message's colours to fit their scheme, and color-scheme: dark is a
// hint they are free to ignore.
func TestTheDocumentRefusesTheClientsDarkTransform(t *testing.T) {
	html := renderedShell(t)
	for _, want := range []string{
		`<meta name="color-scheme" content="only light">`,
		`<meta name="supported-color-schemes" content="light">`,
		`color-scheme:only light`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the message does not declare %q, so a client will recolour it", want)
		}
	}
	if strings.Contains(html, `content="dark"`) {
		t.Error("the message still declares a dark scheme, which invites the transform that greyed it out")
	}
}

// Gmail strips <head> from every message it renders, so a colour that appears
// only in the <style> block is absent for the largest mail client there is. This
// is the test that stops somebody moving the palette into a stylesheet and
// shipping a message that renders as unstyled black-on-white for most of its
// recipients.
var tdTag = regexp.MustCompile(`<td[^>]*>`)

func TestEveryCellCarriesItsOwnStyle(t *testing.T) {
	for _, td := range tdTag.FindAllString(renderedShell(t), -1) {
		if !strings.Contains(td, "style=") {
			t.Errorf("a cell relies on the stylesheet Gmail removes: %s", td)
		}
	}
}

// The page ground has to come from a table, and from a bgcolor attribute as well
// as a style. Outlook's desktop clients ignore a background on <body> entirely,
// so without both the dark card is rendered on white.
func TestThePageGroundSurvivesOutlook(t *testing.T) {
	html := renderedShell(t)
	if !strings.Contains(html, `bgcolor="`+colorPage+`"`) {
		t.Error("the page background is not set as a bgcolor attribute; Outlook will render this on white")
	}
	if !strings.Contains(html, `background-color:`+colorPage) {
		t.Error("the page background is not set as an inline style")
	}
}

// The preheader is what an inbox shows beside the subject. Without one the client
// takes the first visible text instead, which is the wordmark — so every message
// previewed as the company name twice and had to be opened to learn what it was.
func TestThePreheaderIsHiddenAndComesFirst(t *testing.T) {
	html := renderedShell(t)
	preheader := strings.Index(html, "The first expires 4 Sep 2026.")
	if preheader < 0 {
		t.Fatal("the preheader is not in the document")
	}
	// Only when the wordmark is text. With APP_URL set — which is every real
	// deployment — wordmark() emits <img alt="SimpleSCEP"> and this substring is
	// absent, and Index returns -1: comparing that against preheader reported the
	// wordmark as coming first in exactly the configuration that ships.
	if wordmark := strings.Index(html, ">SimpleSCEP<"); wordmark >= 0 && wordmark < preheader {
		t.Error("the wordmark precedes the preheader, so it is what the inbox preview will show")
	}
	if !strings.Contains(html, "display:none;max-height:0;overflow:hidden;mso-hide:all") {
		t.Error("the preheader is not hidden, so it will render as the first line of the message")
	}
	// Without the padding the client tops the preview up with whatever visible
	// copy follows, running it into the preheader without a space.
	if !strings.Contains(html, "&#8199;&#65279;&#8199;") {
		t.Error("the preheader is not padded; visible body copy will be pulled into the preview")
	}
}

// An empty preheader emits nothing rather than an empty hidden div, so a caller
// that has nothing useful to preview does not ship a message whose preview line
// is sixty invisible spaces.
func TestAnAbsentPreheaderEmitsNothing(t *testing.T) {
	if strings.Contains(Shell{}.Render(paragraph("hello")), "mso-hide:all") {
		t.Error("an empty preheader still emitted its container")
	}
}

// No images and no web fonts, both for the same reason: they are the two things
// a mail client is most likely to refuse. Images are blocked by default for a
// sender the recipient has not corresponded with — which is every recipient of a
// sign-in link — and a message whose only identification is an image that did not
// load is an unexplained link from a name nobody recognises.
func TestNothingIsFetchedFromTheNetwork(t *testing.T) {
	// The logo is the one deliberate exception, and it is off when APP_URL is
	// unset. This pins that nothing else reaches for the network.
	t.Setenv("APP_URL", "")
	html := renderedShell(t)
	for _, forbidden := range []string{"<img", "fonts.googleapis", "@import", "<link", "background-image"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the message pulls %q from the network; it will not render when that is blocked", forbidden)
		}
	}
}

func TestTheFooterIdentifiesTheOpenSourceProject(t *testing.T) {
	html := renderedShell(t)
	if !strings.Contains(html, "open-source private PKI") {
		t.Error("the footer does not identify the open-source project")
	}
	for _, stale := range []string{"/terms", "/privacy", "managed private PKI"} {
		if strings.Contains(html, stale) {
			t.Errorf("the footer contains hosted-service copy %q", stale)
		}
	}
}

// Every style in these messages lives in a style="..." attribute, so a double
// quote inside one closes the attribute early: the rest of the declaration is
// read as a run of bogus attributes and every style after it is dropped. The
// font stacks are where this bites, because the families that need quoting —
// Segoe UI, Liberation Mono — are exactly the ones a stylesheet writes with
// double quotes, and input.css does. Copying that spelling across renders the
// whole message unstyled.
func TestNoInlineStyleIsTerminatedEarly(t *testing.T) {
	messages := map[string]string{
		"action": func() string { b, _ := testAction().Render(); return b }(),
		"notice": func() string { b, _ := testNotice().Render(); return b }(),
	}
	for name, html := range messages {
		for _, attr := range regexp.MustCompile(`style="[^"]*"`).FindAllString(html, -1) {
			value := strings.TrimSuffix(strings.TrimPrefix(attr, `style="`), `"`)
			// A truncated declaration ends mid-list rather than at a semicolon or
			// a complete value, which is what a stray quote leaves behind.
			if strings.HasSuffix(strings.TrimSpace(value), ",") {
				t.Errorf("%s: a style attribute was cut short: %q", name, attr)
			}
		}
		if strings.Contains(html, `"Segoe`) || strings.Contains(html, `"Liberation`) {
			t.Errorf("%s: a font family is double-quoted inside an attribute, which truncates it", name)
		}
		// The font has to survive as far as the card, or the message renders in
		// the client's default serif.
		if !strings.Contains(html, "'Segoe UI'") {
			t.Errorf("%s: the font stack is missing its quoted family", name)
		}
	}
}

// The card has to be visibly a card. An earlier palette put page and card 1.36x
// apart in luminance, which on a dashboard full of sidebar and dense content is
// enough structure and on a single-card email is none: the message read as one
// wash with no card in it. On a light ground the card is the lighter of the two.
func TestTheCardSeparatesFromThePage(t *testing.T) {
	if contrastRatio(colorCard, colorPage) < 1.1 {
		t.Error("the card and the page are the same tone; the card will not read as a card")
	}
	if relativeLuminance(colorCard) <= relativeLuminance(colorPage) {
		t.Error("the card is darker than the page it sits on")
	}
}

// Every pair of text and the surface behind it clears WCAG AA. The small print
// and the table's 11px labels are the ones that go first when a palette is
// nudged, so they are named individually rather than spot-checked.
func TestEveryTextPairIsReadable(t *testing.T) {
	pairs := []struct {
		fg, bg, what string
	}{
		{colorText, colorCard, "headings on the card"},
		{colorMutedText, colorCard, "body copy on the card"},
		{colorLink, colorCard, "links on the card"},
		{colorOnPrimary, colorPrimary, "the button label"},
		{colorText, colorSecondary, "table values on the header row"},
		{colorMutedText, colorSecondary, "table labels on the header row"},
		{colorText, colorPanel, "quoted text on an inset panel"},
		{colorLink, colorPage, "links on the page ground"},
		{colorMutedText, colorPage, "the footer on the page ground"},
	}
	for _, p := range pairs {
		if got := contrastRatio(p.fg, p.bg); got < 4.5 {
			t.Errorf("%s is %.2f:1, below the 4.5:1 floor", p.what, got)
		}
	}
}

func relativeLuminance(hex string) float64 {
	channel := func(i int) float64 {
		var v int
		if _, err := fmt.Sscanf(hex[i:i+2], "%02x", &v); err != nil {
			panic("malformed colour " + hex)
		}
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(1) + 0.7152*channel(3) + 0.0722*channel(5)
}

func contrastRatio(a, b string) float64 {
	la, lb := relativeLuminance(a), relativeLuminance(b)
	return (math.Max(la, lb) + 0.05) / (math.Min(la, lb) + 0.05)
}

// The logo is a PNG because no mail client of consequence renders the SVG this
// product ships. Images are blocked by default for a sender the recipient has
// not corresponded with before — which is every recipient of a first sign-in
// link — so the alt text is the common case, not the fallback, and it has to be
// styled or it renders as small dark serif type on a dark card.
func TestTheLogoIdentifiesUsWithOrWithoutImages(t *testing.T) {
	t.Setenv("APP_URL", "https://app.example.com/")
	html := renderedShell(t)
	if !strings.Contains(html, `src="https://app.example.com/assets/logos/horizontal-dark.png"`) {
		t.Error("the logo is not referenced by absolute URL; a relative src resolves against nothing in an email")
	}
	if !strings.Contains(html, `alt="SimpleSCEP"`) {
		t.Error("the logo has no alt text, so a blocked image leaves the message unidentified")
	}
	if !strings.Contains(html, "color:"+colorText) {
		t.Error("the alt text is unstyled and will render as dark type on a dark card")
	}
	if !strings.Contains(html, `width="176"`) || !strings.Contains(html, `height="27"`) {
		t.Error("the image has no intrinsic dimensions; Outlook will size it to the file's own 2x pixels")
	}
}

// A deployment that has not said where it is served from emits no image at all.
// An <img> whose src cannot resolve is a broken-image icon, which is worse than
// the word it replaced.
func TestNoAppURLMeansNoBrokenImage(t *testing.T) {
	t.Setenv("APP_URL", "")
	html := renderedShell(t)
	if strings.Contains(html, "<img") {
		t.Error("an image was emitted with no APP_URL to resolve it against")
	}
	if !strings.Contains(html, ">SimpleSCEP<") {
		t.Error("the text wordmark did not take over, so the message is unidentified")
	}
}
