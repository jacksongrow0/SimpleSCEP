package mail

import (
	"strings"
	"testing"
)

func testNotice() Notice {
	return Notice{
		Heading: "2 certificates expire soon",
		Body:    []string{"2 certificates issued by Northwind Issuing CA G2 expire within the next 30 days."},
		Table: Table{
			Headers: []string{"Certificate", "Serial", "Expires"},
			Rows: [][]string{
				{"vpn-gateway-03.ams.internal.northwind.example", "4A:1F:09:BE", "4 Sep 2026"},
				{"kiosk-118", "0E:88:D1:33", "11 Sep 2026"},
			},
			Mono: map[int]bool{1: true},
		},
		Link:  Link{Label: "Review certificates", URL: "https://app.example.com/certificates"},
		Notes: []string{"This notice is sent once per certificate."},
	}
}

// A message carrying a table and link has the shape of a newsletter, and the
// expiry alert is the one notification whose arrival is the entire point of the
// feature — a copy filed as spam is the outage it exists to prevent.
func TestANoticeSendsBothParts(t *testing.T) {
	msg := testNotice().Message("someone@example.com", "2 certificates expire soon")
	if msg.Body == "" {
		t.Fatal("no HTML part")
	}
	if msg.Text == "" {
		t.Fatal("no plain-text part; the message is HTML-only")
	}
	if strings.Contains(msg.Text, "<td") || strings.Contains(msg.Text, "<div") {
		t.Errorf("the text part carries markup: %q", msg.Text)
	}
}

// A stripped table is every cell on its own line with nothing saying which
// column it came from, which for this message is a list of dates and serials in
// no stated relation to each other. The text part lays the columns out itself.
func TestTheTextTableKeepsItsColumns(t *testing.T) {
	_, text := testNotice().Render()
	var row string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "kiosk-118") {
			row = line
		}
	}
	if row == "" {
		t.Fatal("the certificate is missing from the text part entirely")
	}
	if !strings.Contains(row, "0E:88:D1:33") || !strings.Contains(row, "11 Sep 2026") {
		t.Errorf("the row lost its other columns: %q", row)
	}
	// The wider subject above it sets the column width, so this row is padded out
	// to meet it. Without that the columns do not line up and the layout is lost.
	if !strings.Contains(row, "kiosk-118  ") {
		t.Errorf("the columns are not aligned: %q", row)
	}
}

// Certificate subjects and other operator-provided values reach these templates
// and must arrive as text.
func TestEverythingACustomerControlsIsEscaped(t *testing.T) {
	n := Notice{
		Heading: "<script>alert(1)</script>",
		Body:    []string{"body <b>tag</b>"},
		Table: Table{
			Headers: []string{"Certificate"},
			Rows:    [][]string{{`CN=<img src=x onerror=alert(1)>`}},
		},
		Panel: [][2]string{{"Subject", "<i>subject</i>"}},
		Quote: "quoted <script>alert(2)</script>",
		Link:  Link{Label: "Go <b>now</b>", URL: `https://example.com/?a="&b=1`},
	}
	html, _ := n.Render()
	for _, leaked := range []string{"<script>", "<b>tag</b>", "<img src=x", "<i>subject</i>", "<b>now</b>"} {
		if strings.Contains(html, leaked) {
			t.Errorf("%q reached the message as markup", leaked)
		}
	}
	if strings.Contains(html, `?a="&b=1`) {
		t.Error("the URL's quote was not escaped, so it terminates the href attribute early")
	}
}

// Outlook's desktop clients render through Word, which supports neither padding
// on an inline-block nor border-radius. Without the VML the call to action in the
// sign-in mail degrades to an underlined link in a message that has one job.
func TestTheButtonHasAnOutlookFallback(t *testing.T) {
	html := button("Sign in", "https://example.com/x")
	if !strings.Contains(html, "v:roundrect") {
		t.Error("no VML fallback; Outlook renders this as a bare link")
	}
	if !strings.Contains(html, `<!--[if mso]>`) || !strings.Contains(html, `<!--[if !mso]><!-->`) {
		t.Error("the two renderings are not gated, so Outlook will show both")
	}
	if strings.Contains(html, `fillcolor="`+colorPrimary+`"`) == false {
		t.Error("the Outlook button is not filled with the primary colour")
	}
}

// A Notice is complete without a call to action — unlike an Action, whose whole
// purpose is the one thing to do.
func TestANoticeNeedsNoLink(t *testing.T) {
	n := Notice{Heading: "Maintenance report", Body: []string{"Review the attached result."}, Quote: "it broke"}
	html, text := n.Render()
	if strings.Contains(html, "v:roundrect") {
		t.Error("a notice with no link still rendered a button")
	}
	if !strings.Contains(text, "it broke") {
		t.Error("the quoted message is missing from the text part")
	}
}

// The preview line falls back to what the message is about, which is nearly
// always the right thing to show, and is cut at a word boundary — a preview
// ending mid-word reads as a message that was itself truncated.
func TestThePreheaderFallsBackToTheOpeningLine(t *testing.T) {
	long := "Several certificates for Northwind Logistics are approaching expiry and should be renewed before the maintenance window"
	got := Action{Body: long}.preheader()
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a long body was not truncated: %q", got)
	}
	if strings.HasSuffix(strings.TrimSuffix(got, "…"), "cont") {
		t.Errorf("the preview was cut mid-word: %q", got)
	}
	if len(got) > 115 {
		t.Errorf("the preview is %d bytes, too long for an inbox listing", len(got))
	}
	short := "Your account is ready."
	if (Action{Body: short}).preheader() != short {
		t.Error("a short body was altered")
	}
}
