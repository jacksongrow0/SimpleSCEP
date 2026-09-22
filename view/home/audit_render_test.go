package home

import (
	"strings"
	"testing"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
)

func auditRow(t *testing.T, event audit.Event) string {
	t.Helper()
	html := render(t, AuditRow(event))
	return strings.TrimSpace(html)
}

func sampleEvent() audit.Event {
	return audit.Event{
		Action: audit.ActionCertificateIssued, Target: "vpn-gw-04.corp.example.com",
		Detail: "Issuing CA · 90 days", ActorName: "Jane Doe", ActorEmail: "jane@example.com",
		ActorIP: "203.0.113.44", ActorUserAgent: "Mozilla/5.0",
		At: time.Date(2026, 8, 26, 14, 3, 0, 0, time.UTC),
	}
}

// TestAuditRowUsesNoParagraph is the regression test for a row that was half
// again as tall as it needed to be. base.templ sets [&_p]:my-[1em] on <body>,
// which compiles to a descendant selector and so outranks any plain margin
// utility — the mt-0.5 and mb-0 the subject line used to carry never applied,
// and every row paid 28px for two margins the template believed it had removed.
//
// Asserted on the element rather than on the class list because the class list
// was never the problem: it read correctly and did nothing. A <p> here is the
// bug whatever margin classes accompany it.
func TestAuditRowUsesNoParagraph(t *testing.T) {
	// "<p " and "<p>" rather than "<p": the row is full of SVG <path> elements.
	row := auditRow(t, sampleEvent())
	if strings.Contains(row, "<p ") || strings.Contains(row, "<p>") {
		t.Errorf("audit row renders a <p>, which body's [&_p]:my-[1em] gives margins no utility on the element can override:\n%s", row)
	}
}

// TestAuditRowKeepsEveryField guards the condensing. Fitting the row onto one
// line meant moving four fields around, and the failure mode of that edit is
// dropping one quietly — this is the log an incident is reconstructed from, so
// a field that stops rendering is not a cosmetic regression.
func TestAuditRowKeepsEveryField(t *testing.T) {
	row := auditRow(t, sampleEvent())
	for _, want := range []string{
		audit.ActionLabel(audit.ActionCertificateIssued),
		"vpn-gw-04.corp.example.com",
		"Issuing CA · 90 days",
		"Jane Doe",
		"203.0.113.44",
	} {
		if !strings.Contains(row, want) {
			t.Errorf("audit row does not render %q", want)
		}
	}
	// The user agent is the one field that is not on the line: it is the longest
	// and the least read, so it hangs off the address as a tooltip.
	if !strings.Contains(row, `title="Mozilla/5.0"`) {
		t.Error("the user agent is not reachable from the row")
	}
}

// TestAuditRowSubjectTruncates covers the half of the line that is allowed to be
// cut off. The subject can run to a full DNS name and the row is one line, so it
// must truncate rather than wrap the row back to two — and the action label must
// not, because a row whose action is unreadable is not a row.
func TestAuditRowSubjectTruncates(t *testing.T) {
	row := auditRow(t, sampleEvent())
	subject, _, ok := strings.Cut(row, "vpn-gw-04.corp.example.com")
	if !ok {
		t.Fatal("audit row renders no subject")
	}
	open := strings.LastIndex(subject, "<span")
	if !strings.Contains(subject[open:], "truncate") {
		t.Error("the subject does not truncate, so a long name wraps the row onto a second line")
	}
	if !strings.Contains(subject[open:], "min-w-0") {
		t.Error("the subject has no min-w-0, so truncate has no width to work against inside a flex row")
	}
}

// TestAuditRowStretchesWhenStacked covers the mobile layout, where this went
// wrong once already. Stacked, the row is a flex column: flex-1 and min-w-0
// govern the main axis, which is now vertical, so the blocks only keep a width
// to truncate against if they are still stretched. With items-start instead, the
// left block sized to its own untruncated text and pushed the row out past the
// card that contains it.
func TestAuditRowStretchesWhenStacked(t *testing.T) {
	row := auditRow(t, sampleEvent())
	if !strings.Contains(row, "max-md:flex-col") {
		t.Fatal("the audit row no longer stacks on a narrow screen")
	}
	if !strings.Contains(row, "max-md:items-stretch") {
		t.Error("the stacked row does not stretch its blocks, so the subject has no width to truncate against")
	}
}
