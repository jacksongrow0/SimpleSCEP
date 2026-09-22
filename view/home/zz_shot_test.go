package home

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
)

func TestZZShot(t *testing.T) {
	at := time.Date(2026, 8, 26, 14, 3, 0, 0, time.UTC)
	actions := []string{audit.ActionCertificateIssued, audit.ActionSignedIn, audit.ActionEndpointPolicy,
		audit.ActionCertificateRevoked, audit.ActionSCEPChallengeIssued, audit.ActionUserRoleChanged}
	var events []audit.Event
	for i := 0; i < 12; i++ {
		events = append(events, audit.Event{
			Action: actions[i%len(actions)], Target: "host-" + strconv.Itoa(i) + ".corp.example.com",
			Detail: "Issuing CA · 90 days", ActorName: "Jane Doe", ActorEmail: "jane@example.com",
			ActorIP: "203.0.113.44", ActorUserAgent: "Mozilla/5.0",
			At: at.Add(-time.Duration(i*17) * time.Minute)})
	}
	page, _ := strconv.Atoi(os.Getenv("PAGE"))
	pages, _ := strconv.Atoi(os.Getenv("PAGES"))
	data := AuditData{Events: events, Total: 4102, Matching: (pages-1)*50 + 12,
		Page: page, Pages: pages, PageSize: 50, Action: os.Getenv("ACTION")}
	html := render(t, Audit(testSession(), data))
	html = strings.Replace(html, `href="/static/app.css?v=20260829-1"`, `href="`+os.Getenv("CSS")+`"`, 1)
	os.WriteFile(os.Getenv("SHOT_OUT"), []byte(html), 0o644)
}
