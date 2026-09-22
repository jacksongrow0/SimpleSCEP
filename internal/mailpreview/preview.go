// Package mailpreview renders every outbound message to disk.
//
// It is a package of its own rather than a second file in cmd/ because cmd/ was
// a single-file main package, and a main package spread over two files can no
// longer be run as "go run cmd/main.go" — only as "go run ./cmd". That is a
// change to how everybody already invokes this program, made as a side effect of
// adding a development command, which is not a trade worth making. Here, cmd/
// keeps one file and gains one line.
package mailpreview

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jacksongrow0/SimpleSCEP/internal/mail"
)

// Dir is where the rendered messages land. Under tmp/ because these are build
// output rather than source: they are regenerated from the templates on every
// run and nothing should be edited here. It is gitignored.
const Dir = "tmp/mail"

// Run writes every user-facing message to disk as HTML and text.
//
// Email is the one thing this service renders that cannot be checked by looking
// at the running application. There is no route that serves it, the templates
// are strings rather than components, and the alternative to this command is
// sending real mail to yourself — which for the expiry alert means waiting for
// the daily sweep to find a certificate inside the window.
//
// Both parts are written so reviewers can check the text alternative as well as
// the HTML message.
func Run() {
	if err := os.MkdirAll(Dir, 0o755); err != nil {
		log.Fatalf("preparing %s: %v", Dir, err)
	}
	// The logo is referenced by absolute URL, because an email has no document
	// base to resolve a relative one against. That leaves a preview with nowhere
	// to load it from, so an unset APP_URL is pointed at the working copy — which
	// is the whole point of a preview: seeing the message with its images, not
	// with the placeholders they leave behind. A deployment that sets APP_URL
	// keeps it, so this can also be used to check the real asset is reachable.
	if os.Getenv("APP_URL") == "" {
		public, err := filepath.Abs("public")
		if err != nil {
			log.Fatalf("locating the asset directory: %v", err)
		}
		os.Setenv("APP_URL", "file://"+public)
	}

	link := "https://app.simplescep.com/auth/login?token=" +
		"eyJhbGciOiJIUzI1NiJ9.dGhpcy1pcy1hLXNhbXBsZS10b2tlbg.7Qx3fV0pR2mKcZ1nJ8sW"

	// The sample data is deliberately awkward. A long certificate subject and a
	// full-length token are what actually break an email layout, and a preview
	// built from "Test User" and "http://x" is one that looks fine and ships
	// broken.
	messages := []struct {
		name    string
		subject string
		render  func() (string, string)
	}{
		{"01-verify", "Confirm your SimpleSCEP email", mail.Action{
			Heading:     "Confirm your email address",
			Body:        "Your SimpleSCEP account is almost ready. Confirm this address to finish signing up.",
			ButtonLabel: "Confirm and open SimpleSCEP",
			URL:         link,
			Expiry:      "15 minutes",
			Unrequested: "If you did not sign up for SimpleSCEP, you can ignore this email and no account will be created.",
		}.Render},

		{"02-signin", "Your SimpleSCEP sign-in link", mail.Action{
			Heading:     "Sign in to SimpleSCEP",
			Body:        "Use the button below to sign in. You will be asked for your second factor afterwards.",
			ButtonLabel: "Sign in",
			URL:         link,
			Expiry:      "15 minutes",
			Unrequested: "If you did not try to sign in, you can ignore this email. Nobody can use this link without your second factor.",
		}.Render},

		{"03-invite", "You're invited to SimpleSCEP", mail.Action{
			Heading:     "You have been invited to SimpleSCEP",
			Body:        "SimpleSCEP is a managed private certificate authority. Accept the invitation to set up your access.",
			ButtonLabel: "Accept the invitation",
			URL:         "https://app.simplescep.com/auth/invite?token=aG91c2Utb2YtbGVhdmVz",
			Expiry:      "7 days",
			Unrequested: "If you were not expecting this, you can ignore this email.",
		}.Render},

		// The common case: one issuing CA, so the column collapses into the
		// sentence. Northwind Logistics is the organization and Northwind Issuing
		// CA G2 is the authority — two different strings, which the message used
		// to conflate.
		{"05-expiry-alert", "3 certificates expire soon", mail.Notice{
			Heading:   "3 certificates expire soon",
			Preheader: "In Northwind Logistics. The first expires 4 Sep 2026.",
			Body:      []string{"3 certificates issued by Northwind Issuing CA G2 in Northwind Logistics expire within the next 30 days."},
			Table: mail.Table{
				Headers: []string{"Certificate", "Serial", "Expires"},
				Rows: [][]string{
					{"vpn-gateway-03.ams.internal.northwind.example", "4A:1F:09:BE:22:7C", "4 Sep 2026"},
					{"CN=Kiosk 118, OU=Retail, O=Northwind", "0E:88:D1:33:5A:90", "11 Sep 2026"},
					{"serial 71:C2:04:AA:19:6F", "71:C2:04:AA:19:6F", "19 Sep 2026"},
				},
				Mono: map[int]bool{1: true},
			},
			Link:  mail.Link{Label: "Review certificates", URL: "https://app.simplescep.com/certificates"},
			Notes: []string{"Renewing or re-enrolling a device replaces its certificate; this notice is sent once per certificate."},
		}.Render},

		{"06-maintenance-report", "SimpleSCEP maintenance report", mail.Notice{
			Heading:   "Maintenance report",
			Preheader: "A protocol check found an enrollment error.",
			Body: []string{
				"Hi Dana,",
				"A protocol check found an enrollment error that needs review.",
			},
			Panel: [][2]string{
				{"Subject", "SCEP enrollment fails after CA rotation"},
				{"Component", "Enrollment"},
				{"Severity", "High"},
			},
			Quote: "After rotating the issuing CA yesterday, every device gets:\n\n  pkiStatus: FAILURE\n  failInfo: badCertId\n\nRe-enrolling by hand works. Automatic renewal does not.",
		}.Render},
	}

	for _, m := range messages {
		body, text := m.render()
		write(m.name+".html", body)
		write(m.name+".txt", "Subject: "+m.subject+"\n\n"+text)
	}
	fmt.Printf("wrote %d messages to %s/ (open the .html files in a browser)\n", len(messages), Dir)
}

func write(name, content string) {
	path := filepath.Join(Dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		log.Fatalf("writing %s: %v", path, err)
	}
}
