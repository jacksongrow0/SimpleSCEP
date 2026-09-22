package mail

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryMessageIsRoutedDeliberately reads the send sites and checks which
// envelope each one picks.
//
// It reads source rather than sending mail because the alternative is a handler
// harness with a database and a session behind it, for an assertion that is
// really about one identifier. The risk it guards is small but specific:
// somebody edits a handler and the sign-in link starts carrying the notification
// reply address. Nothing else would notice.
//
// If a send site moves, this test names the file and what it expected. Update the
// table; do not delete the case.
func TestEveryMessageIsRoutedDeliberately(t *testing.T) {
	root := repoRoot(t)
	// Each case: the message-building call, and the envelope that must wrap it.
	for _, tc := range []struct{ file, message, envelope string }{
		// Authentication. These carry single-use tokens and no reply to them is
		// meaningful, so they must not reach a mailbox anybody works through.
		{"internal/auth/handler.go", "signIn.Message(", "mail.NoReply.Apply("},
		{"internal/auth/handler.go", "verify.Message(", "mail.NoReply.Apply("},
		// Invitations use the deployment's optional notification reply address.
		{"internal/auth/handler.go", "invite.Message(", "mail.Notifications.Apply("},
	} {
		src := readSource(t, filepath.Join(root, tc.file))
		idx := strings.Index(src, tc.message)
		if idx < 0 {
			t.Errorf("%s no longer contains %q; the send site moved and this case needs updating", tc.file, tc.message)
			continue
		}
		// The envelope wraps the message, so it appears just before it. A short
		// window keeps an unrelated Apply elsewhere in the file out of the match.
		window := src[max(0, idx-80):idx]
		if !strings.Contains(window, tc.envelope) {
			t.Errorf("%s: %q is not wrapped in %s — it is sent as %q",
				tc.file, tc.message, tc.envelope, strings.TrimSpace(window))
		}
	}
}

// TestEverySendSiteChoosesAnEnvelope ensures new messages opt into the
// authentication or notification reply behavior deliberately.
func TestEverySendSiteChoosesAnEnvelope(t *testing.T) {
	root := repoRoot(t)
	send := regexp.MustCompile(`\.Send\((?:ctx|r\.Context\(\)|txctx)`)
	for _, dir := range []string{"internal/auth", "internal/pki", "internal/home", "internal/acme", "internal/est", "internal/scep"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			src := readSource(t, filepath.Join(root, path))
			if !send.MatchString(src) {
				continue
			}
			if strings.Contains(src, "mail.Message{") || strings.Contains(src, ".Message(") {
				if !strings.Contains(src, ".Apply(") {
					t.Errorf("%s sends mail but names no envelope", path)
				}
			}
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// This package lives at <root>/internal/mail.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func readSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}
