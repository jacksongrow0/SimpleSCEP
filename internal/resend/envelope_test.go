package resend

import "testing"

// TestEnvelopePrefersTheMessage covers the per-message override that lets an
// automated notice leave under a different mailbox than authentication mail.
func TestEnvelopePrefersTheMessage(t *testing.T) {
	const transport = "SimpleSCEP <pki@example.test>"
	for _, tc := range []struct {
		name, message, want string
	}{
		{"message names its own", "Notifications <alerts@example.test>", "Notifications <alerts@example.test>"},
		{"message names none", "", transport},
		// A message whose From is whitespace must fall back rather than be sent
		// with an envelope the provider will reject.
		{"message names blank", "  ", transport},
	} {
		if got := envelope(tc.message, transport); got != tc.want {
			t.Errorf("%s: envelope(%q, %q) = %q, want %q", tc.name, tc.message, transport, got, tc.want)
		}
	}
}
