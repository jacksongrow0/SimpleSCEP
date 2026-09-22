package mail

import "testing"

func TestEnvelopeUsesDeploymentSender(t *testing.T) {
	t.Setenv("MAIL_FROM", "SimpleSCEP <pki@example.test>")
	t.Setenv("MAIL_REPLY_TO", "operators@example.test")

	login := NoReply.Apply(Message{To: "a@example.test"})
	if login.From != "SimpleSCEP <pki@example.test>" || login.ReplyTo != "" {
		t.Errorf("authentication envelope = %+v", login)
	}

	notice := Notifications.Apply(Message{To: "a@example.test", Subject: "s", Body: "b"})
	if notice.From != "SimpleSCEP <pki@example.test>" || notice.ReplyTo != "operators@example.test" {
		t.Errorf("notification envelope = %+v", notice)
	}
}

func TestEnvelopeDoesNotOverrideMessageHeaders(t *testing.T) {
	t.Setenv("MAIL_FROM", "configured@example.test")
	t.Setenv("MAIL_REPLY_TO", "configured-reply@example.test")
	got := Notifications.Apply(Message{From: "chosen@example.test", ReplyTo: "reply@example.test"})
	if got.From != "chosen@example.test" || got.ReplyTo != "reply@example.test" {
		t.Errorf("Apply overwrote message headers: %+v", got)
	}
}
