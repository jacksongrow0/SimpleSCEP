package layout

import (
	"context"
	"strings"
	"testing"
)

func TestSecurityPanelLoadsFromSecurityTab(t *testing.T) {
	var out strings.Builder
	if err := App("Test", "", Session{Name: "Person"}).Render(context.Background(), &out); err != nil {
		t.Fatalf("render App: %v", err)
	}
	html := out.String()
	if got := strings.Count(html, `hx-get="/security/panel"`); got != 1 {
		t.Fatalf("security panel load count = %d, want one load from the Security tab", got)
	}
	if !strings.Contains(html, `hx-target="#security-panel"`) {
		t.Error("Security tab does not load into the security panel")
	}
	if !strings.Contains(userSettingsOpenScript, "#panel-account") ||
		!strings.Contains(userSettingsOpenScript, "into #security-panel") {
		t.Error("opening Settings does not reset to Account and clear cached security content")
	}
	if !strings.Contains(securityTabScript(), "into #security-panel") {
		t.Error("Security tab does not clear cached content before requesting fresh access")
	}
}

func TestStepUpReplayPreservesRequestMethod(t *testing.T) {
	if !strings.Contains(stepUpDialogScript, "stepup(action, retarget, method)") ||
		!strings.Contains(stepUpDialogScript, "#step-up-method.value to method") {
		t.Error("step-up dialog does not remember the refused request method")
	}
	if strings.Contains(stepUpFormScript, "htmx.ajax('POST'") ||
		!strings.Contains(stepUpFormScript, "htmx.ajax(#step-up-method.value") {
		t.Error("step-up replay does not use the remembered request method")
	}

	var out strings.Builder
	if err := StepUpDialog().Render(context.Background(), &out); err != nil {
		t.Fatalf("render StepUpDialog: %v", err)
	}
	if !strings.Contains(out.String(), `id="step-up-method"`) {
		t.Error("step-up dialog has nowhere to store the request method")
	}
}
