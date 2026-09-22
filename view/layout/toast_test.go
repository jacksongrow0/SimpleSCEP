package layout

import (
	"context"
	"strings"
	"testing"

	"github.com/jacksongrow0/SimpleSCEP/internal/toast"
)

func renderApp(t *testing.T, ctx context.Context) string {
	t.Helper()
	var out strings.Builder
	if err := App("Test", "", Session{Name: "Person"}).Render(ctx, &out); err != nil {
		t.Fatalf("render App: %v", err)
	}
	return out.String()
}

func TestShellHostsExactlyOneToastRegion(t *testing.T) {
	html := renderApp(t, context.Background())
	if got := strings.Count(html, `id="toast-region"`); got != 1 {
		t.Fatalf("toast region count = %d, want one", got)
	}
	if !strings.Contains(html, `src="/static/toast.js"`) {
		t.Error("the shell hosts a toast region with nothing to render into it")
	}
	// Nothing pending, so nothing to show. A region that always carried the
	// attributes would toast an empty string on every page load.
	if strings.Contains(html, "data-initial-text") {
		t.Error("an empty shell carries an initial message")
	}
}

func TestAPendingMessageReachesTheShell(t *testing.T) {
	ctx := toast.WithMessage(context.Background(),
		toast.New(toast.Warning, `Two lists were not published`))
	html := renderApp(t, ctx)

	if !strings.Contains(html, `data-initial-tone="warning"`) {
		t.Error("the shell lost the tone of the pending message")
	}
	if !strings.Contains(html, "Two lists were not published") {
		t.Error("the shell lost the pending message")
	}
}

// A message can be an error string built from user input, and it lands in an
// attribute.
func TestAPendingMessageIsEscaped(t *testing.T) {
	ctx := toast.WithMessage(context.Background(),
		toast.New(toast.Error, `"><img src=x onerror=alert(1)>`))
	html := renderApp(t, ctx)

	if strings.Contains(html, "<img src=x") {
		t.Fatal("the pending message reached the page as markup")
	}
}

// The rule this replaced toasted "Saved successfully" on any successful htmx
// request to a form. Every FormError helper answers 200 so htmx will swap the
// error fragment, so it reported success for rejections. It must not come back,
// and neither must the singleton element it drove.
func TestTheShellNoLongerToastsForItself(t *testing.T) {
	html := renderApp(t, context.Background())
	// "htmx:afterRequest" is not in this list: stepUpFormScript uses it to
	// re-fire a refused request, which is unrelated and still correct.
	for _, stale := range []string{
		"Saved successfully",
		"send notify",
		"on notify(",
		`id="toast"`,
	} {
		if strings.Contains(html, stale) {
			t.Errorf("the shell still carries %q", stale)
		}
	}
}
