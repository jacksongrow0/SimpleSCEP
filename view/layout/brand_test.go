package layout

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The wordmark is the file the brand ships, not an approximation of it. What
// this replaced was an inline <svg> and the word "SimpleSCEP" in bold, which
// looked deliberate and matched nothing else the customer had seen — not the
// marketing site, not the favicon.
func TestTheShellRendersTheRealWordmark(t *testing.T) {
	html := renderApp(t, context.Background())
	if !strings.Contains(html, `src="/assets/logos/horizontal-dark.svg"`) {
		t.Error("the shell is not rendering the wordmark file")
	}
	if strings.Contains(html, "Simple<b>SCEP</b>") || strings.Contains(html, "ss-grad") {
		t.Error("the hand-drawn stand-in mark is still being rendered")
	}
	// Both the sidebar and the mobile bar carry it.
	if got := strings.Count(html, `class="logo`); got != 2 {
		t.Errorf("logo count = %d, want two: the sidebar and the mobile bar", got)
	}
	// An image with no alt text reads as "logo" or as the file name.
	if !strings.Contains(html, `alt="SimpleSCEP"`) {
		t.Error("the wordmark has no alt text")
	}
}

// A crawler is told twice, and this is the half that survives a page being
// rendered rather than fetched. The other half is the X-Robots-Tag header in
// internal/middleware.
func TestEveryPageAsksNotToBeIndexed(t *testing.T) {
	var out strings.Builder
	if err := Base("Test").Render(context.Background(), &out); err != nil {
		t.Fatalf("render Base: %v", err)
	}
	if !strings.Contains(out.String(), `<meta name="robots" content="noindex, nofollow">`) {
		t.Error("the page head does not ask to be left out of the index")
	}
}

// The icons the browser asks for by name. They are declared in the head rather
// than left to convention because only /favicon.ico has a convention, and it is
// the one file of the set that is not under /assets/.
func TestTheHeadDeclaresTheBrandIcons(t *testing.T) {
	var out strings.Builder
	if err := Base("Test").Render(context.Background(), &out); err != nil {
		t.Fatalf("render Base: %v", err)
	}
	html := out.String()
	for _, href := range []string{
		`href="/favicon.ico"`,
		`href="/assets/favicon.svg"`,
		`href="/assets/apple-touch-icon.png"`,
		`href="/assets/site.webmanifest"`,
	} {
		if !strings.Contains(html, href) {
			t.Errorf("the head does not declare %s", href)
		}
	}
}

// Every brand file the pages reference has to be on disk under public/. Nothing
// else checks: a renamed logo is a broken image on the sign-in page and a
// missing favicon is a 404 nobody reads, and both survive every other test in
// this repository.
func TestTheBrandFilesTheHeadReferencesExist(t *testing.T) {
	root := filepath.Join("..", "..", "public")
	for _, rel := range []string{
		"favicon.ico",
		"robots.txt",
		"assets/favicon.svg",
		"assets/apple-touch-icon.png",
		"assets/site.webmanifest",
		"assets/web-app-manifest-192x192.png",
		"assets/web-app-manifest-512x512.png",
		"assets/logos/horizontal-dark.svg",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("public/%s is referenced by the pages and is not there: %v", rel, err)
		}
	}
}
