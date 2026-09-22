package main

import (
	"os"
	"strings"
	"testing"
)

// TestDevelopmentHost pins the gate that decides whether a missing
// RESEND_API_KEY is tolerated. The direction that matters is the false one: a
// host wrongly called development turns a production deploy into one where
// login links go to the log and every customer sees sign-in silently do
// nothing. So the unrecognised cases are asserted as production, not skipped.
func TestDevelopmentHost(t *testing.T) {
	development := []string{
		"localhost",
		"LOCALHOST",
		"127.0.0.1",
		"::1",
		"[::1]",
		"simplescep.localhost",
		"vpn.test",
		"macbook.local",
		// A trailing dot is a fully qualified name and still names loopback.
		"localhost.",
	}
	for _, host := range development {
		if !developmentHost(host) {
			t.Errorf("developmentHost(%q) = false, want true", host)
		}
	}

	production := []string{
		"simplescep.com",
		"app.simplescep.com",
		"192.0.2.10",
		"",
		// Suffix matching must not be fooled by a domain that merely contains
		// the reserved label, which is registrable and points anywhere.
		"localhost.evil.com",
		"test.example.com",
		"local.example.com",
		// Nor by one that ends in the label without the separating dot.
		"notlocalhost",
		"mytest",
	}
	for _, host := range production {
		if developmentHost(host) {
			t.Errorf("developmentHost(%q) = true, want false", host)
		}
	}
}

// TestTheMainPackageIsOneFile pins how this program can be invoked.
//
// A main package spread over several files can only be run as "go run ./cmd";
// "go run cmd/main.go" compiles that one file as the pseudo-package
// command-line-arguments and fails on every symbol defined beside it. Both
// spellings work today and both are in people's shell history, so a second file
// here silently breaks one of them — as adding the mail preview command did,
// which is why it now lives in internal/mailpreview and this test exists.
//
// A new command belongs in its own package under internal/, called from the
// switch in main. If this fails, that is the fix rather than deleting the test.
func TestTheMainPackageIsOneFile(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the command directory: %v", err)
	}
	var sources []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sources = append(sources, name)
	}
	if len(sources) != 1 {
		t.Errorf("the main package is %v; \"go run cmd/main.go\" no longer works. "+
			"Put the new command in its own package under internal/ and call it from the switch in main", sources)
	}
}
