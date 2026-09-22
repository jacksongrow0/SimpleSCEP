package pki

import (
	"errors"
	"testing"
)

// TestNamePolicyMatchesEachSANSeparately is the substring bypass.
//
// The check this replaces joined every requested name with a comma and ran
// MatchString over the result, which is a substring match: a policy naming one
// domain accepted a request that also asked for an unrelated one, and the
// requested SAN DER is copied into the issued certificate verbatim.
func TestNamePolicyMatchesEachSANSeparately(t *testing.T) {
	p := NamePolicy{SAN: `\.corp\.example\.com$`}

	if err := p.Check("CN=device-7", []string{"device7.corp.example.com"}); err != nil {
		t.Fatalf("a conforming name was refused: %v", err)
	}
	if err := p.Check("CN=device-7", []string{"a.corp.example.com", "b.corp.example.com"}); err != nil {
		t.Fatalf("two conforming names were refused: %v", err)
	}

	err := p.Check("CN=device-7", []string{"evil.attacker.com", "device7.corp.example.com"})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("a smuggled name was accepted alongside a conforming one: %v", err)
	}
	// Order must not matter: the joined-string check happened to refuse this
	// arrangement and accept the one above, which is how the bypass stayed hidden.
	if err := p.Check("CN=device-7", []string{"device7.corp.example.com", "evil.attacker.com"}); !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("a smuggled name was accepted when it came last: %v", err)
	}
}

// TestNamePolicyAppliesBothRulesWhenTheyAreIdentical is the map-literal defect.
//
// The rules used to live in a map keyed by the pattern, so setting the subject
// and SAN patterns to the same expression — which an administrator would
// reasonably do — collapsed the map to a single entry and left only one rule
// running, with the page still showing both saved.
func TestNamePolicyAppliesBothRulesWhenTheyAreIdentical(t *testing.T) {
	const same = `corp\.example\.com`
	p := NamePolicy{Subject: same, SAN: same}

	// The SAN conforms and the subject does not. Under the map this passed.
	err := p.Check("CN=Domain Admin", []string{"device7.corp.example.com"})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("the subject rule did not run when both patterns were identical: %v", err)
	}
	// And the mirror image, so this is not passing for the wrong reason.
	if err := p.Check("CN=device7.corp.example.com", []string{"evil.attacker.com"}); !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("the SAN rule did not run when both patterns were identical: %v", err)
	}
	if err := p.Check("CN=device7.corp.example.com", []string{"device7.corp.example.com"}); err != nil {
		t.Errorf("a request satisfying both identical rules was refused: %v", err)
	}
}

// TestNamePolicyEmptySANPatternPermitsNoSANs pins the default, which is closed.
// A new endpoint ships with no SAN pattern, and until an administrator writes
// one the endpoint may not carry names it was never told to accept.
//
// This is the reverse of what an empty pattern used to mean, and the reverse of
// what an empty *subject* pattern still means, so it is worth being explicit:
// blank SAN is not "no rule", it is "no names".
func TestNamePolicyEmptySANPatternPermitsNoSANs(t *testing.T) {
	err := (NamePolicy{}).Check("CN=anything", []string{"anything.example.com"})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("an unset SAN pattern allowed a SAN through: %v", err)
	}
	err = (NamePolicy{Subject: `^CN=device`}).Check("CN=device-1", []string{"whatever.example.com"})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("a subject rule with no SAN rule allowed a SAN through: %v", err)
	}
	// The rule is about which names may be carried. A request that asks for
	// none asks for nothing this rule governs, so it is still issued.
	if err := (NamePolicy{}).Check("CN=device-1", nil); err != nil {
		t.Errorf("a request carrying no SAN was refused by the empty rule: %v", err)
	}
	// The subject side keeps the open default: nothing trusts a subject to name
	// a host, and tightening it was not what was asked for.
	if err := (NamePolicy{SAN: `.*`}).Check("CN=literally anything", []string{"x.example.com"}); err != nil {
		t.Errorf("an unset subject pattern constrained the subject: %v", err)
	}
}

// TestNamePolicyRefusesARequestWithNoSANs preserves the behaviour of the check
// this replaces. Per-name matching would pass a request with no names vacuously,
// which would quietly loosen every configured SAN policy.
func TestNamePolicyRefusesARequestWithNoSANs(t *testing.T) {
	if err := (NamePolicy{SAN: `\.corp\.example\.com$`}).Check("CN=device-7", nil); !errors.Is(err, ErrPolicyRefused) {
		t.Errorf("a request carrying no SAN satisfied a SAN policy: %v", err)
	}
	// A policy that does accept the empty rendering still does.
	if err := (NamePolicy{SAN: `.*`}).Check("CN=device-7", nil); err != nil {
		t.Errorf("a permissive SAN policy refused a request with no SANs: %v", err)
	}
}

// TestNamePolicyDistinguishesABrokenPolicyFromARefusal matters because the two
// are nobody's fault in common, and the callers map them to different responses:
// a refusal is the client's request, an invalid pattern is a row in our database.
func TestNamePolicyDistinguishesABrokenPolicyFromARefusal(t *testing.T) {
	err := (NamePolicy{Subject: "([unclosed"}).Check("CN=device-7", nil)
	if !errors.Is(err, ErrPolicyInvalid) {
		t.Errorf("an uncompilable subject pattern did not report as invalid: %v", err)
	}
	if errors.Is(err, ErrPolicyRefused) {
		t.Error("an uncompilable pattern reported as a refusal, which blames the client")
	}
	err = (NamePolicy{SAN: "([unclosed"}).Check("CN=device-7", []string{"a.example.com"})
	if !errors.Is(err, ErrPolicyInvalid) {
		t.Errorf("an uncompilable SAN pattern did not report as invalid: %v", err)
	}
}
