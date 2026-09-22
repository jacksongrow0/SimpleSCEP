package auth

import (
	"strings"
	"testing"
)

func TestNewRecoveryCodesShape(t *testing.T) {
	display, rows, err := newRecoveryCodes()
	if err != nil {
		t.Fatalf("newRecoveryCodes: %v", err)
	}
	if len(display) != recoveryCodeCount || len(rows) != recoveryCodeCount {
		t.Fatalf("got %d display codes and %d rows, want %d of each",
			len(display), len(rows), recoveryCodeCount)
	}

	selectors := map[string]bool{}
	for i, shown := range display {
		// Displayed with dashes, grouped in fours.
		if want := "XXXX-XXXX-XXXX-XXXX"; len(shown) != len(want) {
			t.Errorf("code %d = %q, want the shape %q", i, shown, want)
		}
		selector, verifier, err := parseRecoveryCode(shown)
		if err != nil {
			t.Fatalf("a freshly minted code did not parse: %q: %v", shown, err)
		}
		if selector != rows[i].Selector {
			t.Errorf("code %d parses to selector %q, but the row stores %q", i, selector, rows[i].Selector)
		}
		if !verifyRecoveryVerifier(rows[i].VerifierHash, verifier) {
			t.Errorf("code %d does not verify against its own stored hash", i)
		}
		// The selector is UNIQUE in the schema, so a duplicate would fail the
		// insert and leave the user with fewer codes than they were shown.
		if selectors[selector] {
			t.Errorf("selector %q issued twice", selector)
		}
		selectors[selector] = true
	}
}

// TestRecoveryCodesAreNotStoredInTheClear is the property the whole table shape
// exists for. A stored row must not contain the verifier — the half that is
// actually secret — in any recoverable form.
func TestRecoveryCodesAreNotStoredInTheClear(t *testing.T) {
	display, rows, err := newRecoveryCodes()
	if err != nil {
		t.Fatalf("newRecoveryCodes: %v", err)
	}
	for i, shown := range display {
		_, verifier, err := parseRecoveryCode(shown)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(rows[i].VerifierHash, verifier) {
			t.Errorf("row %d stores the verifier in its hash field", i)
		}
		if strings.Contains(rows[i].Selector, verifier) {
			t.Errorf("row %d stores the verifier in its selector", i)
		}
	}
}

// TestParseRecoveryCodeIsForgiving covers the transcription this has to
// survive. Someone typing a recovery code has lost their phone and is reading
// from a printout; the excluded letters are mapped to what they are mistaken
// for rather than refused.
func TestParseRecoveryCodeIsForgiving(t *testing.T) {
	// A known code, written six different ways, must parse identically.
	const canonical = "A1B2C3D4E5F6G7H8"
	variants := []string{
		"A1B2C3D4E5F6G7H8",
		"A1B2-C3D4-E5F6-G7H8",
		"a1b2-c3d4-e5f6-g7h8",
		"  A1B2 C3D4 E5F6 G7H8  ",
		"A1B2-C3D4-E5F6-G7H8\n",
		// I and L read as 1, O reads as 0: none of these appear in the alphabet,
		// so the mapping is unambiguous.
		"AIB2-C3D4-E5F6-G7H8",
	}
	wantSel, wantVer, err := parseRecoveryCode(canonical)
	if err != nil {
		t.Fatalf("canonical code did not parse: %v", err)
	}
	for _, v := range variants[:5] {
		sel, ver, err := parseRecoveryCode(v)
		if err != nil {
			t.Errorf("%q did not parse: %v", v, err)
			continue
		}
		if sel != wantSel || ver != wantVer {
			t.Errorf("%q parsed to %q/%q, want %q/%q", v, sel, ver, wantSel, wantVer)
		}
	}
	// "AIB2..." maps I to 1, giving "A1B2...", the same as canonical.
	if sel, ver, err := parseRecoveryCode(variants[5]); err != nil {
		t.Errorf("%q did not parse: %v", variants[5], err)
	} else if sel != wantSel || ver != wantVer {
		t.Errorf("%q parsed to %q/%q, want I to be read as 1", variants[5], sel, ver)
	}
}

func TestParseRecoveryCodeRefusesWrongLength(t *testing.T) {
	for _, input := range []string{
		"",
		"A1B2",
		"A1B2-C3D4-E5F6-G7H",   // one short
		"A1B2-C3D4-E5F6-G7H8Z", // one long
		"----------------",     // nothing but separators
		"!@#$%^&*()",           // nothing in the alphabet
	} {
		if _, _, err := parseRecoveryCode(input); err == nil {
			t.Errorf("parseRecoveryCode(%q) succeeded; want an error", input)
		}
	}
}

// TestVerifyRecoveryVerifierRejectsWrongInput is what makes a wrong guess safe:
// it fails, and — because the handler verifies before consuming — it does not
// burn the code.
func TestVerifyRecoveryVerifierRejectsWrongInput(t *testing.T) {
	hash, err := hashRecoveryVerifier("ABCDEFGHJK")
	if err != nil {
		t.Fatalf("hashRecoveryVerifier: %v", err)
	}
	if !verifyRecoveryVerifier(hash, "ABCDEFGHJK") {
		t.Fatal("the correct verifier did not verify")
	}
	for _, wrong := range []string{"", "ABCDEFGHJ", "ABCDEFGHJM", "abcdefghjk", "0000000000"} {
		if verifyRecoveryVerifier(hash, wrong) {
			t.Errorf("verifier %q was accepted", wrong)
		}
	}
	// A malformed stored hash must fail closed rather than panic.
	for _, bad := range []string{"", "nodot", "a.b.c", "!!!.???"} {
		if verifyRecoveryVerifier(bad, "ABCDEFGHJK") {
			t.Errorf("malformed stored hash %q was accepted", bad)
		}
	}
}

// TestRecoveryAlphabetHasNoLookalikes pins the alphabet itself. Adding I, L, O
// or U back would make parseRecoveryCode's normalisation ambiguous — a typed
// "0" could then legitimately be either "0" or "O" — and silently break codes
// that were previously accepted.
func TestRecoveryAlphabetHasNoLookalikes(t *testing.T) {
	for _, c := range "ILOU" {
		if strings.ContainsRune(recoveryAlphabet, c) {
			t.Errorf("%q is in the alphabet; parseRecoveryCode maps it to something else, "+
				"so codes containing it could never be entered", c)
		}
	}
	if len(recoveryAlphabet) != 32 {
		t.Errorf("alphabet is %d characters; randomRecoveryCode masks to 5 bits and needs exactly 32 "+
			"for a uniform draw", len(recoveryAlphabet))
	}
	seen := map[rune]bool{}
	for _, c := range recoveryAlphabet {
		if seen[c] {
			t.Errorf("%q appears twice in the alphabet, which biases the draw", c)
		}
		seen[c] = true
	}
}

// TestRandomRecoveryCodeIsUnpredictable is a smoke test over the draw. The
// verifier is the only secret in the code, so a biased or repeating generator
// would quietly shrink the search space it rests on.
func TestRandomRecoveryCodeIsUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		code, err := randomRecoveryCode()
		if err != nil {
			t.Fatalf("randomRecoveryCode: %v", err)
		}
		if len(code) != recoveryCodeLen {
			t.Fatalf("length = %d, want %d", len(code), recoveryCodeLen)
		}
		for _, c := range code {
			if !strings.ContainsRune(recoveryAlphabet, c) {
				t.Fatalf("code %q contains %q, which is outside the alphabet", code, c)
			}
		}
		if seen[code] {
			t.Fatal("randomRecoveryCode repeated a value within 200 draws")
		}
		seen[code] = true
	}
}
