package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestTokenHashMatchesPostgres pins the Go hash to the one the migration used to
// convert the existing rows. The migration hashed in SQL, with
// encode(sha256(convert_to(token,'UTF8')),'hex'), and every in-flight magic link
// and invitation was rewritten with it. If this function ever stopped agreeing —
// a switch to base64, to a salt, to SHA-512 — no previously issued link would
// redeem, and the failure would look like "the email is broken" rather than like
// a hash change.
//
// The expected value below was produced by Postgres, not by this package.
func TestTokenHashMatchesPostgres(t *testing.T) {
	const token = "abc-DEF_123"
	const fromPostgres = "7469e9a6b53358b1e6dabc4c2beb15ac747131f8045078162187063295853539"

	if got := tokenHash(token); got != fromPostgres {
		t.Errorf("tokenHash(%q) = %q, want %q (the value Postgres wrote during the migration)",
			token, got, fromPostgres)
	}
}

// TestTokenHashIsPlainSHA256 states the other half: the hash is deliberately
// fast and unsalted, because the input is 256 bits from crypto/rand. Anyone
// tempted to "harden" this into argon2 would be adding real per-request cost on
// the sign-in path against an attacker who has nothing to guess — and would
// silently invalidate every stored token while doing it.
func TestTokenHashIsPlainSHA256(t *testing.T) {
	token, err := magicToken()
	if err != nil {
		t.Fatalf("magicToken: %v", err)
	}
	sum := sha256.Sum256([]byte(token))
	if got, want := tokenHash(token), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("tokenHash = %q, want plain hex SHA-256 %q", got, want)
	}
	// Same input, same output: the lookup is an indexed equality on the stored
	// hash, so a salt here would make redemption impossible rather than safer.
	first, second := tokenHash(token), tokenHash(token)
	if first != second {
		t.Errorf("tokenHash is not deterministic (%q then %q); a stored token could never be found again",
			first, second)
	}
}

// TestMagicTokenIsUnguessable is what justifies the fast hash above. 256 bits
// from crypto/rand is the reason there is nothing for argon2 to slow down.
func TestMagicTokenIsUnguessable(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		token, err := magicToken()
		if err != nil {
			t.Fatalf("magicToken: %v", err)
		}
		// 32 bytes base64url-encoded without padding.
		if len(token) != 43 {
			t.Fatalf("magicToken length = %d, want 43 (32 random bytes); a shorter token would be guessable", len(token))
		}
		if seen[token] {
			t.Fatal("magicToken repeated a value within 100 draws")
		}
		seen[token] = true
	}
}

// TestLoginSaysTheSameThingRegardless is the regression guard for the account
// enumeration oracle. POST /login used to answer 401 "user not found" for an
// unknown address and 200 "Check your email..." for a known one, which let an
// anonymous caller test any address against the customer list.
//
// The handler needs a database to exercise end to end, so this pins the thing
// that made the two branches distinguishable: there is exactly one response
// string, and it commits to nothing.
func TestLoginSaysTheSameThingRegardless(t *testing.T) {
	lower := strings.ToLower(loginAccepted)
	for _, leak := range []string{"not found", "no account", "unknown", "exists", "invalid"} {
		if strings.Contains(lower, leak) {
			t.Errorf("the login response contains %q; it must not reveal whether the address has an account", leak)
		}
	}
	// The phrasing has to stay conditional. "We sent you a link" is a claim only
	// true for an address that exists, and a user who mistypes their address is
	// owed the truth that nothing may arrive.
	if !strings.Contains(loginAccepted, "If that address has an account") {
		t.Errorf("loginAccepted = %q, want a conditional that holds for both branches", loginAccepted)
	}
}
