package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSecretHashesAreSaltedAndVerify(t *testing.T) {
	a, err := HashSecret("high-entropy-secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashSecret("high-entropy-secret")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("secret hashes must use unique salts")
	}
	if !VerifySecret(a, "high-entropy-secret") || VerifySecret(a, "wrong") {
		t.Fatal("secret verification failed")
	}
}

// A stored value that is not two base64 fields must fail closed rather than
// error, so a truncated or corrupted row cannot authenticate anything.
func TestMalformedHashNeverVerifies(t *testing.T) {
	for _, encoded := range []string{"", "no-separator", "a.b.c", "!!!.!!!"} {
		if VerifySecret(encoded, "anything") {
			t.Fatalf("malformed hash %q verified", encoded)
		}
	}
}

func TestRandomSecretIsUnique(t *testing.T) {
	a, err := RandomSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || a == "" {
		t.Fatal("secrets must be unique and non-empty")
	}
}

func TestPublicKeyPolicy(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if ValidatePublicKey(&weak.PublicKey) == nil {
		t.Fatal("weak RSA key accepted")
	}
	if err := ValidatePublicKey(&strong.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKey(&ec.PublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestSplitCSVDropsBlanks(t *testing.T) {
	got := SplitCSV(" a , ,b,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	if SplitCSV("") != nil {
		t.Fatal("an empty list must stay nil")
	}
}

// The typed confirmation is a control, not a courtesy: it must tolerate case
// and surrounding whitespace but never accept an empty box.
func TestConfirmsEndpointName(t *testing.T) {
	if !ConfirmsEndpointName("  Prod-Endpoint ", "prod-endpoint") {
		t.Fatal("case and whitespace differences must still confirm")
	}
	if ConfirmsEndpointName("", "") {
		t.Fatal("an empty confirmation must never pass")
	}
	if ConfirmsEndpointName("other", "prod-endpoint") {
		t.Fatal("a different name must not confirm")
	}
}
