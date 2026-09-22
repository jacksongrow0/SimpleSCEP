package pki

import (
	"bytes"
	"context"
	"testing"
)

func TestFakeProviderProtectsWithPurposeBinding(t *testing.T) {
	p := NewFakeProvider()
	ciphertext, err := p.Protect(context.Background(), "endpoint-a", []byte("private material"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("private material")) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	plain, err := p.Unprotect(context.Background(), "endpoint-a", ciphertext)
	if err != nil || string(plain) != "private material" {
		t.Fatalf("round trip failed: %q %v", plain, err)
	}
	if _, err := p.Unprotect(context.Background(), "endpoint-b", ciphertext); err == nil {
		t.Fatal("purpose binding was not enforced")
	}
}
