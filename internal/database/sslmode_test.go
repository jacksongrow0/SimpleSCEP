package database

import (
	"strings"
	"testing"
)

// TestAssertSSLModeRefusesPlaintextInProduction pins the gate that stops a
// deployment shipping with the sslmode a developer uses against a local
// Postgres. Every other startup setting fails closed; this one did not until it
// was given a floor.
func TestAssertSSLModeRefusesPlaintextInProduction(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer", "DISABLE", " prefer "} {
		t.Setenv("POSTGRES_SSL", mode)
		err := AssertSSLMode(false)
		if err == nil {
			t.Errorf("POSTGRES_SSL=%q was accepted on a production host", mode)
			continue
		}
		if !strings.Contains(err.Error(), "plaintext") {
			t.Errorf("POSTGRES_SSL=%q: error does not say what is wrong: %v", mode, err)
		}
	}
}

// The same values are exactly what a developer running against a local Postgres
// needs, so the gate has to be keyed on the host rather than on the value alone.
func TestAssertSSLModeAllowsPlaintextInDevelopment(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer"} {
		t.Setenv("POSTGRES_SSL", mode)
		if err := AssertSSLMode(true); err != nil {
			t.Errorf("POSTGRES_SSL=%q refused on a development host: %v", mode, err)
		}
	}
}

func TestAssertSSLModeAcceptsEncryptedModes(t *testing.T) {
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		t.Setenv("POSTGRES_SSL", mode)
		if err := AssertSSLMode(false); err != nil {
			t.Errorf("POSTGRES_SSL=%q refused: %v", mode, err)
		}
	}
}
