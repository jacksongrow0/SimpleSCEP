package database

import (
	"os"
	"strings"
	"testing"
)

// transaction_timeout was added in PostgreSQL 17. pg_dump emits it in a dump
// made by that version, but the schema itself does not depend on it. Keeping the
// generated SET in the baseline prevents otherwise-compatible older servers
// from applying any of the schema.
func TestBaselineDoesNotRequirePostgreSQL17SessionSettings(t *testing.T) {
	sql, err := os.ReadFile("migrations/0001_open_source.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sql), "transaction_timeout") {
		t.Fatal("baseline migration contains PostgreSQL 17-only transaction_timeout setting")
	}
}
