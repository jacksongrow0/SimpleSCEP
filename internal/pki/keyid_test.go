package pki

import (
	"regexp"
	"strings"
	"testing"
)

const testOrgID = "799e642d-da87-48aa-8db1-9f22f68f69f6"

func testKeyID(name string) string {
	return keyID(CreateKeyRequest{OrgID: testOrgID, CAType: "issuing", CAName: name})
}

// TestKeyIDHasNoDoubledSeparators covers what an operator reads in the KMS
// console. A CA named with a trailing space used to produce "…-test--<hex>",
// and one with a slash three separators in a row, because the sanitiser mapped
// each character to a dash and nothing collapsed the run.
func TestKeyIDHasNoDoubledSeparators(t *testing.T) {
	for _, name := range []string{
		"Test", "Test ", " Test", "Test / Prod", "Test__Prod", "a...b",
		"  ", "", "A very long certificate authority name for many devices",
	} {
		id := testKeyID(name)
		if strings.Contains(id, "--") {
			t.Errorf("keyID(%q) = %q has a doubled separator", name, id)
		}
		if strings.HasPrefix(id, "-") || strings.HasSuffix(id, "-") {
			t.Errorf("keyID(%q) = %q starts or ends with a separator", name, id)
		}
	}
}

// TestKeyIDIsAcceptableToKMS pins the format Cloud KMS will accept at all: a
// CryptoKey id must match [a-zA-Z0-9_-]{1,63}. Exceeding it is rejected at
// creation, which surfaces as a failed CA rather than as anything about names.
func TestKeyIDIsAcceptableToKMS(t *testing.T) {
	valid := regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)
	for _, name := range []string{
		"Test", "", strings.Repeat("long name ", 20), "ünïcode ✓ name", "Test / Prod",
	} {
		id := testKeyID(name)
		if !valid.MatchString(id) {
			t.Errorf("keyID(%q) = %q is not a valid CryptoKey id (len %d)", name, id, len(id))
		}
	}
}

// TestKeyIDLeavesRoomForTheCAName is the point of the short organization
// prefix. The whole uuid took 36 of the 63 characters, leaving five for the
// name, so the only human-meaningful part of the id was the part truncated
// away.
func TestKeyIDLeavesRoomForTheCAName(t *testing.T) {
	id := testKeyID("Issuing Test")
	if !strings.Contains(id, "issuing-test") {
		t.Errorf("keyID = %q; the CA name did not survive", id)
	}
	if !strings.HasPrefix(id, "799e642d-") {
		t.Errorf("keyID = %q; the organization prefix is missing", id)
	}
	if strings.Contains(id, testOrgID) {
		t.Errorf("keyID = %q still carries the whole organization uuid", id)
	}
	// A name long enough to be cut should still be recognisable.
	long := testKeyID("Devices EMEA Production Fleet")
	if !strings.Contains(long, "devices-emea") {
		t.Errorf("keyID = %q lost too much of a long name", long)
	}
}

// TestImportJobIDFitsWithItsSuffix covers the id that could not be created at
// all. It was keyID(req) + "-import", and keyID may use all 63 characters, so a
// long CA name produced a 70-character id that Cloud KMS rejects.
func TestImportJobIDFitsWithItsSuffix(t *testing.T) {
	valid := regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)
	for _, name := range []string{"Test", strings.Repeat("long name ", 20), "Devices EMEA Production Fleet"} {
		id := importJobID(CreateKeyRequest{OrgID: testOrgID, CAType: "issuing", CAName: name})
		if !valid.MatchString(id) {
			t.Errorf("importJobID(%q) = %q is not a valid id (len %d)", name, id, len(id))
		}
		if !strings.HasSuffix(id, "-import") {
			t.Errorf("importJobID(%q) = %q lost its suffix", name, id)
		}
	}
}

// TestKMSLabelsCarryTheWholeOrgID is the other half of shortening the prefix:
// the full organization id has to remain queryable in the KMS console.
func TestKMSLabelsCarryTheWholeOrgID(t *testing.T) {
	labels := kmsLabels("  " + strings.ToUpper(testOrgID) + "  ")
	if labels["org"] != testOrgID {
		t.Errorf("labels[org] = %q, want %q", labels["org"], testOrgID)
	}
}

// TestKeyIDIsUniquePerCall records why the random suffix is there: two CAs with
// the same name in the same organization must not collide, and neither must a
// rotation of one.
func TestKeyIDIsUniquePerCall(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		id := testKeyID("Test")
		if seen[id] {
			t.Fatalf("keyID produced %q twice", id)
		}
		seen[id] = true
	}
}
