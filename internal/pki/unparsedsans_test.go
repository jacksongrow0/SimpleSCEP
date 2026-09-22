package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
)

// sanExtension builds a subjectAltName extension out of raw GeneralName values.
func sanExtension(t *testing.T, names ...asn1.RawValue) *pkix.Extension {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence,
		IsCompound: true, Bytes: concatDER(t, names...)})
	if err != nil {
		t.Fatalf("marshalling SAN sequence: %v", err)
	}
	return &pkix.Extension{Id: oidSubjectAltName, Value: der}
}

func concatDER(t *testing.T, names ...asn1.RawValue) []byte {
	t.Helper()
	var out []byte
	for _, name := range names {
		der, err := asn1.Marshal(name)
		if err != nil {
			t.Fatalf("marshalling GeneralName: %v", err)
		}
		out = append(out, der...)
	}
	return out
}

func generalName(tag int, body []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: body}
}

// TestUnparsedSANsSurfacesTagsX509DoesNotModel is the regression that matters.
//
// pki copies the requested SAN extension into the certificate verbatim, so any
// GeneralName form that neither x509 nor this function enumerates is issued
// without a policy ever seeing it. directoryName [4] and registeredID [8] are the
// ones with teeth: AD-integrated relying parties authorize on them.
func TestUnparsedSANsSurfacesTagsX509DoesNotModel(t *testing.T) {
	for _, tc := range []struct {
		name string
		tag  int
	}{
		{"x400Address", 3},
		{"directoryName", 4},
		{"ediPartyName", 5},
		{"registeredID", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UnparsedSANs(sanExtension(t, generalName(tc.tag, []byte{0xde, 0xad, 0xbe, 0xef})))
			if len(got) != 1 {
				t.Fatalf("UnparsedSANs() = %v, want exactly one entry", got)
			}
			if !strings.HasPrefix(got[0], "tag=") {
				t.Errorf("UnparsedSANs() = %q, want a tag=N:hex rendering", got[0])
			}
			if !strings.Contains(got[0], "deadbeef") {
				t.Errorf("UnparsedSANs() = %q, want the value to be visible", got[0])
			}
		})
	}
}

// The forms x509 already parses must not be repeated here: every caller lists
// those from the parsed certificate and appends this, so returning them too would
// double-count a name and break ACME's exact-set comparison.
func TestUnparsedSANsSkipsTheFormsX509Parses(t *testing.T) {
	ext := sanExtension(t,
		generalName(1, []byte("ops@example.com")),
		generalName(2, []byte("device.corp.example")),
		generalName(6, []byte("https://example.com")),
		generalName(7, []byte{192, 0, 2, 1}),
	)
	if got := UnparsedSANs(ext); len(got) != 0 {
		t.Errorf("UnparsedSANs() = %v, want none", got)
	}
}

// The bypass this closes, stated as the policy decision it produces: a request
// pairing an allowed dNSName with an unpoliceable directoryName must be refused
// by an endpoint whose SAN policy admits only the dNSName.
func TestSANPolicyRefusesAnUnparsedNameSmuggledBesideAnAllowedOne(t *testing.T) {
	policy := NamePolicy{SAN: `^[a-z0-9.-]+\.corp\.example$`}

	if err := policy.Check("CN=device7", []string{"device7.corp.example"}); err != nil {
		t.Fatalf("the allowed name alone was refused: %v", err)
	}

	smuggled := sanExtension(t,
		generalName(2, []byte("device7.corp.example")),
		generalName(4, []byte("CN=Domain Admin,DC=corp,DC=example")),
	)
	// What a caller assembles: the parsed forms, then whatever else the extension
	// carries.
	sans := append([]string{"device7.corp.example"}, UnparsedSANs(smuggled)...)
	if err := policy.Check("CN=device7", sans); err == nil {
		t.Fatalf("a directoryName SAN passed a policy that admits only dNSNames: %v", sans)
	}
}
