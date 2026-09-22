package pki

import "testing"

func TestValidateProtection(t *testing.T) {
	for _, value := range []string{ProtectionSoftware, ProtectionHSM, " HSM "} {
		if _, err := ValidateProtection(value); err != nil {
			t.Errorf("ValidateProtection(%q): %v", value, err)
		}
	}
	for _, value := range []string{"", "local", "hardware"} {
		if _, err := ValidateProtection(value); err == nil {
			t.Errorf("ValidateProtection(%q) succeeded", value)
		}
	}
}

func TestKeyProviderDefaultsToGoogle(t *testing.T) {
	t.Setenv("KEY_PROVIDER", "")
	if got := KeyProviderName(); got != KeyProviderGoogle {
		t.Fatalf("default key provider = %q, want google", got)
	}
	t.Setenv("KEY_PROVIDER", " Azure ")
	if got := KeyProviderName(); got != KeyProviderAzure {
		t.Fatalf("key provider = %q, want azure", got)
	}
}

func TestValidateKeyInfoProtection(t *testing.T) {
	software := KeyInfo{Name: "k", Algorithm: AlgorithmECDSAP256SHA256, ProtectionLevel: "SOFTWARE", Purpose: "ASYMMETRIC_SIGN"}
	if err := validateKeyInfo(software); err != nil {
		t.Errorf("software key rejected: %v", err)
	}
	hsm := software
	hsm.ProtectionLevel = "HSM"
	if err := validateKeyInfo(hsm); err != nil {
		t.Errorf("hsm key rejected: %v", err)
	}
	singleTenant := software
	singleTenant.ProtectionLevel = "HSM_SINGLE_TENANT"
	if err := validateKeyInfo(singleTenant); err == nil {
		t.Error("single-tenant HSM key must be rejected")
	}
}

func TestExportPostureMapping(t *testing.T) {
	cases := []struct {
		level    string
		imported bool
		want     string
	}{
		{"HSM", false, ExportPostureNonExportableHSM},
		{"HSM", true, ExportPostureImportedHSM},
		{"SOFTWARE", false, ExportPostureNonExportableSoftware},
		{"SOFTWARE", true, ExportPostureImportedSoftware},
	}
	for _, tc := range cases {
		if got := exportPosture(tc.level, tc.imported); got != tc.want {
			t.Errorf("exportPosture(%q, %v) = %q, want %q", tc.level, tc.imported, got, tc.want)
		}
	}
}
