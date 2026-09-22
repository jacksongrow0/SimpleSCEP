package pki

import (
	"fmt"
	"os"
	"strings"
)

// KEY_PROVIDER selects the key implementation. Production deployments use
// google or azure. local is a deprecated, development-only in-memory provider.
const (
	ProtectionHSM      = "hsm"
	ProtectionSoftware = "software"
	KeyProviderGoogle  = "google"
	KeyProviderAzure   = "azure"
	KeyProviderLocal   = "local"
)

// KeyProviderName returns the configured production provider. Google remains
// the default so existing deployments do not change providers during upgrade.
func KeyProviderName() string {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("KEY_PROVIDER")))
	if provider == "" {
		return KeyProviderGoogle
	}
	return provider
}

// ValidateProtection checks a per-CA key protection selection. There is no
// implicit default: callers must make the software/HSM choice explicit.
func ValidateProtection(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != ProtectionSoftware && value != ProtectionHSM {
		return "", fmt.Errorf("key protection must be software or hsm")
	}
	return value, nil
}

func keyMatchesProtection(info KeyInfo, protection string) bool {
	if protection == ProtectionSoftware {
		return info.ProtectionLevel == "SOFTWARE"
	}
	return info.ProtectionLevel == "HSM"
}

func protectionFromExportPosture(posture string) string {
	if posture == ExportPostureNonExportableSoftware || posture == ExportPostureImportedSoftware {
		return ProtectionSoftware
	}
	return ProtectionHSM
}

// KeyProviderSummary is deployment-level copy; protection is deliberately not
// implied because it is selected independently for every CA.
func KeyProviderSummary() string {
	switch KeyProviderName() {
	case KeyProviderAzure:
		return "Azure Key Vault · Per-CA software or HSM"
	case KeyProviderLocal:
		return "Local in-memory keys · Deprecated development mode"
	default:
		return "Google Cloud KMS · Per-CA software or HSM"
	}
}

// CRLRefreshInterval is how often a CRL is republished, exported so the
// Organization page can state the real cadence rather than a number typed into a
// template.
const CRLRefreshInterval = revocationValidity

// KeyLocation is the provider location CA keys live in when configuration
// exposes it. Google key-ring names include a location; Azure Key Vault URLs do
// not, so Azure returns "" rather than presenting a vault hostname as a region.
//
// It exists because the Organization page previously asserted a hardcoded data
// region. A Google key ring's location is the one region this application can
// derive from provider configuration.
//
// The resource name is projects/<p>/locations/<loc>/keyRings/<r>, so the location
// is the segment after "locations". Anything that does not parse yields "" and the
// page then says nothing rather than guessing.
func KeyLocation() string {
	if KeyProviderName() == KeyProviderAzure {
		return ""
	}
	parts := strings.Split(os.Getenv("GOOGLE_CLOUD_KMS_KEY_RING"), "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
