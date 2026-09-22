package scep

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"

	"github.com/jacksongrow0/SimpleSCEP/internal/enroll"
	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

// EKUChoices is the set an administrator may permit on the SCEP endpoint, in
// the order the policy form renders them.
//
// It is deliberately narrower than the PKI layer's full list. ocsp_signing is
// excluded because RFC 6960 treats a certificate carrying it as a delegated
// responder for its issuer, so a device that obtained one from this endpoint
// could sign "good" responses for certificates the same CA has revoked — a
// straight escalation out of device enrollment. time_stamping and mac_address
// are excluded as having no enrollment meaning; a deployment that genuinely
// needs either should issue it from the certificates UI, where a human is
// naming one certificate rather than opening a device-reachable path to it.
var EKUChoices = []string{
	appPKI.EKUClientAuth,
	appPKI.EKUServerAuth,
	appPKI.EKUEmailProtection,
	appPKI.EKUCodeSigning,
	appPKI.EKUSmartcardLogon,
	appPKI.EKUIPSECEndSystem,
	appPKI.EKUIPSECTunnel,
	appPKI.EKUIPSECUser,
}

var ekuLabels = map[string]string{
	appPKI.EKUClientAuth:      "Client authentication",
	appPKI.EKUServerAuth:      "Server authentication",
	appPKI.EKUEmailProtection: "Email protection (S/MIME)",
	appPKI.EKUCodeSigning:     "Code signing",
	appPKI.EKUSmartcardLogon:  "Smartcard logon",
	appPKI.EKUIPSECEndSystem:  "IPsec end system",
	appPKI.EKUIPSECTunnel:     "IPsec tunnel",
	appPKI.EKUIPSECUser:       "IPsec user",
}

// EKULabel renders a usage token for an administrator, falling back to the
// token itself so a value stored before it was offered here still reads.
func EKULabel(token string) string {
	if label, ok := ekuLabels[token]; ok {
		return label
	}
	return token
}

// ValidateAllowedEKUs checks a proposed endpoint allow list before it is
// stored: every entry must be a usage this endpoint may offer at all, and must
// be within the issuing CA's own profile. Issuance enforces the latter again,
// but an administrator should learn it while saving the policy rather than from
// a device that silently fails to enroll.
func (s Service) ValidateAllowedEKUs(ctx context.Context, e Endpoint, ekus []string) error {
	if len(ekus) == 0 {
		return fmt.Errorf("allow at least one extended key usage")
	}
	ca, err := s.pkiRepo.CA(ctx, e.OrganizationID, e.CAID)
	if err != nil {
		return err
	}
	profile := enroll.SplitCSV(ca.IssuanceEKUs)
	for _, t := range ekus {
		if !slices.Contains(EKUChoices, t) {
			return fmt.Errorf("unsupported extended key usage %q", t)
		}
		if !slices.Contains(profile, t) {
			return fmt.Errorf("%s is not in the issuing CA's profile", EKULabel(t))
		}
	}
	return nil
}

// narrowEKUs validates the usages a one-time challenge pins its enrollment to.
// A challenge may only narrow the endpoint's allow list, so minting one can
// never become a way around the issuance policy. An empty request pins nothing.
func narrowEKUs(allowedCSV string, expected []string) ([]string, error) {
	if len(expected) == 0 {
		return nil, nil
	}
	allowed := enroll.SplitCSV(allowedCSV)
	var out []string
	seen := map[string]bool{}
	for _, t := range expected {
		if !slices.Contains(allowed, t) {
			return nil, fmt.Errorf("%s is not permitted by this endpoint's issuance policy", EKULabel(t))
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

// sameEKUSet compares two usage lists as sets. Extended key usages are a set in
// the certificate rather than a sequence, so pinning them must not depend on
// the order a client happened to serialize them in — the trap the SAN pin,
// which is an ordered comparison, already has.
func sameEKUSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// RequestedEKUs reads the extendedKeyUsage a CSR asks for. Go populates
// x509.CertificateRequest.Extensions from the PKCS#9 extensionRequest attribute
// but gives the type no EKU field, so the DER is decoded here. A request
// carrying no such extension yields nil, which ResolveEKUs reads as "no
// preference" rather than as "none".
func RequestedEKUs(csr *x509.CertificateRequest) ([]string, error) {
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidExtKeyUsage) {
			continue
		}
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
			return nil, fmt.Errorf("unreadable extended key usage request")
		}
		out := make([]string, 0, len(oids))
		for _, oid := range oids {
			out = append(out, appPKI.EKUToken(oid))
		}
		return out, nil
	}
	return nil, nil
}

// ResolveEKUs decides the extended key usages an enrollment is issued with. The
// endpoint's allow list is the ceiling, and a request that asks for a subset is
// issued exactly that subset — which is what lets one endpoint serve an Intune
// Wi-Fi profile and an S/MIME profile at the same time without either receiving
// the other's usage.
//
// A request that asks for nothing gets client authentication alone, never the
// whole allow list. Permitting a usage has to stay a decision about what a
// device may ask for, not a grant to every device that asks for nothing:
// widening the ceiling so the finance team can enroll S/MIME certificates must
// not put emailProtection on every Wi-Fi certificate whose client omits the
// extension.
//
// Asking for a usage the endpoint does not permit is refused rather than
// silently narrowed, so a mismatch between an MDM profile and this policy
// surfaces in the enrollment log instead of issuing a certificate that will not
// do what the profile promised.
// It is exported because internal/est enrolls the same way — a CSR that may
// carry an extendedKeyUsage request against an endpoint allow list — and this
// policy should not exist in two versions that can drift apart.
func ResolveEKUs(allowedCSV string, requested []string) ([]string, error) {
	allowed := enroll.SplitCSV(allowedCSV)
	if len(allowed) == 0 {
		allowed = []string{appPKI.EKUClientAuth}
	}
	if len(requested) == 0 {
		if !slices.Contains(allowed, appPKI.EKUClientAuth) {
			return nil, fmt.Errorf("this endpoint does not permit client authentication, so a request must state the extended key usage it needs")
		}
		return []string{appPKI.EKUClientAuth}, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, t := range requested {
		if !slices.Contains(allowed, t) {
			return nil, fmt.Errorf("extended key usage %q is not permitted by this endpoint", EKULabel(t))
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}
