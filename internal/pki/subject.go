package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var countryRe = regexp.MustCompile(`^[A-Z]{2}$`)

// BuildSubject validates structured subject input and assembles a pkix.Name.
// CommonName is required; the rest are optional. Country must be an ISO
// 3166-1 alpha-2 code (format check only).
func BuildSubject(in SubjectInput) (pkix.Name, error) {
	cn := strings.TrimSpace(in.CommonName)
	if cn == "" {
		return pkix.Name{}, fmt.Errorf("common name (CN) is required")
	}
	if err := validateRDN("common name", cn); err != nil {
		return pkix.Name{}, err
	}
	name := pkix.Name{CommonName: cn}
	optional := []struct {
		label string
		value string
		dst   *[]string
	}{
		{"organization", in.Organization, &name.Organization},
		{"organizational unit", in.OrganizationalUnit, &name.OrganizationalUnit},
		{"state/province", in.Province, &name.Province},
		{"locality", in.Locality, &name.Locality},
	}
	for _, f := range optional {
		v := strings.TrimSpace(f.value)
		if v == "" {
			continue
		}
		if err := validateRDN(f.label, v); err != nil {
			return pkix.Name{}, err
		}
		*f.dst = []string{v}
	}
	if c := strings.ToUpper(strings.TrimSpace(in.Country)); c != "" {
		if !countryRe.MatchString(c) {
			return pkix.Name{}, fmt.Errorf("country must be a two-letter ISO 3166-1 code")
		}
		name.Country = []string{c}
	}
	return name, nil
}

func validateRDN(label, value string) error {
	if len(value) > 128 {
		return fmt.Errorf("%s must be at most 128 characters", label)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains invalid characters", label)
		}
	}
	return nil
}

// standardEKUs maps tokens that x509 understands natively.
var standardEKUs = map[string]x509.ExtKeyUsage{
	EKUClientAuth:      x509.ExtKeyUsageClientAuth,
	EKUServerAuth:      x509.ExtKeyUsageServerAuth,
	EKUCodeSigning:     x509.ExtKeyUsageCodeSigning,
	EKUEmailProtection: x509.ExtKeyUsageEmailProtection,
	EKUIPSECEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
	EKUIPSECTunnel:     x509.ExtKeyUsageIPSECTunnel,
	EKUIPSECUser:       x509.ExtKeyUsageIPSECUser,
	EKUTimeStamping:    x509.ExtKeyUsageTimeStamping,
	EKUOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
}

// namedOIDEKUs are well-known usages Go's x509 has no enum for; they are
// emitted through UnknownExtKeyUsage.
var namedOIDEKUs = map[string]asn1.ObjectIdentifier{
	EKUSmartcardLogon: {1, 3, 6, 1, 4, 1, 311, 20, 2, 2}, // Microsoft smartcard logon
	EKUMacAddress:     {1, 3, 6, 1, 1, 1, 1, 22},         // macAddress
}

// EKUAnyPurpose is anyExtendedKeyUsage. Most validators read it as "matches
// every purpose", so a certificate carrying it is constrained by nothing: a
// stolen device key becomes usable for server authentication or code signing
// under an identity this CA vouched for. It is never issuable; an operator who
// needs three usages lists three usages.
const EKUAnyPurpose = "2.5.29.37.0"

// ekuOIDs is the wire form of every named usage, so an extendedKeyUsage a
// requester asks for can be named back to its token. standardEKUs above maps
// the same tokens onto Go's enum for issuance; this table is what a CSR carries.
var ekuOIDs = map[string]asn1.ObjectIdentifier{
	EKUClientAuth:      {1, 3, 6, 1, 5, 5, 7, 3, 2},
	EKUServerAuth:      {1, 3, 6, 1, 5, 5, 7, 3, 1},
	EKUCodeSigning:     {1, 3, 6, 1, 5, 5, 7, 3, 3},
	EKUEmailProtection: {1, 3, 6, 1, 5, 5, 7, 3, 4},
	EKUIPSECEndSystem:  {1, 3, 6, 1, 5, 5, 7, 3, 5},
	EKUIPSECTunnel:     {1, 3, 6, 1, 5, 5, 7, 3, 6},
	EKUIPSECUser:       {1, 3, 6, 1, 5, 5, 7, 3, 7},
	EKUTimeStamping:    {1, 3, 6, 1, 5, 5, 7, 3, 8},
	EKUOCSPSigning:     {1, 3, 6, 1, 5, 5, 7, 3, 9},
	EKUSmartcardLogon:  {1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
	EKUMacAddress:      {1, 3, 6, 1, 1, 1, 1, 22},
}

// EKUToken names an extendedKeyUsage OID with the token this codebase uses,
// falling back to the dotted form so an unrecognized usage is still reportable
// rather than silently dropped.
func EKUToken(oid asn1.ObjectIdentifier) string {
	for token, known := range ekuOIDs {
		if oid.Equal(known) {
			return token
		}
	}
	return oid.String()
}

// ValidateEKUs checks tokens against the supported set — named usages or
// custom dotted OIDs — deduplicates while preserving order, and defaults to
// client_auth when empty. Custom OIDs are normalized to their canonical
// dotted form.
func ValidateEKUs(tokens []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		_, standard := standardEKUs[t]
		_, named := namedOIDEKUs[t]
		if !standard && !named {
			oid, err := parseOID(t)
			if err != nil {
				return nil, fmt.Errorf("unsupported extended key usage %q (use a known usage or a dotted OID)", t)
			}
			t = oid.String()
			if t == EKUAnyPurpose {
				return nil, fmt.Errorf("extended key usage %q (any purpose) is not allowed; list the specific usages instead", EKUAnyPurpose)
			}
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		out = []string{EKUClientAuth}
	}
	return out, nil
}

func parseOID(raw string) (asn1.ObjectIdentifier, error) {
	if len(raw) > 64 {
		return nil, fmt.Errorf("oid too long")
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oid needs at least two arcs")
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid oid arc %q", p)
		}
		oid[i] = n
	}
	if oid[0] > 2 {
		return nil, fmt.Errorf("invalid oid root arc")
	}
	return oid, nil
}

// ekuUsages expands a stored profile into the x509 template fields: native
// usages plus OIDs (named or custom) for UnknownExtKeyUsage.
func ekuUsages(csv string) ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier) {
	var usages []x509.ExtKeyUsage
	var oids []asn1.ObjectIdentifier
	for t := range strings.SplitSeq(csv, ",") {
		t = strings.TrimSpace(t)
		if u, ok := standardEKUs[t]; ok {
			usages = append(usages, u)
			continue
		}
		if oid, ok := namedOIDEKUs[t]; ok {
			oids = append(oids, oid)
			continue
		}
		if oid, err := parseOID(t); err == nil {
			oids = append(oids, oid)
		}
	}
	if len(usages) == 0 && len(oids) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	return usages, oids
}

func ValidateAlgorithm(a string) (string, error) {
	switch a {
	case "":
		return AlgorithmECDSAP256SHA256, nil
	case AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384, AlgorithmRSA3072SHA256, AlgorithmRSA4096SHA256:
		return a, nil
	default:
		return "", fmt.Errorf("unsupported key algorithm %q", a)
	}
}

// ValidateLeafAlgorithm checks a leaf key algorithm token, defaulting to
// ECDSA P-256 when empty.
func ValidateLeafAlgorithm(a string) (string, error) {
	switch a {
	case "":
		return LeafECP256, nil
	case LeafRSA2048, LeafRSA3072, LeafRSA4096, LeafECP256, LeafECP384:
		return a, nil
	default:
		return "", fmt.Errorf("unsupported key algorithm %q", a)
	}
}

// GenerateLeafKey creates an end-entity keypair in process memory and returns
// the signer plus its PKCS#8 PEM encoding. The key is handed to the requester
// exactly once and must never be persisted or logged.
func GenerateLeafKey(algorithm string) (crypto.Signer, string, error) {
	var key crypto.Signer
	var err error
	switch algorithm {
	case LeafRSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case LeafRSA3072:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case LeafRSA4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case LeafECP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case LeafECP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, "", fmt.Errorf("unsupported key algorithm %q", algorithm)
	}
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// leafValidityDays validates a requested leaf validity; 0 applies the default.
func leafValidityDays(days int) (int, error) {
	if days == 0 {
		return 365, nil
	}
	if days < 1 || days > MaxLeafValidityDays {
		return 0, fmt.Errorf("validity must be between 1 day and 10 years")
	}
	return days, nil
}

// ekuSelection resolves the EKUs applied to a leaf: the requested tokens are
// normalized and must all be in the issuing CA's profile, and required (when
// set) is always included — a CA whose profile lacks it cannot issue the
// certificate at all. An empty request with no required usage applies the CA's
// full profile.
func ekuSelection(requested []string, caProfile, required string) ([]string, error) {
	if len(requested) == 0 && required == "" {
		var profile []string
		for t := range strings.SplitSeq(caProfile, ",") {
			if t = strings.TrimSpace(t); t != "" {
				profile = append(profile, t)
			}
		}
		return profile, nil
	}
	if required != "" {
		requested = append([]string{required}, requested...)
	}
	ekus, err := ValidateEKUs(requested)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for t := range strings.SplitSeq(caProfile, ",") {
		if t = strings.TrimSpace(t); t != "" {
			allowed[t] = true
		}
	}
	for _, t := range ekus {
		if !allowed[t] {
			return nil, fmt.Errorf("extended key usage %q is not permitted by this issuing CA", t)
		}
	}
	return ekus, nil
}

// keyEstablishmentEKUs are the purposes whose protocols establish a key with
// the certified key, rather than only signing with it. They are what justify
// the encryption bits below.
var keyEstablishmentEKUs = map[string]bool{
	EKUClientAuth: true, EKUServerAuth: true, EKUEmailProtection: true, EKUSmartcardLogon: true,
	EKUIPSECEndSystem: true, EKUIPSECTunnel: true, EKUIPSECUser: true,
}

// agreementEKUs are the purposes that establish a key by agreement rather than
// by transport, which is the only way an EC key can do it.
var agreementEKUs = map[string]bool{
	EKUEmailProtection: true, EKUIPSECEndSystem: true, EKUIPSECTunnel: true, EKUIPSECUser: true,
}

// leafKeyUsage returns the key usage bits for an end-entity certificate. Every
// purpose this CA issues signs, so digitalSignature is always set; the
// encryption bits are added only for purposes that actually establish a key, so
// a code-signing or timestamping certificate no longer carries a keyEncipherment
// bit it cannot use. RSA establishes keys by transport (keyEncipherment) and EC
// by agreement (keyAgreement), so the bit follows the key type as well as the
// purpose — without keyAgreement an EC S/MIME certificate could sign mail but
// never receive encrypted mail.
//
// An unrecognized usage — a custom dotted OID — is treated as possibly needing
// both, because narrowing bits on a purpose this code cannot reason about would
// break a deployment silently.
// minRSABits is the floor for a subscriber key. 2048 is the smallest RSA size
// still accepted for public trust, and the CA has no business certifying a key
// weaker than one it would refuse for itself.
const minRSABits = 2048

// ValidatePublicKey refuses to certify a key too weak to be worth signing.
//
// This is the floor, applied in signLeaf so every issuance path crosses it —
// including the administrator's own POST /certificates/csr, which reaches Issue
// without passing through any protocol's checks. It is deliberately the floor
// and not a policy: the device protocols narrow it further (scep.validatePublicKey
// allows only P-256 and P-384, because a fleet enrolling with exotic curves is
// far more likely to be a mistake than a requirement), while ACME clients
// legitimately present Ed25519 and P-521 and must keep working.
func ValidatePublicKey(pub crypto.PublicKey) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < minRSABits {
			return fmt.Errorf("RSA keys smaller than %d bits are not allowed", minRSABits)
		}
	case *ecdsa.PublicKey:
		if key.Curve == nil {
			return fmt.Errorf("EC key has no curve")
		}
		if bits := key.Curve.Params().BitSize; bits < 256 {
			return fmt.Errorf("EC curves smaller than 256 bits are not allowed, got %d", bits)
		}
	case ed25519.PublicKey:
		// Fixed at 128-bit security; nothing to check.
	default:
		return fmt.Errorf("unsupported public key algorithm %T", pub)
	}
	return nil
}

func leafKeyUsage(pub crypto.PublicKey, ekus []string) x509.KeyUsage {
	usage := x509.KeyUsageDigitalSignature
	establishes, agrees := false, false
	for _, t := range ekus {
		if _, known := standardEKUs[t]; !known {
			if _, named := namedOIDEKUs[t]; !named {
				// A custom OID: assume it may need either bit.
				establishes, agrees = true, true
				break
			}
		}
		if keyEstablishmentEKUs[t] {
			establishes = true
		}
		if agreementEKUs[t] {
			agrees = true
		}
	}
	if _, ok := pub.(*rsa.PublicKey); ok {
		if establishes {
			usage |= x509.KeyUsageKeyEncipherment
		}
		return usage
	}
	if agrees {
		usage |= x509.KeyUsageKeyAgreement
	}
	return usage
}

func validityDays(caType string, days int) (int, error) {
	if days == 0 {
		if caType == CATypeRoot {
			return DefaultRootDays, nil
		}
		return DefaultIssuingDays, nil
	}
	if days < 1 || days > MaxValidityDays {
		return 0, fmt.Errorf("validity must be between 1 day and 30 years")
	}
	return days, nil
}

// ekusWithinParent enforces that every requested EKU is in the parent CA's
// profile; an empty parent profile fails closed and permits nothing.
func ekusWithinParent(ekus []string, parentCSV string) error {
	allowed := map[string]bool{}
	for t := range strings.SplitSeq(parentCSV, ",") {
		if t = strings.TrimSpace(t); t != "" {
			allowed[t] = true
		}
	}
	for _, t := range ekus {
		if !allowed[t] {
			return fmt.Errorf("extended key usage %q is not permitted by the parent root CA", t)
		}
	}
	return nil
}

// exportPosture labels a CA row from the actual protection level of its key
// so software-mode CAs are never presented as HSM-backed.
func exportPosture(protectionLevel string, imported bool) string {
	software := protectionLevel == "SOFTWARE"
	switch {
	case imported && software:
		return ExportPostureImportedSoftware
	case imported:
		return ExportPostureImportedHSM
	case software:
		return ExportPostureNonExportableSoftware
	default:
		return ExportPostureNonExportableHSM
	}
}

// rejectPrivateKeyMaterial refuses any input containing a PEM block that
// looks like key material; user-supplied fields must only ever carry
// certificates or CSRs.
func rejectPrivateKeyMaterial(inputs ...string) error {
	for _, in := range inputs {
		rest := []byte(in)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
				return fmt.Errorf("private key material is not accepted; submit only certificates")
			}
		}
	}
	return nil
}

// Go's x509 models only the rfc822Name, dNSName, uniformResourceIdentifier and
// iPAddress forms of a GeneralName, and re-marshals a pkix.Name only from its
// structured fields. Anything else a client asks for — an emailAddress RDN, or
// Microsoft's userPrincipalName otherName that Intune populates from
// {{UserPrincipalName}} — survives only if the DER is carried through verbatim.
var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidUPN            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

// SubjectAltName returns a request's raw subjectAltName extension, or nil when
// it carries none.
func SubjectAltName(csr *x509.CertificateRequest) *pkix.Extension {
	return SubjectAltNameFrom(csr.Extensions)
}

// SubjectAltNameFrom is the same lookup over an already-issued certificate's
// extensions. It exists so a renewal can be compared against the certificate it
// renews: both x509.Certificate and x509.CertificateRequest carry Extensions, but
// they are different types, and the otherName forms this service issues live only
// in the raw extension.
func SubjectAltNameFrom(exts []pkix.Extension) *pkix.Extension {
	for _, ext := range exts {
		if ext.Id.Equal(oidSubjectAltName) {
			found := ext
			return &found
		}
	}
	return nil
}

// UnparsedSANs lists every subjectAltName entry that Go's x509 does not model,
// so they can be shown and policed alongside the forms it does.
//
// Callers pair this with csr.DNSNames, csr.IPAddresses, csr.EmailAddresses and
// csr.URIs — GeneralName tags 2, 7, 1 and 6 — and this function covers the rest
// of the CHOICE. Between them the two halves enumerate the whole extension,
// which is the property every SAN policy in this service rests on: pki copies
// the requested SAN DER into the certificate verbatim (see signLeaf), so a form
// that appears in neither half is issued without anything having checked it.
//
// This used to return otherName alone and skip every other unmodelled tag. That
// left directoryName [4] and registeredID [8] — both of which AD-integrated
// relying parties authorize on — invisible to endpoint SAN policies, to EST
// identifier pinning, to ACME's exact-set match, and to the same-name comparison
// on SCEP renewal, while still reaching the issued certificate. A CSR asking for
// an allowed dNSName alongside "CN=Domain Admin,DC=corp,DC=example" was issued
// both and policed on one.
//
// A UPN yields its string value, because that is the form an operator writes a
// policy against. Every other otherName yields "oid=hex", and every other tag
// yields "tag=N:hex" — deliberately not a value a sane SAN pattern matches, so
// an endpoint with a policy refuses it and an endpoint without one is unchanged.
func UnparsedSANs(ext *pkix.Extension) []string {
	if ext == nil {
		return nil
	}
	var sans asn1.RawValue
	if _, err := asn1.Unmarshal(ext.Value, &sans); err != nil {
		return nil
	}
	var out []string
	for rest := sans.Bytes; len(rest) > 0; {
		var name asn1.RawValue
		remainder, err := asn1.Unmarshal(rest, &name)
		if err != nil {
			return out
		}
		rest = remainder
		if name.Class != asn1.ClassContextSpecific {
			continue
		}
		// Tags 1, 2, 6 and 7 — rfc822Name, dNSName, uniformResourceIdentifier and
		// iPAddress — are the ones x509 parses, and the caller has already listed
		// them. Everything else in the CHOICE is ours: otherName [0] is rendered
		// below, and x400Address [3], directoryName [4], ediPartyName [5] and
		// registeredID [8] are surfaced as opaque tagged values so a policy has
		// something to refuse.
		switch name.Tag {
		case 1, 2, 6, 7:
			continue
		case 0:
		default:
			out = append(out, "tag="+strconv.Itoa(name.Tag)+":"+hex.EncodeToString(name.Bytes))
			continue
		}
		var typeID asn1.ObjectIdentifier
		valueDER, err := asn1.Unmarshal(name.Bytes, &typeID)
		if err != nil {
			continue
		}
		// The value sits inside an explicit [0] wrapper.
		var wrapper asn1.RawValue
		if _, err := asn1.Unmarshal(valueDER, &wrapper); err != nil {
			continue
		}
		var value asn1.RawValue
		if _, err := asn1.Unmarshal(wrapper.Bytes, &value); err != nil {
			continue
		}
		if typeID.Equal(oidUPN) {
			out = append(out, string(value.Bytes))
			continue
		}
		out = append(out, typeID.String()+"="+hex.EncodeToString(value.Bytes))
	}
	return out
}

// shortNames covers the attributes Go's pkix.RDNSequence.String() has no
// abbreviation for and therefore renders as "oid=#hex". emailAddress is the one
// that matters in practice: Intune populates it from {{EmailAddress}}.
var shortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
	"2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "SERIALNUMBER",
	"2.5.4.17": "POSTALCODE", "1.2.840.113549.1.9.1": "E",
	"0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
}

// RenderSubject describes a subject as issued, reading it from the DER so that
// attributes absent from pkix.Name are shown rather than dropped. Falls back to
// the given name when the DER cannot be read.
func RenderSubject(raw []byte, fallback pkix.Name) string {
	if len(raw) == 0 {
		return fallback.String()
	}
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdns); err != nil {
		return fallback.String()
	}
	var parts []string
	// RDNs are marshalled most-general first; subjects read most-specific first.
	for i := len(rdns) - 1; i >= 0; i-- {
		for _, atv := range rdns[i] {
			name, ok := shortNames[atv.Type.String()]
			if !ok {
				name = atv.Type.String()
			}
			parts = append(parts, fmt.Sprintf("%s=%v", name, atv.Value))
		}
	}
	if len(parts) == 0 {
		return fallback.String()
	}
	return strings.Join(parts, ",")
}
