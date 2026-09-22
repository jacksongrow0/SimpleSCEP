package pki

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrPolicyInvalid reports that the endpoint's own configuration will not
// compile. It is separate from ErrPolicyRefused because the two are nobody's
// fault in common: a refusal is something the client asked for, an invalid
// policy is a row in our database, and an enrollment client told "your request
// is not permitted" for our broken regex will be debugged in the wrong place.
var ErrPolicyInvalid = errors.New("invalid issuance policy")

// ErrPolicyRefused reports that the request does not satisfy the policy.
var ErrPolicyRefused = errors.New("not permitted by the issuance policy")

// NamePolicy is an enrollment endpoint's subject and subjectAltName rules.
//
// Both are regular expressions an administrator writes. An empty *subject*
// pattern is unconstrained; an empty *SAN* pattern permits no subject
// alternative names at all, and the asymmetry is deliberate — see Check.
//
// What matters is what they are applied to, which is the whole reason this type
// exists rather than the two lines it replaces.
//
// Every caller had written the same map literal:
//
//	for pattern, value := range map[string]string{e.SubjectPattern: subject, e.SANPattern: sans}
//
// which carried two defects. The map is keyed by the *pattern*, so an
// administrator who set both fields to the same expression — a natural thing to
// do — collapsed it to one entry, and Go's last-key-wins left only the SAN rule
// running while the page showed both saved. And the SAN value was every name
// joined with a comma, tested with MatchString, which is a substring match over
// the concatenation: a policy of `\.corp\.example\.com$` accepted a request for
// `evil.attacker.com, device7.corp.example.com`, and pki copies the requested SAN
// DER into the certificate verbatim. Anchoring the pattern did not help, because
// an anchored pattern then rejects every multi-SAN request and gets un-anchored
// again.
//
// So the SAN rule is applied to each name on its own and every name must match,
// which is what ACME's per-identifier check already did.
type NamePolicy struct {
	Subject string
	SAN     string
}

// Check applies the policy to one request's names.
//
// subject is the rendering the certificate will actually carry — RenderSubject
// over the CSR's raw DER, not pkix.Name.String(), which silently omits every RDN
// Go does not model. An emailAddress RDN is invisible to the latter and is issued
// by the former, which is exactly the gap a subject policy is written to close.
//
// sans is every subjectAltName the request asks for, including the otherName
// forms x509 does not parse. A name left out of this slice is a name nothing
// checks.
func (p NamePolicy) Check(subject string, sans []string) error {
	if p.Subject != "" {
		re, err := regexp.Compile(p.Subject)
		if err != nil {
			return fmt.Errorf("subject pattern does not compile: %w", ErrPolicyInvalid)
		}
		if !re.MatchString(subject) {
			return fmt.Errorf("subject %q: %w", subject, ErrPolicyRefused)
		}
	}
	// An endpoint with no SAN rule permits no subject alternative names. This is
	// the default a new endpoint starts with, and it is closed on purpose: a SAN
	// is the field a certificate is actually validated against, so an endpoint
	// that has not been told which names it may carry must not be the one
	// deciding. The subject rule keeps the opposite default because a subject is
	// descriptive — nothing trusts it to name a host.
	//
	// A request asking for no SAN at all is still issued. The rule governs which
	// names may be carried, and a certificate carrying none carries nothing to
	// constrain.
	if p.SAN == "" {
		if len(sans) > 0 {
			return fmt.Errorf("subject alternative name %q: this endpoint has no SAN policy, so it "+
				"permits none: %w", sans[0], ErrPolicyRefused)
		}
		return nil
	}
	re, err := regexp.Compile(p.SAN)
	if err != nil {
		return fmt.Errorf("SAN pattern does not compile: %w", ErrPolicyInvalid)
	}
	// A request carrying no subjectAltName at all is still tested, against the
	// empty string. Per-name matching would otherwise pass it vacuously — there
	// is no name to fail — and that would be a quiet loosening: the joined-string
	// check this replaces tested "" and refused it for any pattern that does not
	// accept the empty rendering, which is nearly all of them. An operator who
	// wrote a SAN policy meant SANs.
	if len(sans) == 0 {
		sans = []string{""}
	}
	for _, name := range sans {
		if !re.MatchString(name) {
			return fmt.Errorf("subject alternative name %q: %w", name, ErrPolicyRefused)
		}
	}
	return nil
}
