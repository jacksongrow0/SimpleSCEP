package layout

// The marketing site's URLs.
//
// These are public project resources. Self-hosted operators remain responsible
// for the policies that apply to their deployment.
const (
	MarketingURL  = "https://simplescep.com"
	RepositoryURL = "https://github.com/jacksongrow0/SimpleSCEP"
	IssuesURL     = RepositoryURL + "/issues"
	SecurityURL   = RepositoryURL + "/security/policy"

	// DocsURL is the public documentation site. It is served from its own host
	// rather than by this application — see docs/ — and it is the project's
	// address, not a deployment's.
	DocsURL = "https://docs.simplescep.com"

	// Deep links into specific documentation pages, for the moments in the
	// console where a reader is doing something — importing a CA, standing up
	// a protocol endpoint, signing a CSR — rather than looking something up.
	// Named individually, rather than built from a path constant elsewhere, so
	// a page renamed in docs/internal/docs/docs.go is a compile-time grep away
	// from every place that pointed at it, not a silent 404.
	DocsImportCAURL = DocsURL + "/platform/import-ca"
	// DocsWrapKeyURL anchors into the section of the import guide that spells
	// out the openssl commands behind wrapInstructions in ca_import.templ —
	// the reference copy for scripting the wrap, not just reading it off the
	// ready-to-wrap step.
	DocsWrapKeyURL                = DocsImportCAURL + "#wrap-the-key-locally"
	DocsCertificateAuthoritiesURL = DocsURL + "/platform/certificate-authorities"
	DocsCertificatesURL           = DocsURL + "/platform/certificates"
	DocsRevocationURL             = DocsURL + "/platform/revocation"
	DocsSCEPURL                   = DocsURL + "/protocols/scep"
	DocsACMEURL                   = DocsURL + "/protocols/acme"
	DocsESTURL                    = DocsURL + "/protocols/est"
)
