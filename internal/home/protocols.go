package home

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/acme"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/est"
	"github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/jacksongrow0/SimpleSCEP/internal/scep"
	"github.com/jacksongrow0/SimpleSCEP/internal/web"
	homeview "github.com/jacksongrow0/SimpleSCEP/view/home"
)

// Protocol endpoint pages: the SCEP, ACME and EST administration screens
// and the read models they render from.

func (h Handler) protocols(w http.ResponseWriter, r *http.Request) {
	s := session(r)
	data, err := h.protocolPage(r, s)
	if err != nil {
		// The page assembles from four queries; without the cause a 500 here is
		// undiagnosable from the browser alone.
		log.Printf("home org=%s protocols failed: %v", s.OrgID, err)
		web.Page(w, r, http.StatusInternalServerError, "The protocols page could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	if err := homeview.Protocols(s, data).Render(r.Context(), w); err != nil {
		web.Page(w, r, http.StatusInternalServerError, "That page could not be rendered",
			"Something went wrong on our side. Try again in a moment.")
	}
}

// acmeEndpoint administers one ACME endpoint.
func (h Handler) acmeEndpoint(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("endpointID")
	if _, err := uuid.Parse(id); err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := h.acmeEndpointPage(r, s, id)
	// The lookup is scoped to the session's organization, so another customer's
	// endpoint is not found rather than served.
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("home org=%s acme endpoint=%s failed: %v", s.OrgID, id, err)
		web.Page(w, r, http.StatusInternalServerError, "That endpoint could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	if err := homeview.ACMEEndpointView(s, data).Render(r.Context(), w); err != nil {
		web.Page(w, r, http.StatusInternalServerError, "That page could not be rendered",
			"Something went wrong on our side. Try again in a moment.")
	}
}

// estEndpoint administers one EST endpoint.
func (h Handler) estEndpoint(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("endpointID")
	if _, err := uuid.Parse(id); err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := h.estEndpointPage(r, s, id)
	// The lookup is scoped to the session's organization, so another customer's
	// endpoint is not found rather than served.
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("home org=%s est endpoint=%s failed: %v", s.OrgID, id, err)
		web.Page(w, r, http.StatusInternalServerError, "That endpoint could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	if err := homeview.ESTEndpointView(s, data).Render(r.Context(), w); err != nil {
		web.Page(w, r, http.StatusInternalServerError, "That page could not be rendered",
			"Something went wrong on our side. Try again in a moment.")
	}
}

func (h Handler) protocolEndpoint(w http.ResponseWriter, r *http.Request) {
	s, ok := web.Admin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("endpointID")
	if _, err := uuid.Parse(id); err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := h.protocolEndpointPage(r, s, id)
	// The lookup is scoped to the session's organization, so another customer's
	// endpoint is not found rather than served.
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("home org=%s scep endpoint=%s failed: %v", s.OrgID, id, err)
		web.Page(w, r, http.StatusInternalServerError, "That endpoint could not be loaded",
			"Something went wrong on our side. Try again in a moment.")
		return
	}
	if err := homeview.ProtocolEndpointView(s, data).Render(r.Context(), w); err != nil {
		web.Page(w, r, http.StatusInternalServerError, "That page could not be rendered",
			"Something went wrong on our side. Try again in a moment.")
	}
}

// protocolPage assembles the SCEP tab: the organization's Entra connection and
// the list of its endpoints. Only administrators can act on any of it, so
// nothing is loaded for anyone else.
func (h Handler) protocolPage(r *http.Request, s auth.Session) (homeview.ProtocolPage, error) {
	var data homeview.ProtocolPage
	if !s.IsAdmin() {
		return data, nil
	}
	// The Entra consent callbacks come back as full-page navigations, so a
	// failed connection reports itself through the query string rather than an
	// htmx swap.
	data.IntuneError = r.URL.Query().Get("intune_error")
	caNames, _, _, err := h.protocolCAs(r, s, &data)
	if err != nil {
		return data, err
	}
	conn, err := h.intuneConnection(r, s)
	if err != nil {
		return data, err
	}
	data.Intune = conn
	summaries, err := h.scepRepo.EndpointSummaries(r.Context(), s.OrgID)
	if err != nil {
		return data, err
	}
	for _, e := range summaries {
		data.Endpoints = append(data.Endpoints, homeview.ProtocolEndpointRow{ID: e.ID, Name: e.Name,
			CAName: caNames[e.CAID], Enabled: e.Enabled, EnabledMethods: e.EnabledMethods,
			RecentIssued: e.RecentIssued, Path: "/protocols/scep/" + e.ID})
	}
	// The ACME tab renders from the same page load, because the tabs are
	// client-side only, so all protocol data is loaded before rendering.
	acmeData, err := h.acmePage(r, s, data.CAs)
	if err != nil {
		return data, err
	}
	data.ACME = acmeData
	estData, err := h.estPage(r, s, data.CAs)
	if err != nil {
		return data, err
	}
	data.EST = estData
	return data, nil
}

// estPage assembles the EST tab. Like acmePage, the selectable CA list is shared
// with the SCEP tab rather than queried again: every protocol binds the same
// issuing CAs.
func (h Handler) estPage(r *http.Request, s auth.Session, cas []homeview.ProtocolCA) (homeview.ESTPage, error) {
	var data homeview.ESTPage
	data.CAs = cas
	caNames, _, _, err := h.protocolCAs(r, s, nil)
	if err != nil {
		return data, err
	}
	summaries, err := h.estRepo.EndpointSummaries(r.Context(), s.OrgID)
	if err != nil {
		return data, err
	}
	for _, e := range summaries {
		data.Endpoints = append(data.Endpoints, homeview.ESTEndpointRow{ID: e.ID, Name: e.Name,
			CAName: caNames[e.CAID], Enabled: e.Enabled, Credentials: e.Credentials,
			RecentIssued: e.RecentIssued, Path: "/protocols/est/" + e.ID})
	}
	return data, nil
}

// estEndpointPage assembles one EST endpoint's administration page: its base
// URL, credentials, issuance policy, and recent enrollments.
func (h Handler) estEndpointPage(r *http.Request, s auth.Session, endpointID string) (homeview.ESTEndpointData, error) {
	var data homeview.ESTEndpointData
	e, err := h.estRepo.EndpointByID(r.Context(), s.OrgID, endpointID)
	if err != nil {
		return data, err
	}
	caNames, caFingerprints, caEKUs, err := h.protocolCAs(r, s, nil)
	if err != nil {
		return data, err
	}
	// How many devices still depend on this endpoint, for the delete dialog.
	live, err := h.estRepo.LiveCertificateCount(r.Context(), e.ID)
	if err != nil {
		return data, err
	}
	data.Endpoint = homeview.ESTEndpoint{ID: e.ID, Name: e.Name, CAName: caNames[e.CAID],
		LiveCertificates: live,
		BaseURL:          h.publicURL + "/.well-known/est/" + e.ID,
		APIBase:          "/api/est/endpoints/" + e.ID,
		CAFingerprint:    caFingerprints[e.CAID],
		Enabled:          e.Enabled, ValidityDays: e.ValidityDays,
		RenewalWindowDays: e.RenewalWindowDays,
		SubjectPattern:    e.SubjectPattern, SANPattern: e.SANPattern,
		ReenrollRequiresSameKey: e.ReenrollRequiresSameKey,
		EKUs:                    estEndpointEKUs(e, caEKUs[e.CAID])}

	credentials, err := h.estRepo.Credentials(r.Context(), e.ID)
	if err != nil {
		return data, err
	}
	for _, cr := range credentials {
		data.Credentials = append(data.Credentials, homeview.ESTCredential{ID: cr.ID, Label: cr.Label,
			Username: cr.Username, IdentifierPin: cr.IdentifierPin, Revoked: cr.RevokedAt != nil,
			ExpiresAt: cr.ExpiresAt, LastUsedAt: cr.UsedAt, CreatedAt: cr.CreatedAt})
	}

	enrollments, err := h.estRepo.Enrollments(r.Context(), e.ID, 10)
	if err != nil {
		return data, err
	}
	for _, n := range enrollments {
		data.Enrollments = append(data.Enrollments, homeview.ESTEnrollment{Subject: n.Subject,
			Operation: n.Operation, Credential: n.Credential, Result: n.Result,
			FailureReason: n.FailureReason, Serial: n.Serial, CertificateStatus: n.CertificateStatus,
			ExpiresAt: n.ExpiresAt, CreatedAt: n.CreatedAt})
	}
	return data, nil
}

// estEndpointEKUs is endpointEKUs for the third protocol. The choice list is
// shared with SCEP's for the same reason acmeEndpointEKUs shares it: the
// exclusions are the same wherever they are asked for.
func estEndpointEKUs(e est.Endpoint, caProfile string) []homeview.ProtocolEKU {
	allowed := strings.Split(e.AllowedEKUs, ",")
	profile := strings.Split(caProfile, ",")
	out := make([]homeview.ProtocolEKU, 0, len(scep.EKUChoices))
	for _, token := range scep.EKUChoices {
		out = append(out, homeview.ProtocolEKU{Token: token, Label: scep.EKULabel(token),
			Allowed: slices.Contains(allowed, token), Available: slices.Contains(profile, token)})
	}
	return out
}

// acmePage assembles the ACME tab. The selectable CA list is shared with the
// SCEP tab rather than queried again: both protocols bind the same issuing CAs.
func (h Handler) acmePage(r *http.Request, s auth.Session, cas []homeview.ProtocolCA) (homeview.ACMEPage, error) {
	var data homeview.ACMEPage
	data.CAs = cas
	caNames, _, _, err := h.protocolCAs(r, s, nil)
	if err != nil {
		return data, err
	}
	summaries, err := h.acmeRepo.EndpointSummaries(r.Context(), s.OrgID)
	if err != nil {
		return data, err
	}
	for _, e := range summaries {
		data.Endpoints = append(data.Endpoints, homeview.ACMEEndpointRow{ID: e.ID, Name: e.Name,
			CAName: caNames[e.CAID], Enabled: e.Enabled, Credentials: e.Credentials,
			RecentIssued: e.RecentIssued, Path: "/protocols/acme/" + e.ID})
	}
	return data, nil
}

// acmeEndpointPage assembles one ACME endpoint's administration page: its
// directory URL, credentials, issuance policy, and recent orders.
func (h Handler) acmeEndpointPage(r *http.Request, s auth.Session, endpointID string) (homeview.ACMEEndpointData, error) {
	var data homeview.ACMEEndpointData
	e, err := h.acmeRepo.EndpointByID(r.Context(), s.OrgID, endpointID)
	if err != nil {
		return data, err
	}
	caNames, caFingerprints, caEKUs, err := h.protocolCAs(r, s, nil)
	if err != nil {
		return data, err
	}
	// How many services still depend on this endpoint, for the delete dialog.
	live, err := h.acmeRepo.LiveCertificateCount(r.Context(), e.ID)
	if err != nil {
		return data, err
	}
	data.Endpoint = homeview.ACMEEndpoint{ID: e.ID, Name: e.Name, CAName: caNames[e.CAID],
		LiveCertificates: live,
		DirectoryURL:     h.publicURL + "/acme/" + e.ID + "/directory",
		APIBase:          "/api/acme/endpoints/" + e.ID,
		CAFingerprint:    caFingerprints[e.CAID],
		Enabled:          e.Enabled, ValidityDays: e.ValidityDays,
		SubjectPattern: e.SubjectPattern, SANPattern: e.SANPattern,
		EKUs: acmeEndpointEKUs(e, caEKUs[e.CAID])}

	credentials, err := h.acmeRepo.Credentials(r.Context(), e.ID)
	if err != nil {
		return data, err
	}
	for _, cr := range credentials {
		data.Credentials = append(data.Credentials, homeview.ACMECredential{ID: cr.ID, Label: cr.Label,
			KID: cr.KID, IdentifierPin: cr.IdentifierPin, SingleUse: cr.SingleUse,
			Used: cr.UsedAt != nil, Revoked: cr.RevokedAt != nil, ExpiresAt: cr.ExpiresAt,
			CreatedAt: cr.CreatedAt})
	}

	orders, err := h.acmeRepo.Orders(r.Context(), e.ID, 10)
	if err != nil {
		return data, err
	}
	for _, o := range orders {
		identifiers, err := h.acmeRepo.Authorizations(r.Context(), o.ID)
		if err != nil {
			return data, err
		}
		names := make([]string, 0, len(identifiers))
		for _, a := range identifiers {
			names = append(names, a.IdentifierValue)
		}
		data.Orders = append(data.Orders, homeview.ACMEOrder{ID: o.ID, Status: o.Status,
			Identifiers: strings.Join(names, ", "), Error: o.ErrorDetail, CreatedAt: o.CreatedAt})
	}
	return data, nil
}

// acmeEndpointEKUs is endpointEKUs for the other protocol. The choice list is
// shared with SCEP's because the exclusions are the same — ocsp_signing and
// anyExtendedKeyUsage are refused wherever they are asked for.
func acmeEndpointEKUs(e acme.Endpoint, caProfile string) []homeview.ProtocolEKU {
	allowed := strings.Split(e.AllowedEKUs, ",")
	profile := strings.Split(caProfile, ",")
	out := make([]homeview.ProtocolEKU, 0, len(scep.EKUChoices))
	for _, token := range scep.EKUChoices {
		out = append(out, homeview.ProtocolEKU{Token: token, Label: scep.EKULabel(token),
			Allowed: slices.Contains(allowed, token), Available: slices.Contains(profile, token)})
	}
	return out
}

// protocolCAs loads the organization's certificate authorities, filling the
// setup dialog's selectable list and returning the lookups both pages need.
func (h Handler) protocolCAs(r *http.Request, s auth.Session, data *homeview.ProtocolPage) (names, fingerprints, ekus map[string]string, err error) {
	cas, err := h.pkiRepo.CAs(r.Context(), s.OrgID)
	if err != nil {
		return nil, nil, nil, err
	}
	names, fingerprints, ekus = map[string]string{}, map[string]string{}, map[string]string{}
	for _, ca := range cas {
		// Issuance profiles and names are collected for every CA, not just the
		// selectable ones, so an endpoint bound to a CA that has since been
		// retired still renders rather than showing everything as unavailable.
		ekus[ca.ID] = ca.IssuanceEKUs
		names[ca.ID] = ca.Name
		fingerprints[ca.ID] = certificateFingerprint(ca.CertificatePEM)
		if data != nil && ca.Type == pki.CATypeIssuing && ca.Status == pki.CAStatusActive {
			data.CAs = append(data.CAs, homeview.ProtocolCA{ID: ca.ID, Name: ca.Name})
		}
	}
	return names, fingerprints, ekus, nil
}

// intuneConnection describes the organization's single Entra directory. Not
// being connected is ordinary, not an error.
func (h Handler) intuneConnection(r *http.Request, s auth.Session) (homeview.ProtocolIntune, error) {
	conn, err := h.scepRepo.IntuneConnection(r.Context(), s.OrgID)
	if errors.Is(err, sql.ErrNoRows) {
		return homeview.ProtocolIntune{}, nil
	}
	if err != nil {
		return homeview.ProtocolIntune{}, err
	}
	return homeview.ProtocolIntune{Connected: true, TenantID: conn.TenantID, ConnectedAt: conn.ConnectedAt}, nil
}

// protocolEndpointPage assembles one endpoint's administration page: its
// summary, authentication methods, issuance policy, and recent enrollments.
func (h Handler) protocolEndpointPage(r *http.Request, s auth.Session, endpointID string) (homeview.ProtocolEndpointData, error) {
	var data homeview.ProtocolEndpointData
	e, err := h.scepRepo.EndpointByID(r.Context(), s.OrgID, endpointID)
	if err != nil {
		return data, err
	}
	caNames, caFingerprints, caEKUs, err := h.protocolCAs(r, s, nil)
	if err != nil {
		return data, err
	}
	// How many devices still depend on this endpoint, for the delete dialog.
	live, err := h.scepRepo.LiveCertificateCount(r.Context(), e.ID)
	if err != nil {
		return data, err
	}
	data.Endpoint = homeview.ProtocolEndpoint{ID: e.ID, Name: e.Name, CAName: caNames[e.CAID],
		LiveCertificates: live,
		URL:              h.publicURL + "/scep/" + e.ID,
		JamfWebhookURL:   h.publicURL + "/integrations/jamf/scep-challenge/" + e.ID,
		APIBase:          "/api/scep/endpoints/" + e.ID,
		RAFingerprint:    certificateFingerprint(e.RACertificatePEM), CAFingerprint: caFingerprints[e.CAID],
		Enabled: e.Enabled, ValidityDays: e.ValidityDays, RenewalWindowDays: e.RenewalWindowDays,
		SubjectPattern: e.SubjectPattern, SANPattern: e.SANPattern, Legacy: e.AllowLegacyCrypto,
		EKUs: endpointEKUs(e, caEKUs[e.CAID])}

	methods, err := h.scepRepo.AuthMethods(r.Context(), e.ID)
	if err != nil {
		return data, err
	}
	stored := map[string]scep.AuthMethod{}
	for _, m := range methods {
		stored[m.Method] = m
	}
	conn, err := h.intuneConnection(r, s)
	if err != nil {
		return data, err
	}
	oneTimeOn := stored[scep.AuthOneTime].Enabled
	for _, name := range scep.Methods {
		data.Methods = append(data.Methods, h.protocolMethod(stored[name], name, oneTimeOn, conn.TenantID))
	}

	transactions, err := h.scepRepo.RecentTransactions(r.Context(), e.ID, 10)
	if err != nil {
		return data, err
	}
	for _, t := range transactions {
		data.Transactions = append(data.Transactions, homeview.ProtocolTransaction{ID: t.TransactionID,
			Status: t.Status, Type: t.MessageType, Authorization: t.AuthorizationSource, Reason: t.FailureReason,
			CreatedAt: t.CreatedAt})
	}
	return data, nil
}

// protocolMethod describes one authentication method, including why it cannot
// be turned on yet, so the page explains the block instead of failing on submit.
func (h Handler) protocolMethod(m scep.AuthMethod, name string, oneTimeOn bool, tenantID string) homeview.ProtocolAuthMethod {
	view := homeview.ProtocolAuthMethod{Method: name, Enabled: m.Enabled, Configured: m.Configured(),
		TenantID: tenantID, Username: m.Username}
	switch name {
	case scep.AuthOneTime:
		view.Label = "One-time challenges"
		view.Description = "A password you generate that authorizes a single enrollment. Also how Jamf Pro enrolls."
		// Nothing is stored against the endpoint for this method — a challenge
		// goes into the challenge table when it is minted — which is why
		// scep.AuthMethod.Configured reports it configured from the start. The
		// badge needs to know that is the reason, or it announces a setup step
		// nobody took.
		view.NoSetup = true
	case scep.AuthStatic:
		view.Label = "Shared secret"
		view.Description = "One password every device uses. For MDMs that cannot request a challenge per device."
		if m.ConfiguredAt != nil {
			view.Detail = "Rotated " + m.ConfiguredAt.UTC().Format("2 Jan 2006")
		}
		if !view.Configured {
			view.Blocked = "Generate a shared secret before turning this on."
		}
	case scep.AuthIntune:
		view.Label = "Microsoft Intune"
		view.Description = "SimpleSCEP verifies each request with Microsoft before issuing."
		// The directory is connected once for the whole organization, so the
		// tenant is passed in rather than read off this endpoint's row.
		if view.Configured {
			view.Detail = "Tenant " + tenantID
			if m.ConfiguredAt != nil {
				view.Detail += " · connected " + m.ConfiguredAt.UTC().Format("2 Jan 2006")
			}
		}
		if !view.Configured {
			view.Blocked = "Connect your organization's Microsoft Entra tenant before turning this on."
		}
	case scep.AuthJamf:
		view.Label = "Jamf Pro"
		view.Description = "Jamf Pro requests a fresh challenge over a webhook each time it enrolls a device."
		if view.Configured {
			view.Detail = "Webhook user " + m.Username
		}
		switch {
		case !view.Configured:
			view.Blocked = "Configure this to generate a webhook password before turning this on."
		case !oneTimeOn:
			view.Blocked = "Turn on one-time challenges first; Jamf Pro enrolls with them."
		}
	}
	return view
}

// endpointEKUs renders the issuance policy's extended key usage checkboxes:
// every usage the SCEP endpoint may offer, marked with whether it is currently
// permitted and whether the issuing CA's profile can carry it at all.
func endpointEKUs(e scep.Endpoint, caProfile string) []homeview.ProtocolEKU {
	allowed := strings.Split(e.AllowedEKUs, ",")
	profile := strings.Split(caProfile, ",")
	out := make([]homeview.ProtocolEKU, 0, len(scep.EKUChoices))
	for _, token := range scep.EKUChoices {
		out = append(out, homeview.ProtocolEKU{Token: token, Label: scep.EKULabel(token),
			Allowed: slices.Contains(allowed, token), Available: slices.Contains(profile, token)})
	}
	return out
}

func certificateFingerprint(raw string) string {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
