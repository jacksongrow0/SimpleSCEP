package scep

// Native Go implementation of Microsoft's Intune SCEP challenge validation and
// certificate revocation protocols, ported from the MIT-licensed reference
// library at github.com/microsoft/Intune-Resource-Access, commit
// 446e1769f93e87c753377c71574b998915bd0018, src/CsrValidation/csharp/ScepValidation.
//
// Microsoft documents this only as "use our C#/Java library", so the wire format
// below is taken from that source rather than from a published specification. If
// enrollment starts failing after an Intune service change, diff against the
// reference: IntuneScepValidator.cs, IntuneClient.cs, IntuneServiceLocationProvider.cs,
// and IntuneRevocationClient.cs are the four files that matter.

import (
	"bytes"
	"context"
	"crypto/sha1" // Intune's notification contract requires a SHA-1 certificate thumbprint.
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	appPKI "github.com/jacksongrow0/SimpleSCEP/internal/pki"
)

const (
	// callerInfo Intune records against every request, for support correlation.
	intuneCallerInfo = "SimpleSCEP/1"

	intuneAuthority    = "https://login.microsoftonline.com/"
	intuneResourceURL  = "https://api.manage.microsoft.com/"
	msGraphResourceURL = "https://graph.microsoft.com/"
	msGraphAPIVersion  = "1.0"

	// The well-known first-party application ID of Intune, used to look up the
	// tenant's service endpoints in Microsoft Graph.
	intuneAppID = "0000000a-0000-0000-c000-000000000000"

	scepServiceName    = "ScepRequestValidationFEService"
	scepServiceVersion = "2018-02-20"
	validateURL        = "ScepActions/validateRequest"
	successNotifyURL   = "ScepActions/successNotification"
	failureNotifyURL   = "ScepActions/failureNotification"

	pkiServiceName     = "PkiConnectorFEService"
	pkiServiceVersion  = "5019-05-05"
	downloadRevokeURL  = "CertificateAuthorityRequests/downloadRevocationRequests"
	uploadRevokeURL    = "CertificateAuthorityRequests/uploadRevocationResults"
	maxRevocationBatch = 500
)

// Revocation result codes Intune accepts. The reference serializes these as enum
// names, not their numeric values, so they must be sent as strings.
const (
	RevokeErrorNone                = "None"
	RevokeErrorCertificateNotFound = "CertificateNotFoundError"
	RevokeErrorRetryable           = "RetryableServiceException"
)

// intuneScopes are built exactly as the reference builds them. The doubled slash
// in the Intune scope is not a typo: the reference concatenates
// DEFAULT_INTUNE_RESOURCE_URL (which ends in "/") with "/.default". If token
// acquisition ever fails with AADSTS500011 (resource principal not found), the
// trailing-slash handling here is the first thing to check.
var (
	intuneScope  = intuneResourceURL + "/.default"
	msGraphScope = msGraphResourceURL + ".default"
)

// IntuneRevocationRequest is one certificate Intune wants revoked.
type IntuneRevocationRequest struct {
	RequestContext  string `json:"requestContext"`
	SerialNumber    string `json:"serialNumber"`
	IssuerName      string `json:"issuerName"`
	CAConfiguration string `json:"caConfiguration"`
}

// IntuneRevocationResult reports the outcome of one revocation request. ErrorCode
// is an enum *name* from Microsoft's CARequestErrorCode, not its numeric value —
// the reference serializes it with a StringEnumConverter.
type IntuneRevocationResult struct {
	RequestContext string `json:"requestContext"`
	Succeeded      bool   `json:"succeeded"`
	ErrorCode      string `json:"errorCode,omitempty"`
	ErrorMessage   string `json:"errorMessage,omitempty"`
}

// ServiceError is a non-success reply from an Intune service. Code is one of
// Microsoft's error enum names, e.g. ChallengeDecryptionError or ChallengeExpired.
type ServiceError struct {
	Code, Description, TransactionID, ActivityID string
}

func (e ServiceError) Error() string {
	msg := "Intune rejected the request: " + e.Code
	if e.Description != "" {
		msg += " (" + e.Description + ")"
	}
	return msg
}

type cachedToken struct {
	value   string
	expires time.Time
}

// IntuneClient talks to Intune directly. It is safe for concurrent use and
// caches access tokens and service endpoints across organizations, keyed by
// tenant so one tenant can never read another's cache entry.
type IntuneClient struct {
	HTTP *http.Client

	mu       sync.Mutex
	tokens   map[string]cachedToken
	services map[string]map[string]string
}

func NewIntuneClient(client *http.Client) *IntuneClient {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &IntuneClient{HTTP: client, tokens: map[string]cachedToken{}, services: map[string]map[string]string{}}
}

// token fetches an OAuth2 client-credentials access token, reusing a cached one
// until shortly before it expires.
func (c *IntuneClient) token(ctx context.Context, i Integration, scope string) (string, error) {
	key := i.TenantID + "|" + i.ApplicationID + "|" + scope
	c.mu.Lock()
	if cached, ok := c.tokens[key]; ok && time.Now().Before(cached.expires) {
		c.mu.Unlock()
		return cached.value, nil
	}
	c.mu.Unlock()

	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {i.ApplicationID},
		"client_secret": {i.Secret}, "scope": {scope}}
	endpoint := intuneAuthority + url.PathEscape(i.TenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("Entra ID token request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		// The body carries AADSTS codes that name the actual misconfiguration,
		// and contains no secret material, so it is worth surfacing.
		return "", fmt.Errorf("Entra ID rejected the credentials (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return "", fmt.Errorf("Entra ID returned no access token")
	}
	ttl := time.Duration(parsed.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	c.mu.Lock()
	// Expire early so a token cannot lapse mid-request.
	c.tokens[key] = cachedToken{value: parsed.AccessToken, expires: time.Now().Add(ttl - 5*time.Minute)}
	c.mu.Unlock()
	return parsed.AccessToken, nil
}

// serviceEndpoint resolves an Intune service to its tenant-specific URL through
// Microsoft Graph, caching the whole service map per tenant.
func (c *IntuneClient) serviceEndpoint(ctx context.Context, i Integration, service string) (string, error) {
	name := strings.ToLower(service)
	c.mu.Lock()
	if cached, ok := c.services[i.TenantID]; ok {
		if endpoint, ok := cached[name]; ok {
			c.mu.Unlock()
			return endpoint, nil
		}
	}
	c.mu.Unlock()

	token, err := c.token(ctx, i, msGraphScope)
	if err != nil {
		return "", err
	}
	discovery := fmt.Sprintf("%sv%s/servicePrincipals/appId=%s/endpoints", msGraphResourceURL, msGraphAPIVersion, intuneAppID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("client-request-id", uuid.NewString())
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("Intune service discovery failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("Intune service discovery failed (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		Value []struct {
			ProviderName string `json:"providerName"`
			ServiceName  string `json:"serviceName"`
			URI          string `json:"uri"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("Intune service discovery returned unreadable JSON: %w", err)
	}
	discovered := map[string]string{}
	for _, entry := range parsed.Value {
		key := entry.ProviderName
		if key == "" {
			key = entry.ServiceName
		}
		if key != "" {
			discovered[strings.ToLower(key)] = entry.URI
		}
	}
	c.mu.Lock()
	c.services[i.TenantID] = discovered
	c.mu.Unlock()

	endpoint, ok := discovered[name]
	if !ok {
		return "", fmt.Errorf("Intune did not publish a %s endpoint for this tenant; check that the app registration has the Intune SCEP challenge validation permission with admin consent", service)
	}
	return endpoint, nil
}

// forgetServices drops a tenant's cached service map so a moved endpoint is
// rediscovered on the next call, mirroring the reference's Clear() on failure.
func (c *IntuneClient) forgetServices(tenantID string) {
	c.mu.Lock()
	delete(c.services, tenantID)
	c.mu.Unlock()
}

// forgetTenant additionally drops the tenant's access tokens. A token minted
// before a role assignment propagated carries no roles claim and keeps failing
// for its whole lifetime, so anything retrying after a permission change has to
// discard it rather than wait the token out.
func (c *IntuneClient) forgetTenant(tenantID string) {
	c.mu.Lock()
	delete(c.services, tenantID)
	for key := range c.tokens {
		if strings.HasPrefix(key, tenantID+"|") {
			delete(c.tokens, key)
		}
	}
	c.mu.Unlock()
}

// CheckTenant reports whether a tenant has granted this application working
// admin consent. Resolving the SCEP service endpoint exercises both application
// permissions in one go: the token proves the service principal exists, and the
// Graph lookup proves Application.Read.All, while a published
// ScepRequestValidationFEService proves the Intune role.
func (c *IntuneClient) CheckTenant(ctx context.Context, i Integration) error {
	c.forgetTenant(i.TenantID)
	_, err := c.serviceEndpoint(ctx, i, scepServiceName)
	return err
}

func (c *IntuneClient) post(ctx context.Context, i Integration, service, apiVersion, suffix string, payload any) ([]byte, string, error) {
	endpoint, err := c.serviceEndpoint(ctx, i, service)
	if err != nil {
		return nil, "", err
	}
	token, err := c.token(ctx, i, intuneScope)
	if err != nil {
		return nil, "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	activityID := uuid.NewString()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(endpoint, "/")+"/"+suffix, bytes.NewReader(body))
	if err != nil {
		return nil, activityID, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("client-request-id", activityID)
	req.Header.Set("api-version", apiVersion)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.forgetServices(i.TenantID)
		return nil, activityID, fmt.Errorf("Intune request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, activityID, err
	}
	if resp.StatusCode/100 != 2 {
		c.forgetServices(i.TenantID)
		return nil, activityID, fmt.Errorf("Intune returned %s for %s", resp.Status, suffix)
	}
	return raw, activityID, nil
}

// scepPost performs a SCEP-service call and converts Intune's per-request result
// code into an error. Anything other than Success means no certificate may be
// issued.
func (c *IntuneClient) scepPost(ctx context.Context, i Integration, suffix, transactionID string, payload any) error {
	raw, activityID, err := c.post(ctx, i, scepServiceName, scepServiceVersion, suffix, payload)
	if err != nil {
		return err
	}
	var result struct {
		Code             string `json:"code"`
		ErrorDescription string `json:"errorDescription"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("Intune returned unreadable JSON: %w", err)
	}
	if !strings.EqualFold(result.Code, "Success") {
		return ServiceError{Code: result.Code, Description: result.ErrorDescription,
			TransactionID: transactionID, ActivityID: activityID}
	}
	return nil
}

// Validate asks Intune whether the challenge password inside this CSR is one it
// issued for this device. A non-nil error means the certificate must not be issued.
func (c *IntuneClient) Validate(ctx context.Context, i Integration, transactionID string, csr []byte) error {
	return c.scepPost(ctx, i, validateURL, transactionID, map[string]any{"request": map[string]any{
		"transactionId":      transactionID,
		"certificateRequest": base64.StdEncoding.EncodeToString(csr),
		"callerInfo":         intuneCallerInfo,
	}})
}

// NotifySuccess tells Intune the certificate was issued, so the device shows as
// compliant in the Intune console.
func (c *IntuneClient) NotifySuccess(ctx context.Context, i Integration, transactionID string, csr []byte, cert appPKI.Certificate) error {
	leaf, err := parseCertificate(cert.CertificatePEM)
	if err != nil {
		return err
	}
	thumbprint := sha1.Sum(leaf.Raw)
	return c.scepPost(ctx, i, successNotifyURL, transactionID, map[string]any{"notification": map[string]any{
		"transactionId":                transactionID,
		"certificateRequest":           base64.StdEncoding.EncodeToString(csr),
		"certificateThumbprint":        strings.ToUpper(hex.EncodeToString(thumbprint[:])),
		"certificateSerialNumber":      cert.Serial,
		"certificateExpirationDateUtc": cert.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"issuingCertificateAuthority":  leaf.Issuer.String(),
		"callerInfo":                   intuneCallerInfo,
		"caConfiguration":              cert.CAID,
		"certificateAuthority":         cert.CAName,
	}})
}

// NotifyFailure reports a rejected enrollment so the reason is visible to the
// Intune administrator instead of the device silently retrying.
func (c *IntuneClient) NotifyFailure(ctx context.Context, i Integration, transactionID string, csr []byte, description string) error {
	if description == "" {
		description = "certificate issuance failed"
	}
	if len(description) > 255 {
		description = description[:255]
	}
	return c.scepPost(ctx, i, failureNotifyURL, transactionID, map[string]any{"notification": map[string]any{
		"transactionId":      transactionID,
		"certificateRequest": base64.StdEncoding.EncodeToString(csr),
		// A generic non-retryable HRESULT; Intune surfaces errorDescription.
		"hResult":          int64(-2147024894),
		"errorDescription": description,
		"callerInfo":       intuneCallerInfo,
	}})
}

// DownloadRevocations pulls certificates Intune wants revoked, optionally
// filtered to one issuer.
func (c *IntuneClient) DownloadRevocations(ctx context.Context, i Integration, transactionID, issuer string, max int) ([]IntuneRevocationRequest, error) {
	if max <= 0 || max > maxRevocationBatch {
		max = 100
	}
	params := map[string]any{"maxRequests": max}
	if issuer != "" {
		params["issuerName"] = issuer
	}
	raw, _, err := c.post(ctx, i, pkiServiceName, pkiServiceVersion, downloadRevokeURL,
		map[string]any{"downloadParameters": params})
	if err != nil {
		return nil, err
	}
	var result struct {
		Value []IntuneRevocationRequest `json:"value"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("Intune returned unreadable revocation JSON: %w", err)
	}
	return result.Value, nil
}

// UploadRevocations reports what happened to each revocation request.
func (c *IntuneClient) UploadRevocations(ctx context.Context, i Integration, transactionID string, results []IntuneRevocationResult) error {
	if len(results) == 0 {
		return nil
	}
	raw, _, err := c.post(ctx, i, pkiServiceName, pkiServiceVersion, uploadRevokeURL,
		map[string]any{"results": results})
	if err != nil {
		return err
	}
	// The reference accepts the value as either a JSON bool or a quoted string.
	var result struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("Intune returned unreadable JSON: %w", err)
	}
	if strings.Trim(strings.ToLower(string(result.Value)), `"`) != "true" {
		return fmt.Errorf("Intune did not record the revocation results")
	}
	return nil
}
