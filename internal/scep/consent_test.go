package scep

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
)

const testAuthSecret = "consent-test-secret"

func testConsentHandler(publicURL string, client *http.Client) Handler {
	return Handler{publicURL: publicURL, authSecret: testAuthSecret, http: client,
		intuneApp: testIntuneApp}
}

// adminRequest carries the session an administrator's browser would present.
func adminRequest(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	return r.WithContext(auth.WithSession(r.Context(),
		auth.Session{OrgID: "org-1", Role: "administrator"}))
}

func issueConsentCookie(t *testing.T, h Handler, state consentState) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	h.setConsentCookie(rec, state)
	cookies := (&http.Response{Header: rec.Header()}).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}
	return cookies[0]
}

// shortenConsentRetries keeps the propagation backoff out of the test runtime
// while leaving the attempt count, which is what the tests actually assert on.
func shortenConsentRetries(t *testing.T) {
	t.Helper()
	original := consentVerifyDelay
	consentVerifyDelay = time.Millisecond
	t.Cleanup(func() { consentVerifyDelay = original })
}

// idToken builds the shape redeemSignIn reads: three dot-separated segments with
// the claims in the middle one.
func idToken(claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestConsentCookieBindsOrganizationAndStage(t *testing.T) {
	h := testConsentHandler("https://scep.example", nil)
	cookie := issueConsentCookie(t, h, consentState{Stage: stageConsent, Nonce: "n", TenantID: "tid", OrgID: "org-1"})

	for name, tc := range map[string]struct {
		orgID, stage string
		want         bool
	}{
		"matching org and stage": {"org-1", stageConsent, true},
		"another organization":   {"org-2", stageConsent, false},
		"replayed at wrong leg":  {"org-1", stageSignIn, false},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.AddCookie(cookie)
			state, ok := h.readConsentCookie(r, tc.orgID, tc.stage)
			if ok != tc.want {
				t.Fatalf("readConsentCookie ok = %t, want %t", ok, tc.want)
			}
			if ok && state.TenantID != "tid" {
				t.Fatalf("tenant = %q", state.TenantID)
			}
		})
	}
}

// A sibling subdomain can drop a cookie on the parent domain, so the tenant it
// names has to be signed rather than merely present.
func TestConsentCookieRejectsTampering(t *testing.T) {
	h := testConsentHandler("https://scep.example", nil)
	forged, _ := json.Marshal(consentState{Stage: stageConsent, Nonce: "n", TenantID: "victim-tenant", OrgID: "org-1"})
	value := base64.RawURLEncoding.EncodeToString(forged)

	for name, cookieValue := range map[string]string{
		"unsigned":                     value,
		"signed with another secret":   value + "." + auth.Sign(value, "some-other-secret"),
		"signature of another payload": value + "." + auth.Sign("different-value", testAuthSecret),
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.AddCookie(&http.Cookie{Name: consentCookie, Value: url.QueryEscape(cookieValue)})
			if _, ok := h.readConsentCookie(r, "org-1", stageConsent); ok {
				t.Fatal("a cookie this application did not sign was accepted")
			}
		})
	}
}

func TestPKCEChallengeIsS256OfVerifier(t *testing.T) {
	// Test vector from RFC 7636 appendix B.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceChallenge(verifier); got != want {
		t.Fatalf("pkceChallenge = %q, want %q", got, want)
	}
}

func TestRedeemSignInReportsTenantAndSendsVerifier(t *testing.T) {
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ignored",
			"id_token":     idToken(map[string]any{"tid": "8f9a-directory", "oid": "admin"}),
		})
	}))
	defer server.Close()

	h := testConsentHandler("https://scep.example", &http.Client{Timeout: 5 * time.Second,
		Transport: rewriteHost(strings.TrimPrefix(server.URL, "http://"))})
	tenantID, err := h.redeemSignIn(context.Background(), "auth-code", "the-verifier")
	if err != nil {
		t.Fatal(err)
	}
	if tenantID != "8f9a-directory" {
		t.Fatalf("tenant = %q, want the tid claim", tenantID)
	}
	if got := form.Get("code_verifier"); got != "the-verifier" {
		t.Fatalf("code_verifier = %q; PKCE must bind the code to this flow", got)
	}
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Fatalf("grant_type = %q", got)
	}
	if got := form.Get("client_secret"); got != testIntuneApp.ClientSecret {
		t.Fatal("the confidential client must authenticate to the token endpoint")
	}
	if got := form.Get("redirect_uri"); got != "https://scep.example"+signInPath {
		t.Fatalf("redirect_uri = %q", got)
	}
}

// The AADSTS code names the misconfiguration, so it has to reach the administrator.
func TestRedeemSignInSurfacesEntraError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"AADSTS54005: code already redeemed."}`))
	}))
	defer server.Close()

	h := testConsentHandler("https://scep.example", &http.Client{Timeout: 5 * time.Second,
		Transport: rewriteHost(strings.TrimPrefix(server.URL, "http://"))})
	_, err := h.redeemSignIn(context.Background(), "auth-code", "verifier")
	if err == nil || !strings.Contains(err.Error(), "AADSTS54005") {
		t.Fatalf("want the AADSTS code surfaced, got %v", err)
	}
}

func TestTenantFromIDTokenRejectsMalformedTokens(t *testing.T) {
	for name, token := range map[string]string{
		"not a JWT":       "nonsense",
		"unreadable body": "header.!!!!.signature",
		"no tid claim":    idToken(map[string]any{"oid": "admin"}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tenantFromIDToken(token); err == nil {
				t.Fatal("a token without a usable tid was accepted")
			}
		})
	}
}

// consentCallbackResult drives intuneConsentCallback with a cookie and query,
// returning the redirect location. Every case here is rejected before any
// database access, so a zero-value repository is never reached.
func consentCallbackResult(t *testing.T, h Handler, state consentState, query url.Values) string {
	t.Helper()
	r := adminRequest("/integrations/intune/consent/callback?" + query.Encode())
	r.AddCookie(issueConsentCookie(t, h, state))
	rec := httptest.NewRecorder()
	h.intuneConsentCallback(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want a redirect", rec.Code)
	}
	return rec.Header().Get("Location")
}

// The whole two-leg design exists for this: a consent callback naming a
// directory other than the one the administrator signed in to must be refused,
// because Microsoft does not authenticate the tenant parameter.
func TestConsentCallbackRejectsMismatchedTenant(t *testing.T) {
	h := testConsentHandler("https://scep.example", nil)
	state := consentState{Stage: stageConsent, Nonce: "nonce-1", TenantID: "signed-in-directory", OrgID: "org-1"}
	location := consentCallbackResult(t, h, state, url.Values{
		"state":         {"nonce-1"},
		"admin_consent": {"True"},
		"tenant":        {"someone-elses-directory"},
	})
	if !strings.Contains(location, "intune_error") ||
		!strings.Contains(location, url.QueryEscape("different Microsoft Entra directory")) {
		t.Fatalf("a replayed tenant was not refused: %s", location)
	}
}

func TestConsentCallbackRejectsForeignState(t *testing.T) {
	h := testConsentHandler("https://scep.example", nil)
	state := consentState{Stage: stageConsent, Nonce: "nonce-1", TenantID: "directory", OrgID: "org-1"}
	location := consentCallbackResult(t, h, state, url.Values{
		"state":         {"nonce-from-another-browser"},
		"admin_consent": {"True"},
		"tenant":        {"directory"},
	})
	if !strings.Contains(location, url.QueryEscape(restartMessage)) {
		t.Fatalf("a callback that did not match the browser's state was accepted: %s", location)
	}
}

func TestConsentCallbackReportsDeclinedConsent(t *testing.T) {
	h := testConsentHandler("https://scep.example", nil)
	state := consentState{Stage: stageConsent, Nonce: "nonce-1", TenantID: "directory", OrgID: "org-1"}
	for name, query := range map[string]url.Values{
		"administrator declined": {"state": {"nonce-1"}, "error": {"access_denied"},
			"error_description": {"AADSTS65004: user declined."}},
		"consent not granted": {"state": {"nonce-1"}, "tenant": {"directory"}, "admin_consent": {"False"}},
	} {
		t.Run(name, func(t *testing.T) {
			location := consentCallbackResult(t, h, state, query)
			if !strings.Contains(location, url.QueryEscape(declinedMessage)) {
				t.Fatalf("declined consent was not reported: %s", location)
			}
		})
	}
}

// Entra applies a new service principal's role assignments asynchronously, so a
// verification failing seconds after consent is propagation, not misconfiguration.
func TestVerifyIntuneTenantRetriesWhileConsentPropagates(t *testing.T) {
	shortenConsentRetries(t)
	intune := &stubIntune{tenantErrs: []error{errors.New("403 Forbidden"), errors.New("403 Forbidden")}}
	s := Service{intune: intune, intuneApp: testIntuneApp}
	if err := s.VerifyIntuneTenant(context.Background(), "tenant-1"); err != nil {
		t.Fatalf("verification gave up while consent was still propagating: %v", err)
	}
	if intune.checks != 3 {
		t.Fatalf("CheckTenant called %d times, want 3", intune.checks)
	}
}

func TestVerifyIntuneTenantGivesUpOnPersistentFailure(t *testing.T) {
	shortenConsentRetries(t)
	failures := []error{errors.New("nope"), errors.New("nope"), errors.New("nope"), errors.New("nope")}
	intune := &stubIntune{tenantErrs: failures}
	s := Service{intune: intune, intuneApp: testIntuneApp}
	if err := s.VerifyIntuneTenant(context.Background(), "tenant-1"); err == nil {
		t.Fatal("a tenant that never verified was accepted")
	}
}

func TestVerifyIntuneTenantNeedsADeployedApplication(t *testing.T) {
	s := Service{intune: &stubIntune{}}
	if err := s.VerifyIntuneTenant(context.Background(), "tenant-1"); err == nil {
		t.Fatal("verification succeeded without application credentials")
	}
}

// A token minted before a role assignment landed carries no roles claim and
// would keep failing for its whole lifetime, so re-checking has to discard it.
func TestCheckTenantDiscardsCachedTokens(t *testing.T) {
	f := newFakeIntune(t)
	client := f.client()
	if err := client.CheckTenant(context.Background(), testIntegration); err != nil {
		t.Fatal(err)
	}
	if err := client.CheckTenant(context.Background(), testIntegration); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls != 2 {
		t.Fatalf("token calls = %d, want a fresh token per check", f.tokenCalls)
	}
	if f.discoveryCalls != 2 {
		t.Fatalf("discovery calls = %d, want a fresh lookup per check", f.discoveryCalls)
	}
}

// Without the Graph application permission the endpoint list comes back empty,
// which is exactly what an unconsented or under-permissioned tenant looks like.
func TestCheckTenantFailsWhenSCEPServiceIsAbsent(t *testing.T) {
	f := newFakeIntune(t)
	f.omitSCEP = true
	err := f.client().CheckTenant(context.Background(), testIntegration)
	if err == nil || !strings.Contains(err.Error(), "SCEP challenge validation permission") {
		t.Fatalf("want a permissions hint, got %v", err)
	}
}

func TestEntraErrorClassifiesDeclinedConsent(t *testing.T) {
	if _, failed := entraError(url.Values{}); failed {
		t.Fatal("a callback with no error was treated as a failure")
	}
	message, failed := entraError(url.Values{"error": {"consent_required"}})
	if !failed || message != declinedMessage {
		t.Fatalf("consent_required = %q", message)
	}
	message, failed = entraError(url.Values{"error": {"server_error"},
		"error_description": {"AADSTS90099: something broke."}})
	if !failed || !strings.Contains(message, "AADSTS90099") {
		t.Fatalf("unexpected message %q", message)
	}
}

// Windows appends NDES's CGI name to the SCEP URL from the profile, so the
// device asks for <endpoint>/pkiclient.exe. If that does not match a route it
// falls through to the catch-all "GET /" and the device parses an HTML page as
// a SCEP response, reporting "Failed to Initialize SCEP enrollment" and
// 0x800700CE ("the file name is too long").
func TestPublicRoutesAcceptWindowsPKIClientPath(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, nil, nil, "https://scep.example", IntuneApp{}, testAuthSecret)
	const id = "689b3324-f82b-456f-b566-d2dfa0a97a26"

	for _, target := range []string{"/scep/" + id, "/scep/" + id + "/pkiclient.exe"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			r := httptest.NewRequest(method, target+"?operation=GetCACaps", nil)
			_, pattern := mux.Handler(r)
			if !strings.Contains(pattern, "/scep/{endpointID}") {
				t.Fatalf("%s %s matched %q, want the public SCEP handler", method, target, pattern)
			}
		}
	}
}
