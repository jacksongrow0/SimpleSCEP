package acme

import (
	"encoding/json"
	"testing"
	"time"
)

// The wire format is the contract. Every other test in this package works with
// Go values, where field casing is invisible; these work with the bytes a
// client actually parses, which is where RFC 8555's member names live.

const wireHost = "firewall01.example.internal"

func wireAuthorization() (Authorization, Challenge) {
	a := Authorization{
		ID: "aaaaaaaa-0000-0000-0000-000000000001", OrganizationID: testOrg,
		OrderID: "bbbbbbbb-0000-0000-0000-000000000001", IdentifierType: IdentifierDNS,
		IdentifierValue: wireHost, Status: StatusValid, ExpiresAt: time.Now().Add(time.Hour),
	}
	c := Challenge{
		ID: "cccccccc-0000-0000-0000-000000000001", OrganizationID: testOrg,
		AuthorizationID: a.ID, Type: ChallengeExternal, Token: "tok", Status: StatusValid,
	}
	return a, c
}

// encode renders a response body the way writeJSON does and parses it back as
// raw JSON, so assertions see the member names rather than Go field names.
func encode(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// TestAuthorizationIdentifierIsLowercaseOnTheWire is a regression test for an
// order that could never be finalized. Identifier carried no JSON tags, so it
// marshalled as {"Type":...,"Value":...}. Clients read the name out of an
// authorization by the lowercase member RFC 8555 §7.1.4 defines: acme.sh found
// no "value", extracted an empty domain, could not match the authorization back
// to the name it had asked for, and stopped before finalize.
func TestAuthorizationIdentifierIsLowercaseOnTheWire(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	h := Handler{service: svc, publicURL: testURL}
	a, c := wireAuthorization()

	body := encode(t, h.authorizationJSON(endpointOf(t, repo), a, c))
	identifier, ok := body["identifier"].(map[string]any)
	if !ok {
		t.Fatalf("identifier is %T, want an object", body["identifier"])
	}
	if got := identifier["type"]; got != IdentifierDNS {
		t.Errorf(`identifier["type"] = %v, want %q`, got, IdentifierDNS)
	}
	// This is the assertion the bug would have failed: a client reading the
	// lowercase member must get the name back, not "".
	if got := identifier["value"]; got != wireHost {
		t.Errorf(`identifier["value"] = %v, want %q`, got, wireHost)
	}
}

// TestOrderIdentifiersAreLowercaseOnTheWire covers the same struct on the other
// response that carries it. An order and its authorizations are serialized by
// different functions, and a client cross-checks the two.
func TestOrderIdentifiersAreLowercaseOnTheWire(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	h := Handler{service: svc, publicURL: testURL}
	a, _ := wireAuthorization()
	order := Order{ID: a.OrderID, OrganizationID: testOrg, EndpointID: testEndpoint,
		Status: StatusReady, ExpiresAt: time.Now().Add(time.Hour)}

	body := encode(t, h.orderJSON(endpointOf(t, repo), order, []Authorization{a}))
	identifiers, ok := body["identifiers"].([]any)
	if !ok || len(identifiers) != 1 {
		t.Fatalf("identifiers = %#v, want one entry", body["identifiers"])
	}
	first, ok := identifiers[0].(map[string]any)
	if !ok {
		t.Fatalf("identifier is %T, want an object", identifiers[0])
	}
	if got := first["type"]; got != IdentifierDNS {
		t.Errorf(`identifiers[0]["type"] = %v, want %q`, got, IdentifierDNS)
	}
	if got := first["value"]; got != wireHost {
		t.Errorf(`identifiers[0]["value"] = %v, want %q`, got, wireHost)
	}
}

// TestResponseMembersAreNotGoFieldNames generalizes the bug rather than the
// instance of it. Responses are assembled as map[string]any with literal member
// names, but any struct nested inside one is marshalled by the encoder, and an
// untagged struct silently exports its Go field names. RFC 8555 has no member
// beginning with an upper-case letter, so that is a reliable tell, and it fires
// for the next untagged struct that reaches the wire as well as this one.
func TestResponseMembersAreNotGoFieldNames(t *testing.T) {
	repo := newFakeStore()
	svc, _ := newTestService(repo)
	h := Handler{service: svc, publicURL: testURL}
	e := endpointOf(t, repo)
	a, c := wireAuthorization()
	order := Order{ID: a.OrderID, OrganizationID: testOrg, EndpointID: testEndpoint,
		Status: StatusReady, ExpiresAt: time.Now().Add(time.Hour)}

	responses := map[string]map[string]any{
		"directory":     svc.Directory(e),
		"account":       accountJSON(Account{Status: StatusValid, Contact: "mailto:ops@example.test"}),
		"order":         h.orderJSON(e, order, []Authorization{a}),
		"authorization": h.authorizationJSON(e, a, c),
		"challenge":     h.challengeJSON(e, c),
	}
	for name, body := range responses {
		for _, member := range members(t, encode(t, body)) {
			if member[0] >= 'A' && member[0] <= 'Z' {
				t.Errorf("the %s response carries member %q; ACME member names are lower camel case, "+
					"so this is an untagged Go struct reaching the wire", name, member)
			}
		}
	}
}

// members walks decoded JSON and collects every object key, at any depth.
func members(t *testing.T, v any) []string {
	t.Helper()
	switch value := v.(type) {
	case map[string]any:
		var out []string
		for k, nested := range value {
			out = append(out, k)
			out = append(out, members(t, nested)...)
		}
		return out
	case []any:
		var out []string
		for _, nested := range value {
			out = append(out, members(t, nested)...)
		}
		return out
	}
	return nil
}
