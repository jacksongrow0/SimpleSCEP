package layout

import (
	"reflect"
	"testing"
)

// TestSessionHasNoUnmappableField guards the two hand-written mappings that fill
// this struct — shellSession in view/home and its twin in view/pki.
//
// They exist as two copies because internal/auth imports view/layout, so layout
// cannot import auth to own the conversion, and no third package sits above both
// view trees.
//
// This test cannot see the mappings, so it does the next best thing: it fails
// when a field is added here, which is the moment both copies need looking at.
// Update the list below and both mappings in the same change.
func TestSessionHasNoUnmappableField(t *testing.T) {
	mapped := map[string]bool{
		"UserID":           true,
		"Name":             true,
		"Role":             true,
		"OrganizationName": true,
	}
	typ := reflect.TypeOf(Session{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if !mapped[name] {
			t.Errorf("Session.%s is new. Add it to shellSession in view/home/components.templ "+
				"AND to its twin in view/pki/certificate_authorities.templ, then list it here", name)
		}
	}
	if got, want := typ.NumField(), len(mapped); got != want {
		t.Errorf("Session has %d fields and %d are listed here", got, want)
	}
}
