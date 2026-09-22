package auth

import (
	"context"
	"strconv"

	"github.com/google/uuid"
	authview "github.com/jacksongrow0/SimpleSCEP/view/auth"
)

// The ways a person can prove they are still the one at the keyboard.
//
// This exists as a list because the interface used to assume there was one. The
// step-up prompt asked for a six-digit code and nothing else, so someone who had
// registered a passkey — and who signs in with it — was still sent to find their
// authenticator app every time they opened their own security settings or
// deleted a certificate authority.
//
// Adding a third factor is meant to be an entry in stepUpCatalogue plus a
// verifier for it. Nothing in the templates names a factor: they render whatever
// StepUpMethods returns, in the order it returns them, and a Kind they do not
// recognise is skipped rather than rendered as a broken control.

// Step-up method kinds. These strings reach the browser, so they are stable
// identifiers rather than display text.
const (
	StepUpTOTP    = "totp"
	StepUpPasskey = "passkey"
)

// StepUpMethod is one way to satisfy a confirmation, as offered to a user who
// actually holds it.
type StepUpMethod struct {
	Kind  string
	Label string
	// Detail says which registered credentials this covers, so a person with
	// two authenticators and one passkey can tell what they are being asked
	// for.
	Detail string
}

// stepUpCatalogue is every kind this application knows how to verify, in the
// order they are offered.
//
// Order is a real decision and not incidental. A passkey is one gesture and a
// code is a hunt through a phone, so where both are held the passkey comes
// first — which is the opposite of what the interface did before.
var stepUpCatalogue = []struct {
	kind  string
	label string
	// count reports how many credentials of this kind the user holds, and
	// whether the deployment can use them at all.
	count func(h Handler, ctx context.Context, userID uuid.UUID) (int, bool, error)
}{
	{
		kind:  StepUpPasskey,
		label: "Passkey",
		count: func(h Handler, ctx context.Context, userID uuid.UUID) (int, bool, error) {
			// Unusable rather than absent when APP_URL yields no relying-party
			// id. Offering it there would produce a button that always fails.
			if h.webauthn == nil {
				return 0, false, nil
			}
			rows, err := h.repo.Passkeys(ctx, userID)
			return len(rows), true, err
		},
	},
	{
		kind:  StepUpTOTP,
		label: "Authenticator app",
		count: func(h Handler, ctx context.Context, userID uuid.UUID) (int, bool, error) {
			rows, err := h.repo.TOTPCredentials(ctx, userID)
			return len(rows), true, err
		},
	},
}

// StepUpMethods lists what this user can confirm with right now.
//
// A kind they hold none of is left out entirely. The alternative — rendering
// every kind and disabling the empty ones — turns the prompt into a catalogue of
// features rather than a question, and the answer to "how do I confirm?" stops
// being visible at a glance.
func (h Handler) StepUpMethods(ctx context.Context, userID uuid.UUID) ([]StepUpMethod, error) {
	out := make([]StepUpMethod, 0, len(stepUpCatalogue))
	for _, entry := range stepUpCatalogue {
		n, usable, err := entry.count(h, ctx, userID)
		if err != nil {
			return nil, err
		}
		if !usable || n == 0 {
			continue
		}
		out = append(out, StepUpMethod{Kind: entry.kind, Label: entry.label, Detail: registeredCount(n)})
	}
	return out, nil
}

func registeredCount(n int) string {
	if n == 1 {
		return "1 registered"
	}
	return strconv.Itoa(n) + " registered"
}

// stepUpViews converts the methods into what the templates render.
func stepUpViews(methods []StepUpMethod) []authview.StepUpMethodView {
	out := make([]authview.StepUpMethodView, 0, len(methods))
	for _, m := range methods {
		out = append(out, authview.StepUpMethodView{Kind: m.Kind, Label: m.Label, Detail: m.Detail})
	}
	return out
}
