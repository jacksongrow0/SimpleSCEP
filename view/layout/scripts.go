package layout

// The hyperscript driving the application shell, kept here rather than inline
// because templ cannot parse a concatenated Go expression inside an attribute
// literal, and these are too long to read on one line in the template.
//
// Everything in this file is client-side behaviour that no Go test can reach.
// `go build`, `go vet`, `templ generate` and the whole test suite pass with any
// of it broken, and hyperscript's own failures are quiet: a parse error is a
// console message, and it installs nothing at all — not the broken feature, the
// entire element's script. Two features in here were dead for that reason, and
// a third threw at runtime behind them. Anything changed here has to be opened
// in a browser before it is believed.
//
// The step-up prompt was the expensive one. Every confirmation in the
// application failed to appear — deleting a certificate authority, rotating one,
// inviting an administrator or changing a role. The
// server was refusing correctly and sending the trigger; nothing was listening.
// Two tokens caused it, and both are recorded here because neither is obvious
// and both are easy to reintroduce:
//
//   - An event name cannot contain a hyphen. `on step-up(...)` tokenises the
//     hyphen as subtraction. The event is named `stepup` for that reason, and
//     middleware.promptStepUp and mfa.js send that name.
//   - There is no `open` command. `close` exists, which is what made the pair
//     look symmetric and correct; showing a dialog is `call me.showModal()`.
//
// showModal rather than the `open` attribute matters twice over now. A dialog
// opened by attribute is not in the top layer, so with the account settings
// dialog already modal the prompt would render behind it — visible in the DOM,
// invisible on screen, which is the same bug wearing a different hat.
const (
	// stepUpDialogScript listens for the stepup event middleware.StepUp raises
	// through HX-Trigger. It fills in what is about to happen, remembers which
	// request to retry, and clears anything left from a previous prompt.
	//
	// It no longer touches the code field. The prompt's methods are fetched
	// when it opens, because which of them a person can use is a fact about
	// that person, so there is no field here to clear or focus at the moment
	// this runs. Focus is handled by an autofocus attribute in the fragment,
	// which htmx applies to content it swaps in.
	stepUpDialogScript = "on stepup(action, retarget, method) from document " +
		"put action into #step-up-action.textContent " +
		"then set #step-up-retarget.value to retarget " +
		"then set #step-up-method.value to method " +
		"then set #step-up-result.textContent to '' " +
		"then call me.showModal() end " +
		"on click if target is me close me end"

	// stepUpFormScript re-fires the refused request once the confirmation is
	// accepted. Without it the user confirms, the dialog closes, and nothing
	// visibly happens — leaving them unsure whether the action they asked for
	// ran.
	//
	// It keys off `stepupdone`, an event the step-up handler raises through
	// HX-Trigger beside the toast, rather than off htmx:afterRequest as it used
	// to. That mattered the moment the prompt's methods became a fetched
	// fragment: the dialog now makes a request of its own to load them, and a
	// listener that closed on any successful request inside itself would shut
	// the dialog the instant it opened.
	//
	// Reading a named event also avoids reaching into event.detail.requestConfig
	// to tell the two requests apart. Nested property access is the kind of
	// thing that throws at runtime in hyperscript, which silently abandons the
	// rest of the feature — the failure mode this file exists to warn about.
	//
	// Two features rather than one nested condition, so closing does not depend
	// on there being anything to retry. The retarget guard is not theoretical:
	// htmx treats an empty URL as the current page, so confirming with nothing
	// pending posted the form to whatever page the user was on and got a 405
	// back. It is cleared after firing so it can never be sent twice.
	//
	// The passkey path does not come through here. That ceremony runs over
	// fetch, which raises no htmx event at all, so mfa.js closes and replays in
	// afterStepUp — the same two steps, spelled out on that side.
	stepUpFormScript = "on stepupdone from document call me.close() end " +
		"on stepupdone from document " +
		"if #step-up-retarget.value is not '' " +
		"call htmx.ajax(#step-up-method.value, #step-up-retarget.value, {source: document.body}) " +
		"then set #step-up-retarget.value to '' then set #step-up-method.value to '' end"

	// userMenuToggleScript opens and closes the account menu above the user card.
	//
	// `halt the event` comes first, and that ordering is the whole point. It used
	// to come last, after `toggle my @aria-expanded between 'true' and 'false'` —
	// which throws at runtime, because `toggle between` takes classes and not
	// attributes. Everything after the throw was skipped, including the halt, so
	// the click carried on to the document and the menu's own dismiss handler
	// closed it again in the same click. The menu opened and shut too fast to see.
	//
	// That was invisible for as long as the dismiss handler had a parse error of
	// its own and installed nothing; fixing that one is what exposed this one.
	// Halting first means a later mistake can no longer reach back and undo the
	// part that already worked.
	userMenuToggleScript = "on click halt the event " +
		"then toggle @hidden on #user-menu " +
		"then if #user-menu's @hidden is null " +
		"set my @aria-expanded to 'true' " +
		"else set my @aria-expanded to 'false' end"

	// userMenuDismissScript closes the menu on a click anywhere outside it. The
	// user card is outside it, which is why the toggle above has to halt the
	// event rather than rely on this being written to exclude it.
	userMenuDismissScript = "on click elsewhere add @hidden to me " +
		"then set @aria-expanded of #user-menu-toggle to 'false'"

	// userSettingsOpenScript resets a dialog that remains in the DOM between
	// openings. Without the reset, closing it on Security and reopening it would
	// reveal the previously rendered factors without navigating through the
	// newly step-up-protected Security tab.
	userSettingsOpenScript = "on click " +
		"remove .active from .user-tab then add .active to #user-tab-account " +
		"then add @hidden to .user-tab-panel then remove @hidden from #panel-account " +
		"then put 'Loading your security settings…' into #security-panel " +
		"then call document.getElementById(my @data-dialog).showModal() " +
		"then add @hidden to #user-menu " +
		"then set @aria-expanded of #user-menu-toggle to 'false'"
)

// tabScript switches the account dialog to one panel. The active class moves
// with hyperscript's `take`, which is exactly this: give it to me, remove it
// from everything else matching the selector.
func tabScript(panelID string) string {
	return "on click take .active from .user-tab for me " +
		"then add @hidden to .user-tab-panel " +
		"then remove @hidden from #" + panelID
}

// securityTabScript clears any panel rendered under an earlier confirmation
// before asking the server for it again.
//
// The dialog stays in the DOM between openings, so without the clear, closing
// it on Security and reopening it would show the previous session's controls
// for as long as the fetch takes. The server decides what comes back — the
// panel, or the prompt that stands in for it while the grace has lapsed — so
// this only has to make sure the stale copy is not what is on screen while that
// is being decided.
func securityTabScript() string {
	return "on click put 'Loading your security settings…' into #security-panel " +
		"then take .active from .user-tab for me " +
		"then add @hidden to .user-tab-panel " +
		"then remove @hidden from #panel-security"
}
