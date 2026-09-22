// Toast notifications.
//
// Plain JavaScript rather than hyperscript, for the reasons view/layout/scripts.go
// sets out at length: a hyperscript parse error installs nothing at all — not
// the broken feature, the whole element's script — and says so only in the
// console, so no Go test can reach it and two features in this application were
// dead for months because of it. It is also what internal/middleware/headers.go
// wants: hyperscript needs 'unsafe-eval', this file is clean under
// script-src 'self'.
//
// Three entry points, one renderer:
//
//   window.toast(tone, text)   called directly, from hyperscript or mfa.js
//   a `toast` event on <body>  raised by the server through HX-Trigger
//   data-initial-* on the host raised by the server through the flash cookie,
//                              for the redirect case where HX-Trigger cannot
//                              survive the navigation
//
// The event name has no hyphen. hyperscript reads one as subtraction, and while
// nothing listens for this in hyperscript today, `stepup` is named that way for
// exactly this reason and a future listener should not have to rediscover it.
(function () {
	"use strict";

	var REGION_ID = "toast-region";

	// How long each tone stays. Errors do not leave on their own: an error the
	// user missed is the one that mattered, and a message that reports why a
	// certificate authority refused to change status is worth a click to
	// dismiss.
	var DURATIONS = { success: 4000, info: 4000, warning: 7000, error: 0 };

	var TONE_CLASSES = {
		success: "border-[color-mix(in_oklch,var(--color-success)_45%,transparent)] text-success",
		warning: "border-[color-mix(in_oklch,var(--color-warning)_45%,transparent)] text-warning",
		error: "border-[color-mix(in_oklch,var(--color-destructive)_45%,transparent)] text-destructive",
		info: "border-border text-foreground"
	};

	var TONE_ICONS = { success: "✓", warning: "!", error: "!", info: "•" };

	function region() {
		return document.getElementById(REGION_ID);
	}

	function normalise(tone) {
		return Object.prototype.hasOwnProperty.call(DURATIONS, tone) ? tone : "info";
	}

	function show(tone, text) {
		var host = region();
		if (!host || !text) return;
		tone = normalise(tone);

		var el = document.createElement("div");
		el.className =
			"pointer-events-auto flex items-start gap-2.5 rounded-lg border bg-popover px-4 py-3 " +
			"text-sm shadow-[0_12px_36px_#0008] transition-[opacity,transform] duration-200 " +
			"opacity-0 translate-y-2 motion-reduce:transition-none motion-reduce:translate-y-0 " +
			TONE_CLASSES[tone];
		// An error is worth interrupting a screen reader for; a confirmation is
		// not. The region itself is polite, so the assertive ones carry their
		// own live region.
		el.setAttribute("role", tone === "error" ? "alert" : "status");
		if (tone === "error") el.setAttribute("aria-live", "assertive");

		var glyph = document.createElement("span");
		glyph.className = "mt-px shrink-0 font-bold";
		glyph.setAttribute("aria-hidden", "true");
		glyph.textContent = TONE_ICONS[tone];

		var body = document.createElement("div");
		body.className = "min-w-0 flex-1 text-foreground";
		// textContent, never innerHTML. Some of what reaches here is an error
		// string built from user input.
		body.textContent = text;

		var close = document.createElement("button");
		close.type = "button";
		close.className =
			"-my-1 -mr-2 shrink-0 cursor-pointer rounded border-0 bg-transparent px-2 py-1 " +
			"text-muted-foreground hover:text-foreground focus-visible:outline-2 " +
			"focus-visible:outline-offset-2 focus-visible:outline-primary";
		close.setAttribute("aria-label", "Dismiss");
		close.textContent = "✕";

		el.appendChild(glyph);
		el.appendChild(body);
		el.appendChild(close);
		host.appendChild(el);

		// Next frame, so the browser lays the element out at opacity 0 before
		// the class change animates it in. Setting both in one frame is a
		// no-op.
		requestAnimationFrame(function () {
			el.classList.remove("opacity-0", "translate-y-2");
		});

		// Each toast owns its own timer. The element this replaced was a
		// singleton, so a second message overwrote the first and then the
		// first message's timer hid the second one early.
		var timer = null;
		function dismiss() {
			if (timer) clearTimeout(timer);
			el.classList.add("opacity-0", "translate-y-2");
			setTimeout(function () {
				if (el.parentNode) el.parentNode.removeChild(el);
			}, 200);
		}
		function arm() {
			var ms = DURATIONS[tone];
			if (ms) timer = setTimeout(dismiss, ms);
		}
		function hold() {
			if (timer) {
				clearTimeout(timer);
				timer = null;
			}
		}

		close.addEventListener("click", dismiss);
		// Reading a message should not run out its clock, and neither should
		// tabbing to its dismiss button.
		el.addEventListener("mouseenter", hold);
		el.addEventListener("mouseleave", arm);
		el.addEventListener("focusin", hold);
		el.addEventListener("focusout", arm);
		arm();
	}

	window.toast = show;

	// The server's same-page path. htmx dispatches HX-Trigger events on the
	// element that made the request, and they bubble to the body.
	document.addEventListener("toast", function (e) {
		if (e.detail) show(e.detail.tone, e.detail.text);
	});

	// The backstop for a refusal that said nothing.
	//
	// htmx's default responseHandling marks 4xx and 5xx as errors and does not
	// swap them, so a handler answering `http.Error(w, "issue failed", 500)` to an
	// hx-post produced no swap, no toast and no console line: the button did
	// nothing at all, silently, and the user pressed it again. internal/pki alone
	// had many such answers and no toasts.
	//
	// internal/toast.Fail is the real fix and is what handlers should use: it sets
	// HX-Trigger alongside the real status, so the message is the server's own
	// words. This exists for everything that has not been converted yet, and as a
	// permanent floor under anything added later — a handler that forgets is now
	// merely terse rather than mute.
	//
	// A response that did carry HX-Trigger is left alone. htmx dispatches that
	// trigger regardless of status, so the "toast" listener above has already
	// shown the server's message and a second one here would double it.
	document.addEventListener("htmx:responseError", function (e) {
		var xhr = e.detail && e.detail.xhr;
		if (!xhr) return;
		try {
			if (xhr.getResponseHeader("HX-Trigger")) return;
		} catch (_) {
			// Some browsers throw on header access for an aborted request. Falling
			// through to a generic message is the safe direction.
		}
		show("error", messageForStatus(xhr.status));
	});

	// messageForStatus turns a bare status into something a person can act on.
	//
	// The response bodies behind these are internal strings — "overview failed",
	// "portal failed" — written for a log rather than for a reader, so they are
	// deliberately not shown. What the status can honestly convey is whether to
	// retry, reload, or ask an administrator.
	function messageForStatus(status) {
		switch (status) {
			case 403:
				return "You do not have permission to do that.";
			case 404:
				return "That is no longer there. Reload the page.";
			case 409:
				return "Something else changed that first. Reload the page and try again.";
			case 429:
				return "Too many requests. Wait a moment and try again.";
			case 0:
				return "That request could not be sent. Check your connection and try again.";
			default:
				if (status >= 500) return "Something went wrong on our side. Try again in a moment.";
				return "That request was refused. Reload the page and try again.";
		}
	}

	// The server's across-a-redirect path. The shell renders the flash onto the
	// host as attributes rather than as an inline <script>, so nothing new
	// needs a CSP hash. Cleared once read so an htmx swap that touches the
	// region cannot replay it.
	function drain() {
		var host = region();
		if (!host || !host.hasAttribute("data-initial-text")) return;
		var tone = host.getAttribute("data-initial-tone");
		var text = host.getAttribute("data-initial-text");
		host.removeAttribute("data-initial-tone");
		host.removeAttribute("data-initial-text");
		show(tone, text);
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", drain);
	} else {
		drain();
	}
})();
