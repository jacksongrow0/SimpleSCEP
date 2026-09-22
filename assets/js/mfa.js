// Passkey ceremonies.
//
// This is the only hand-written JavaScript in the application, and it exists
// because the WebAuthn API has no form-encoded equivalent: navigator.credentials
// takes and returns ArrayBuffers nested inside structured objects, so a plain
// form post cannot express either half of a ceremony.
//
// It is loaded by the second-factor prompt and by the authenticated shell,
// because passkey registration lives in the account settings dialog and that
// dialog is on every authenticated page. It stays out of the base layout so the
// signup and login pages, which run no ceremony, do not carry it.
//
// The registration button arrives with an htmx swap rather than with the
// document, so binding runs again after each swap and marks what it has already
// bound. Without the marker a panel refreshed three times would fire three
// ceremonies from one click.
//
// No eval, no inline handlers, no framework, no build step. Unlike the
// localTime() block and hyperscript, this file is already clean under a
// script-src 'self' policy without 'unsafe-eval', which is the direction the
// reported CSP is heading.
(function () {
	"use strict";

	// WebAuthn speaks ArrayBuffers; JSON speaks base64url. These two functions are
	// the whole impedance mismatch.
	function fromBase64Url(value) {
		const padded = value.replace(/-/g, "+").replace(/_/g, "/");
		const raw = atob(padded + "===".slice((padded.length + 3) % 4));
		const bytes = new Uint8Array(raw.length);
		for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
		return bytes.buffer;
	}

	function toBase64Url(buffer) {
		const bytes = new Uint8Array(buffer);
		let binary = "";
		for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
		return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	}

	// The server sends the options exactly as the specification defines them, so
	// the fields that need decoding are known and fixed.
	function decodeRequestOptions(options) {
		options.challenge = fromBase64Url(options.challenge);
		(options.allowCredentials || []).forEach(function (c) {
			c.id = fromBase64Url(c.id);
		});
		return options;
	}

	function decodeCreationOptions(options) {
		options.challenge = fromBase64Url(options.challenge);
		options.user.id = fromBase64Url(options.user.id);
		(options.excludeCredentials || []).forEach(function (c) {
			c.id = fromBase64Url(c.id);
		});
		return options;
	}

	function encodeAssertion(credential) {
		return {
			id: credential.id,
			type: credential.type,
			rawId: toBase64Url(credential.rawId),
			response: {
				clientDataJSON: toBase64Url(credential.response.clientDataJSON),
				authenticatorData: toBase64Url(credential.response.authenticatorData),
				signature: toBase64Url(credential.response.signature),
				userHandle: credential.response.userHandle
					? toBase64Url(credential.response.userHandle)
					: null,
			},
		};
	}

	function encodeAttestation(credential) {
		return {
			id: credential.id,
			type: credential.type,
			rawId: toBase64Url(credential.rawId),
			response: {
				clientDataJSON: toBase64Url(credential.response.clientDataJSON),
				attestationObject: toBase64Url(credential.response.attestationObject),
			},
		};
	}

	// same-origin credentials so the challenge and session cookies travel; the
	// server refuses anything cross-origin at the CSRF layer regardless.
	function post(url, body, signal) {
		return fetch(url, {
			method: "POST",
			credentials: "same-origin",
			headers: { "Content-Type": "application/json" },
			body: body === undefined ? null : JSON.stringify(body),
			signal: signal,
		});
	}

	async function readError(response, fallback) {
		try {
			const text = await response.text();
			return text.trim() || fallback;
		} catch (e) {
			return fallback;
		}
	}

	// Report writes into the result line beside the control, and raises a toast
	// with the same words.
	//
	// Both, not one, because the two are read in different situations. The
	// result line is where someone who just pressed the button is already
	// looking; the toast is what reaches them when the panel underneath has
	// been swapped away or the dialog closed behind the ceremony, which is
	// exactly when a WebAuthn call is most likely to have failed.
	//
	// These requests go out through fetch, so nothing here passes through htmx
	// and no HX-Trigger header would be read. The toast has to be raised on
	// this side.
	function report(id, message) {
		const target = document.getElementById(id);
		if (target) target.textContent = message;
		if (message && window.toast) window.toast("error", message);
	}

	// A user who cancels the browser prompt has not failed at anything, so it is
	// not reported as an error. Everything else is worth saying out loud.
	//
	// InvalidStateError is the authenticator saying it already holds a credential
	// for this account — the excludeCredentials list doing its job. "Your device
	// could not create a passkey" is true but reads as a fault; what happened is
	// that there was nothing to create.
	function describe(err, fallback) {
		if (err && (err.name === "NotAllowedError" || err.name === "AbortError")) return "";
		if (err && err.name === "InvalidStateError") {
			return "This device already has a passkey for your account. It is in the list above.";
		}
		return fallback;
	}

	async function signInWithPasskey(resultID) {
		report(resultID, "");
		try {
			const begun = await post("/auth/2fa/passkey/begin");
			if (!begun.ok) {
				report(resultID, await readError(begun, "Passkey sign-in is unavailable."));
				return;
			}
			const payload = await begun.json();
			// The options arrive wrapped in publicKey, per the specification.
			const options = decodeRequestOptions(payload.publicKey || payload);
			const assertion = await navigator.credentials.get({ publicKey: options });
			await finishSignIn(assertion, resultID);
		} catch (err) {
			report(resultID, describe(err, "Your device could not complete the passkey request."));
		}
	}

	// finishSignIn is the half both ceremonies share. The server cannot tell
	// which of them produced the assertion, and nothing here needs to either.
	async function finishSignIn(assertion, resultID) {
		const finished = await post("/auth/2fa/passkey/finish", encodeAssertion(assertion));
		if (!finished.ok) {
			report(resultID, await readError(finished, "That passkey was not accepted."));
			return;
		}
		// The server sets the session cookie on this response, so navigate rather
		// than letting fetch follow anything.
		window.location = finished.headers.get("HX-Redirect") || "/";
	}

	// Confirming with a passkey instead of typing a code.
	//
	// The assertion is the same one sign-in performs; what differs is where it
	// lands. On success the server has stamped the step-up grace, and whatever
	// was waiting on that confirmation is refreshed in place — the security
	// panel if that is what asked, otherwise the page.
	// Keep only one request per button. This handles an accidental double-click
	// without ever starting a ceremony before the person explicitly asks for it.
	const stepUpAttempts = new WeakMap();

	async function confirmWithPasskey(resultID, button) {
		const previous = stepUpAttempts.get(button);
		if (previous) previous.abort();
		const attempt = new AbortController();
		stepUpAttempts.set(button, attempt);
		report(resultID, "");
		try {
			const begun = await post("/security/step-up/passkey/begin", undefined, attempt.signal);
			if (!begun.ok) {
				report(resultID, await readError(begun, "Passkey confirmation is unavailable."));
				return;
			}
			const payload = await begun.json();
			const options = decodeRequestOptions(payload.publicKey || payload);
			const assertion = await navigator.credentials.get({
				publicKey: options,
				mediation: "required",
				signal: attempt.signal,
			});
			const finished = await post(
				"/security/step-up/passkey/finish",
				encodeAssertion(assertion),
				attempt.signal
			);
			if (!finished.ok) {
				report(resultID, await readError(finished, "That passkey was not accepted."));
				return;
			}
			if (window.toast) window.toast("success", "Confirmed");
			afterStepUp(button);
		} catch (err) {
			// A double-click deliberately aborts the first request. Its rejected
			// promise can settle after the replacement has started, so only the
			// current attempt is allowed to change the replacement's result line.
			if (stepUpAttempts.get(button) === attempt) {
				report(resultID, describe(err, "Your device could not complete the passkey request."));
			}
		} finally {
			if (stepUpAttempts.get(button) === attempt) stepUpAttempts.delete(button);
		}
	}

	// Where a confirmation given with a passkey leaves you.
	//
	// The code form gets this for free: it is an htmx post, so the dialog's own
	// script sees htmx:afterRequest and replays what was refused. A passkey
	// ceremony runs over fetch and fires no such event, so the same two
	// outcomes are spelled out here.
	//
	// The two are told apart by the standalone prompt's own id, not by being
	// inside a <dialog> at all: the account dialog draws this same prompt inline
	// where the security panel goes, so `closest("dialog")` matched there too
	// and confirming in the Security tab closed the dialog the person was
	// working in and reloaded the page under them.
	function afterStepUp(button) {
		const dialog = button && button.closest("#step-up-dialog");
		if (dialog) {
			// Confirmed in the standalone prompt, so something is waiting on it.
			const retarget = document.getElementById("step-up-retarget");
			const method = document.getElementById("step-up-method");
			dialog.close();
			if (retarget && retarget.value && window.htmx) {
				// Cleared before firing, so a second confirmation cannot replay
				// the same request again.
				const url = retarget.value;
				const verb = (method && method.value) || "GET";
				retarget.value = "";
				if (method) method.value = "";
				window.htmx.ajax(verb, url, { source: document.body });
				return;
			}
			window.location.reload();
			return;
		}
		// Confirmed in the account dialog's own prompt, which is sitting where
		// the panel goes.
		refreshPanel();
	}

	async function registerPasskey(labelID, resultID) {
		report(resultID, "");
		const labelField = document.getElementById(labelID);
		const label = labelField ? labelField.value : "";
		try {
			const begun = await post("/security/passkeys/begin");
			if (begun.status === 403) {
				// Step-up refused it. middleware.StepUp has already raised the dialog
				// through HX-Trigger, but fetch does not process htmx headers, so the
				// dialog is opened here instead.
				const trigger = begun.headers.get("HX-Trigger");
				if (trigger) {
					try {
						const parsed = JSON.parse(trigger);
						// Named without a hyphen because StepUpDialog listens for it in
						// hyperscript, which cannot tokenise one. See
						// view/layout/scripts.go.
						if (parsed.stepup) {
							document.body.dispatchEvent(
								new CustomEvent("stepup", { detail: parsed.stepup, bubbles: true })
							);
							return;
						}
					} catch (e) {
						/* fall through to the plain message */
					}
				}
				report(resultID, await readError(begun, "Confirm with your authenticator first."));
				return;
			}
			if (!begun.ok) {
				report(resultID, await readError(begun, "Could not start registration."));
				return;
			}
			const payload = await begun.json();
			const options = decodeCreationOptions(payload.publicKey || payload);
			const credential = await navigator.credentials.create({ publicKey: options });
			const url = "/security/passkeys/finish?label=" + encodeURIComponent(label);
			const finished = await post(url, encodeAttestation(credential));
			if (!finished.ok) {
				report(resultID, await readError(finished, "That passkey was not accepted."));
				return;
			}
			if (window.toast) window.toast("success", "Passkey “" + label + "” registered");
			refreshPanel();
		} catch (err) {
			report(resultID, describe(err, "Your device could not create a passkey."));
		}
	}

	// The new passkey has to appear in the list, and the list is a fragment inside
	// an open dialog. Reloading the page would show it too, at the cost of closing
	// the dialog the user is still working in, so the panel is re-fetched in place
	// and the reload is kept only for a page that has no panel.
	function refreshPanel() {
		const panel = document.getElementById("security-panel");
		if (panel && window.htmx) {
			window.htmx.ajax("GET", "/security/panel", { target: panel, swap: "outerHTML" });
			return;
		}
		window.location.reload();
	}

	// Controls can arrive in an htmx fragment after this script has loaded. They
	// are enabled here, while one delegated click listener below handles both
	// initial and later controls without relying on swap timing.
	function enable(selector) {
		document.querySelectorAll(selector).forEach(function (button) {
			button.hidden = false;
			button.disabled = false;
			button.removeAttribute("aria-disabled");
		});
	}

	function passkeyButton(target) {
		if (!target || typeof target.closest !== "function") return null;
		return target.closest(
			"[data-passkey-signin], [data-passkey-stepup], [data-passkey-register]"
		);
	}

	// Delegation is load-order independent: the confirm-it's-you methods are
	// fetched after the dialog opens, so their button may not exist during the
	// initial activate(). A listener on document still receives its click.
	document.addEventListener("click", function (event) {
		const button = passkeyButton(event.target);
		if (!button || button.disabled) return;
		event.preventDefault();
		if (button.hasAttribute("data-passkey-signin")) {
			signInWithPasskey(button.getAttribute("data-passkey-result"));
			return;
		}
		if (button.hasAttribute("data-passkey-stepup")) {
			confirmWithPasskey(button.getAttribute("data-passkey-result"), button);
			return;
		}
		registerPasskey(
			button.getAttribute("data-passkey-label"),
			button.getAttribute("data-passkey-result")
		);
	});

	// Progressive enhancement: sign-in and registration buttons are rendered
	// hidden and revealed only where the API exists. The step-up retry stays
	// visible but is disabled here when WebAuthn is unavailable. A browser without
	// WebAuthn still has the authenticator-code field, which always works.
	//
	// Where the API is missing, the explanation beside the control is revealed
	// instead. A hidden button with nothing in its place is indistinguishable
	// from a feature nobody built, and WebAuthn is missing far more often than it
	// looks: it needs a secure context, so any deployment reached over plain HTTP
	// on something other than localhost has none.
	function activate() {
		if (
			!window.PublicKeyCredential ||
			!navigator.credentials ||
			typeof navigator.credentials.get !== "function"
		) {
			document.querySelectorAll("[data-passkey-signin], [data-passkey-stepup]").forEach(function (button) {
				button.hidden = false;
				button.disabled = true;
				button.setAttribute("aria-disabled", "true");
			});
			document.querySelectorAll("[data-passkey-unsupported]").forEach(function (note) {
				note.hidden = false;
			});
			return;
		}
		enable("[data-passkey-signin], [data-passkey-stepup], [data-passkey-register]");
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", activate);
	} else {
		activate();
	}
	document.addEventListener("htmx:afterSwap", activate);
	document.addEventListener("htmx:afterSettle", activate);
})();
