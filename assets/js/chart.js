// The hover layer for the overview's enrollment graph.
//
// Plain JavaScript rather than hyperscript, for the reasons view/layout/scripts.go
// sets out at length: a hyperscript parse error installs nothing at all — not
// the broken feature, the whole element's script — and says so only in the
// console. It is also what internal/middleware/headers.go wants: hyperscript
// needs 'unsafe-eval', this file is clean under script-src 'self'.
//
// This file draws nothing and builds no markup. The server rendered the lines,
// a parked dot for each of them, and every row of the tooltip; all that happens
// here is that things move and numbers are written into text nodes that already
// exist. Two consequences worth keeping:
//
//   - Every class name stays in view/home/enrollments.templ, where Tailwind's
//     scanner can see it. A class assembled in this file would need input.css to
//     @source it, and would silently render unstyled until someone noticed.
//   - Series labels never pass through innerHTML, because they never pass
//     through here at all.
//
// The graph is readable with this file missing or broken: the lines are drawn,
// the legend carries each method's total for the window, and the table under
// the graph carries every daily figure. The hover layer is a convenience over
// data that is already on the page, which is the only reason it is allowed to
// live somewhere no Go test can reach.
(function () {
	"use strict";

	// How far above the pointer the tooltip floats, and how much clear space to
	// keep at the edges of the figure so it is never half outside the card.
	var TOOLTIP_OFFSET = 16;
	var EDGE_MARGIN = 8;

	function number(el, name) {
		return parseFloat(el.getAttribute(name));
	}

	function setup(figure) {
		var svg = figure.querySelector("svg");
		var tooltip = figure.querySelector("[data-chart-tooltip]");
		var crosshair = figure.querySelector("[data-chart-crosshair]");
		var date = figure.querySelector("[data-chart-tooltip-date]");
		if (!svg || !tooltip || !crosshair || !date) return;

		var days = (figure.getAttribute("data-days") || "").split("|");
		if (days.length < 2) return;
		var left = number(figure, "data-plot-left");
		var right = number(figure, "data-plot-right");
		var top = number(figure, "data-plot-top");
		var bottom = number(figure, "data-plot-bottom");
		var max = number(figure, "data-max");
		var viewWidth = svg.viewBox.baseVal.width;
		if (!(max > 0) || !(viewWidth > 0)) return;

		// One entry per drawn line, pairing the values with the dot that marks
		// them and the tooltip row that reports them. A line whose dot or row is
		// missing is skipped rather than throwing partway through a redraw.
		var series = [];
		var lines = figure.querySelectorAll("[data-chart-series]");
		for (var i = 0; i < lines.length; i++) {
			var profile = lines[i].getAttribute("data-chart-series");
			var dot = figure.querySelector('[data-chart-dot="' + profile + '"]');
			var row = figure.querySelector('[data-chart-tooltip-row="' + profile + '"]');
			var value = row && row.querySelector("[data-chart-tooltip-value]");
			if (!dot || !value) continue;
			var counts = (lines[i].getAttribute("data-counts") || "").split(",");
			series.push({ dot: dot, value: value, counts: counts });
		}
		if (!series.length) return;

		var current = days.length - 1;
		var showing = false;

		function xAt(index) {
			return left + ((right - left) * index) / (days.length - 1);
		}

		function yAt(count) {
			return bottom - ((bottom - top) * count) / max;
		}

		// Where the pointer is, in the SVG's own units. The element scales to
		// its column, so the ratio has to be measured rather than assumed.
		function indexAt(clientX) {
			var box = svg.getBoundingClientRect();
			if (!box.width) return current;
			var userX = ((clientX - box.left) / box.width) * viewWidth;
			var ratio = (userX - left) / (right - left);
			var index = Math.round(ratio * (days.length - 1));
			if (index < 0) return 0;
			if (index > days.length - 1) return days.length - 1;
			return index;
		}

		// clientY is optional: keyboard navigation has no pointer, and parks the
		// tooltip at the middle of the plot instead.
		function show(index, clientY) {
			current = index;
			showing = true;
			var x = xAt(index);
			crosshair.setAttribute("x1", x);
			crosshair.setAttribute("x2", x);
			crosshair.setAttribute("visibility", "visible");
			for (var i = 0; i < series.length; i++) {
				var count = parseInt(series[i].counts[index], 10) || 0;
				series[i].dot.setAttribute("cx", x);
				series[i].dot.setAttribute("cy", yAt(count));
				series[i].dot.setAttribute("visibility", "visible");
				series[i].value.textContent = String(count);
			}
			date.textContent = days[index];
			tooltip.hidden = false;
			place(x, clientY);
		}

		// The tooltip is a positioned HTML element over an SVG that scales, so
		// its offsets are inline styles — there is no class that can carry a
		// value computed per pointer position. It is clamped to the figure so it
		// never hangs off the card, and it is translated half its own width by a
		// class, so `left` here is the crosshair, not the corner.
		function place(x, clientY) {
			var figureBox = figure.getBoundingClientRect();
			var svgBox = svg.getBoundingClientRect();
			if (!svgBox.width || !figureBox.width) return;
			var scale = svgBox.width / viewWidth;
			var half = tooltip.offsetWidth / 2;
			var pixels = svgBox.left - figureBox.left + x * scale;
			var lowest = half + EDGE_MARGIN;
			var highest = figureBox.width - half - EDGE_MARGIN;
			if (pixels < lowest) pixels = lowest;
			if (pixels > highest) pixels = highest;
			tooltip.style.left = pixels + "px";

			var y = typeof clientY === "number"
				? clientY - figureBox.top - tooltip.offsetHeight - TOOLTIP_OFFSET
				: svgBox.top - figureBox.top + ((top + bottom) / 2) * scale - tooltip.offsetHeight / 2;
			if (y < EDGE_MARGIN) y = EDGE_MARGIN;
			var floor = figureBox.height - tooltip.offsetHeight - EDGE_MARGIN;
			if (y > floor) y = floor;
			tooltip.style.top = y + "px";
		}

		function hide() {
			showing = false;
			crosshair.setAttribute("visibility", "hidden");
			for (var i = 0; i < series.length; i++) {
				series[i].dot.setAttribute("visibility", "hidden");
			}
			tooltip.hidden = true;
		}

		svg.addEventListener("pointermove", function (event) {
			show(indexAt(event.clientX), event.clientY);
		});
		svg.addEventListener("pointerleave", hide);
		// A tap holds the readout rather than flashing it: pointerleave does not
		// fire for touch until the next tap elsewhere.
		svg.addEventListener("pointerdown", function (event) {
			show(indexAt(event.clientX), event.clientY);
		});

		// The keyboard gets the same readout as the pointer, which is the whole
		// reason the SVG is focusable. Home and End are here because walking
		// thirty days one arrow at a time to reach today is not navigation.
		svg.addEventListener("focus", function () {
			show(current);
		});
		svg.addEventListener("blur", hide);
		svg.addEventListener("keydown", function (event) {
			var index = current;
			if (event.key === "ArrowLeft") index = current - 1;
			else if (event.key === "ArrowRight") index = current + 1;
			else if (event.key === "Home") index = 0;
			else if (event.key === "End") index = days.length - 1;
			else return;
			if (index < 0) index = 0;
			if (index > days.length - 1) index = days.length - 1;
			event.preventDefault();
			show(index);
		});

		// The figure's width changes with the window and with the sidebar, and
		// the tooltip's offsets are in pixels, so a resize while it is open
		// leaves it pointing at the wrong day.
		window.addEventListener("resize", function () {
			if (showing) place(xAt(current));
		});
	}

	// Marked as it is set up, because htmx swaps re-run this and binding a
	// second set of listeners to the same figure is invisible until the
	// tooltip starts fighting itself.
	function render(root) {
		var scope = root || document;
		var figures = [].slice.call(scope.querySelectorAll('[data-chart="enrollments"]'));
		// htmx hands afterSwap the swapped element itself, which
		// querySelectorAll does not include in its own results.
		if (scope.matches && scope.matches('[data-chart="enrollments"]')) figures.push(scope);
		for (var i = 0; i < figures.length; i++) {
			if (figures[i].hasAttribute("data-chart-ready")) continue;
			figures[i].setAttribute("data-chart-ready", "");
			setup(figures[i]);
		}
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", function () {
			render(document);
		});
	} else {
		render(document);
	}
	document.addEventListener("htmx:afterSwap", function (event) {
		render(event.target);
	});
})();
