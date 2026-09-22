package home

import (
	"strings"
	"testing"
	"time"
)

var testMethods = []EnrollmentMethod{
	{Profile: "csr", Label: "CSR"},
	{Profile: "server", Label: "Manual server"},
	{Profile: "client", Label: "Manual client"},
	{Profile: "scep", Label: "SCEP"},
	{Profile: "acme", Label: "ACME"},
	{Profile: "est", Label: "EST"},
}

func day(start time.Time, offset int) time.Time { return start.AddDate(0, 0, offset) }

func TestBuildEnrollmentsFillsTheWholeWindow(t *testing.T) {
	start := EnrollmentWindowStart(time.Date(2026, 8, 29, 17, 42, 0, 0, time.UTC))
	if want := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC); !start.Equal(want) {
		t.Fatalf("window starts %s, want %s", start, want)
	}
	chart := BuildEnrollments(start, testMethods, []EnrollmentCount{
		{Day: day(start, 0), Profile: "scep", Count: 3},
		{Day: day(start, 29), Profile: "scep", Count: 5},
		{Day: day(start, 10), Profile: "acme", Count: 2},
	})
	if len(chart.Days) != EnrollmentWindowDays {
		t.Fatalf("chart covers %d days, want %d", len(chart.Days), EnrollmentWindowDays)
	}
	if chart.Total != 10 {
		t.Errorf("total is %d, want 10", chart.Total)
	}
	// Every series has to be the same length as the axis, or index i means a
	// different day on different lines and the whole graph is a lie.
	for _, series := range chart.Series {
		if len(series.Counts) != EnrollmentWindowDays {
			t.Fatalf("%s has %d points, want %d", series.Label, len(series.Counts), EnrollmentWindowDays)
		}
	}
	scep := chart.Series[3]
	if scep.Label != "SCEP" || scep.Total != 8 || scep.Counts[0] != 3 || scep.Counts[29] != 5 {
		t.Errorf("SCEP series is %+v, want 3 on the first day and 5 on the last", scep)
	}
	if drawn := chart.Drawn(); len(drawn) != 2 {
		t.Errorf("%d lines drawn, want the 2 methods that issued anything", len(drawn))
	}
}

// A slot is the method's position in the roster, never its rank in this
// window. Colour follows the entity: a month where nobody used SCEP must not
// repaint ACME in SCEP's colour.
func TestEnrollmentSlotsFollowTheMethodNotTheRank(t *testing.T) {
	start := EnrollmentWindowStart(time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	busy := BuildEnrollments(start, testMethods, []EnrollmentCount{
		{Day: day(start, 1), Profile: "est", Count: 40},
		{Day: day(start, 1), Profile: "csr", Count: 1},
	})
	quiet := BuildEnrollments(start, testMethods, []EnrollmentCount{
		{Day: day(start, 1), Profile: "est", Count: 1},
	})
	for i, series := range busy.Series {
		if series.Slot != i+1 {
			t.Errorf("%s is slot %d, want %d", series.Label, series.Slot, i+1)
		}
		if quiet.Series[i].Slot != series.Slot {
			t.Errorf("%s moved from slot %d to %d between two windows", series.Label,
				series.Slot, quiet.Series[i].Slot)
		}
	}
}

func TestBuildEnrollmentsIgnoresWhatItCannotPlot(t *testing.T) {
	start := EnrollmentWindowStart(time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	chart := BuildEnrollments(start, testMethods, []EnrollmentCount{
		{Day: day(start, -1), Profile: "scep", Count: 4},
		{Day: day(start, EnrollmentWindowDays), Profile: "scep", Count: 4},
		{Day: day(start, 2), Profile: "infrastructure", Count: 9},
		{Day: day(start, 2), Profile: "scep", Count: 1},
	})
	if chart.Total != 1 {
		t.Errorf("total is %d, want only the one row inside the window with a known profile", chart.Total)
	}
}

// The axis has to land on whole certificates: a gridline at 3.75 is unreadable,
// and one below the busiest day would clip the line off the top of the plot.
func TestEnrollmentAxisRoundsToWholeCertificates(t *testing.T) {
	for _, tc := range []struct{ peak, max, step int }{
		{0, 4, 1}, {1, 4, 1}, {4, 4, 1}, {5, 5, 1}, {6, 6, 2}, {9, 10, 2},
		{17, 20, 5}, {41, 50, 10}, {201, 250, 50},
	} {
		max, step := enrollmentAxis(tc.peak)
		if max != tc.max || step != tc.step {
			t.Errorf("peak %d gives max %d step %d, want %d and %d", tc.peak, max, step, tc.max, tc.step)
		}
		if max < tc.peak {
			t.Errorf("peak %d has an axis topping out at %d, which clips the line", tc.peak, max)
		}
		if max%step != 0 || max/step > 5 {
			t.Errorf("peak %d gives max %d step %d, which is not a readable set of ticks", tc.peak, max, step)
		}
	}
}

func TestEnrollmentPlotCarriesEveryLineAndItsNumbers(t *testing.T) {
	start := EnrollmentWindowStart(time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	rows := make([]EnrollmentCount, 0, len(testMethods))
	for i, method := range testMethods {
		rows = append(rows, EnrollmentCount{Day: day(start, i*3), Profile: method.Profile, Count: i + 1})
	}
	html := render(t, Enrollments(BuildEnrollments(start, testMethods, rows)))
	for slot := 1; slot <= 6; slot++ {
		for _, prefix := range []string{"stroke-chart-", "fill-chart-", "bg-chart-"} {
			if !strings.Contains(html, prefix+itoa(slot)) {
				t.Errorf("no %s%d anywhere: a series has no colour", prefix, slot)
			}
		}
	}
	for _, method := range testMethods {
		if !strings.Contains(html, `data-chart-series="`+method.Profile+`"`) {
			t.Errorf("%s has no line", method.Label)
		}
		if !strings.Contains(html, `data-chart-dot="`+method.Profile+`"`) {
			t.Errorf("%s has no hover dot for chart.js to move", method.Label)
		}
		if !strings.Contains(html, `data-chart-tooltip-row="`+method.Profile+`"`) {
			t.Errorf("%s has no tooltip row", method.Label)
		}
	}
	// The tooltip enhances and never gates: the same figures are on the page
	// without it, in the legend and the table.
	if !strings.Contains(html, "Show the daily figures") || !strings.Contains(html, "Aug 29 2026") {
		t.Error("the table view is missing, so the daily figures are hover-only")
	}
	if !strings.Contains(html, "21 certificates issued Jul 31 – Aug 29") {
		t.Error("the card does not say what it is counting or over what span")
	}
	// The geometry chart.js reads has to be the geometry the points were
	// plotted against, not a second copy written out by hand.
	for _, want := range []string{`data-plot-left="46"`, `data-plot-right="748"`,
		`data-plot-top="14"`, `data-plot-bottom="240"`, `data-max="6"`} {
		if !strings.Contains(html, want) {
			t.Errorf("the figure is missing %s", want)
		}
	}
}

// A month with nothing in it is a different page from a graph of zeroes: six
// flat lines lying on the baseline read as broken.
func TestEnrollmentsEmptyWindowDrawsNoLines(t *testing.T) {
	start := EnrollmentWindowStart(time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	html := render(t, Enrollments(BuildEnrollments(start, testMethods, nil)))
	if strings.Contains(html, "data-chart-series") {
		t.Error("lines were drawn for a window with no enrollments")
	}
	if !strings.Contains(html, "Nothing issued Jul 31 – Aug 29") {
		t.Error("an empty window says nothing about why the graph is missing")
	}
	// The header would otherwise say "0 certificates issued …" immediately
	// above an empty state saying the same thing.
	if strings.Contains(html, "0 certificates issued") {
		t.Error("the empty window is announced twice")
	}
}

// The legend names all six whatever happened, so a method nobody used reads as
// unused rather than as a method that does not exist.
func TestEnrollmentLegendNamesEveryMethod(t *testing.T) {
	start := EnrollmentWindowStart(time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	html := render(t, Enrollments(BuildEnrollments(start, testMethods, []EnrollmentCount{
		{Day: day(start, 4), Profile: "scep", Count: 2},
	})))
	for _, method := range testMethods {
		if !strings.Contains(html, ">"+method.Label+"<") {
			t.Errorf("%s is missing from the legend", method.Label)
		}
	}
	if strings.Contains(html, `data-chart-series="acme"`) {
		t.Error("a method with no enrollments was given a flat line along the axis")
	}
}
