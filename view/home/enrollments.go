package home

import (
	"strconv"
	"strings"
	"time"
)

// EnrollmentWindowDays is how far back the enrollment graph looks, counting
// today. Thirty days to agree with the "Expiring < 30d" metric directly above
// it on the same page: two windows of different lengths sitting side by side is
// how a reader ends up comparing figures that were never comparable.
const EnrollmentWindowDays = 30

// EnrollmentMethod names one line on the graph: a certificate profile and how
// it is spoken about.
//
// The roster lives in internal/home rather than here, because the profiles are
// pki's constants and view/home cannot import pki — pki renders one of this
// package's pages. What this package owns is the consequence of the roster's
// order, which is the whole point of it being a fixed list: position n in the
// slice is colour slot n, tied to the method and never to its rank, so a quiet
// month never repaints the lines. A reader who learned that SCEP is the yellow
// one keeps that.
type EnrollmentMethod struct {
	Profile string
	Label   string
	// Detail says where the certificates came from, for the table view's
	// header. The legend has no room for it and the tooltip has to stay a
	// readout rather than a lesson.
	Detail string
}

// EnrollmentCount is one day's issuance for one method, as the handler read it
// out of the database: sparse, with no row at all for a method that issued
// nothing that day.
type EnrollmentCount struct {
	Day     time.Time
	Profile string
	Count   int
}

// EnrollmentSeries is one method's line: a count for every day in the window,
// zeroes included, so every series is the same length as EnrollmentChart.Days
// and index i means the same day in all of them.
type EnrollmentSeries struct {
	Profile string
	Label   string
	Detail  string
	// Slot is 1..6 and picks the colour. It is the method's position in
	// enrollmentMethods, never its rank in this particular window.
	Slot   int
	Counts []int
	Total  int
}

// EnrollmentChart is everything the graph draws. It is built once per request
// from the day/method rows the database returns, which are sparse — a method
// that issued nothing on a given day produces no row — onto a dense axis, so
// the drawing code never has to ask whether a day exists.
type EnrollmentChart struct {
	// Days is one entry per x position, oldest first, each at midnight UTC.
	Days   []time.Time
	Series []EnrollmentSeries
	// Total is every certificate in the window, across all six methods.
	Total int
	// Max is the top of the y axis and Step the interval between its ticks.
	// Max is always a whole number of steps, so the gridlines land on whole
	// certificates and the last one is the top of the plot.
	Max, Step int
}

// EnrollmentWindowStart is the first midnight the graph covers.
//
// UTC because every timestamp in this schema is a bare `timestamp without time
// zone` written and compared in UTC — internal/database.AssertUTC refuses to
// start otherwise — so a window computed in any other zone would cut the day
// somewhere the data does not.
func EnrollmentWindowStart(now time.Time) time.Time {
	return now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -(EnrollmentWindowDays - 1))
}

// BuildEnrollments lays the sparse per-day rows onto the full window, so the
// drawing code never has to ask whether a day exists.
//
// Rows outside the window are ignored rather than trusted to be absent, and a
// profile the roster does not know — one added to the schema and not to the
// method list — is dropped rather than silently folded into another method's
// line.
func BuildEnrollments(start time.Time, methods []EnrollmentMethod, rows []EnrollmentCount) EnrollmentChart {
	chart := EnrollmentChart{Days: make([]time.Time, EnrollmentWindowDays)}
	for i := range chart.Days {
		chart.Days[i] = start.AddDate(0, 0, i)
	}
	index := make(map[string]int, len(methods))
	for slot, method := range methods {
		index[method.Profile] = slot
		chart.Series = append(chart.Series, EnrollmentSeries{
			Profile: method.Profile, Label: method.Label, Detail: method.Detail,
			Slot: slot + 1, Counts: make([]int, EnrollmentWindowDays),
		})
	}
	for _, row := range rows {
		slot, known := index[row.Profile]
		if !known {
			continue
		}
		day := int(row.Day.UTC().Truncate(24*time.Hour).Sub(start) / (24 * time.Hour))
		if day < 0 || day >= EnrollmentWindowDays {
			continue
		}
		chart.Series[slot].Counts[day] += row.Count
		chart.Series[slot].Total += row.Count
		chart.Total += row.Count
	}
	peak := 0
	for _, series := range chart.Series {
		for _, count := range series.Counts {
			if count > peak {
				peak = count
			}
		}
	}
	chart.Max, chart.Step = enrollmentAxis(peak)
	return chart
}

// enrollmentAxis picks the y axis: the smallest round step that gets the
// busiest day inside five intervals, and the first multiple of it at or above
// that day.
//
// Round means 1, 2 or 5 times a power of ten, which is what makes a gridline
// readable — an axis that divides a peak of 41 into ticks of 8.2 carries
// numbers nobody can hold in their head, and one that stops at 40 clips the
// line off the top of the plot. Four is the floor for the top of the axis, so a
// quiet month is a low line across an ordinary-looking graph rather than one
// certificate drawn as a full-height spike.
func enrollmentAxis(peak int) (max, step int) {
	if peak <= 4 {
		return 4, 1
	}
	for step = 1; ; step *= 10 {
		for _, candidate := range []int{step, step * 2, step * 5} {
			if intervals := (peak + candidate - 1) / candidate; intervals <= 5 {
				return intervals * candidate, candidate
			}
		}
	}
}

// The drawing surface, in the SVG's own user units. The viewBox is fixed and
// the element scales to its column, so these are the only coordinates anything
// here has to reason about — and the height includes the band the date labels
// sit in, rather than ending at the plot and letting the labels fall out of the
// box.
const (
	enrollmentViewWidth  = 760
	enrollmentViewHeight = 272
	enrollmentPlotLeft   = 46
	enrollmentPlotRight  = 748
	enrollmentPlotTop    = 14
	enrollmentPlotBottom = 240
	enrollmentDateLabelY = 262
)

// HasData reports whether anything was enrolled in the window. Nothing to draw
// is a different page from a graph of zeroes: six lines lying on top of each
// other along the baseline says "broken", not "quiet month".
func (c EnrollmentChart) HasData() bool { return c.Total > 0 }

// Drawn returns the series that actually have a line — the ones with at least
// one enrollment. A method that issued nothing contributes a flat line along
// the axis, and six of those stacked on the baseline is a smear that hides the
// series that do have data. The legend still lists all six, so a method absent
// from the plot is reported rather than disappeared.
func (c EnrollmentChart) Drawn() []EnrollmentSeries {
	drawn := make([]EnrollmentSeries, 0, len(c.Series))
	for _, series := range c.Series {
		if series.Total > 0 {
			drawn = append(drawn, series)
		}
	}
	return drawn
}

func (c EnrollmentChart) x(i int) float64 {
	if len(c.Days) < 2 {
		return enrollmentPlotLeft
	}
	span := float64(enrollmentPlotRight - enrollmentPlotLeft)
	return enrollmentPlotLeft + span*float64(i)/float64(len(c.Days)-1)
}

func (c EnrollmentChart) y(value int) float64 {
	if c.Max <= 0 {
		return enrollmentPlotBottom
	}
	span := float64(enrollmentPlotBottom - enrollmentPlotTop)
	return enrollmentPlotBottom - span*float64(value)/float64(c.Max)
}

// Points is one series as a polyline, at one decimal place — enough to place a
// point inside a pixel once the SVG is scaled to its column, and short enough
// that thirty of them stay readable in the source.
func (c EnrollmentChart) Points(series EnrollmentSeries) string {
	var b strings.Builder
	for i, count := range series.Counts {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(coord(c.x(i)))
		b.WriteByte(',')
		b.WriteString(coord(c.y(count)))
	}
	return b.String()
}

// EnrollmentTick is one horizontal gridline and the value it stands for.
type EnrollmentTick struct {
	Label string
	Y     string
}

// Ticks are the y gridlines, top down, so the SVG draws them in the order they
// appear. There are between four and six of them, whichever divides this
// window's busiest day most cleanly.
func (c EnrollmentChart) Ticks() []EnrollmentTick {
	ticks := make([]EnrollmentTick, 0, 6)
	for value := c.Max; value >= 0; value -= c.Step {
		ticks = append(ticks, EnrollmentTick{Label: strconv.Itoa(value), Y: coord(c.y(value))})
	}
	return ticks
}

// EnrollmentDateTick is one date label under the plot.
type EnrollmentDateTick struct {
	Label string
	X     string
	// Anchor keeps the first and last labels inside the drawing rather than
	// hanging off its edges, where the card's padding would clip them.
	Anchor string
}

// DateTicks labels roughly every sixth day. Every day would be an unreadable
// picket fence at this width, and the tooltip carries the exact date for any
// point the reader actually cares about.
func (c EnrollmentChart) DateTicks() []EnrollmentDateTick {
	if len(c.Days) == 0 {
		return nil
	}
	last := len(c.Days) - 1
	stride := 6
	ticks := make([]EnrollmentDateTick, 0, len(c.Days)/stride+1)
	for i := 0; i <= last; i += stride {
		// The final label is pinned to the last day rather than wherever the
		// stride lands, so the axis says where the window actually ends.
		if last-i < stride {
			i = last
		}
		anchor := "middle"
		switch i {
		case 0:
			anchor = "start"
		case last:
			anchor = "end"
		}
		ticks = append(ticks, EnrollmentDateTick{
			Label: c.Days[i].Format("Jan 2"), X: coord(c.x(i)), Anchor: anchor,
		})
		if i == last {
			break
		}
	}
	return ticks
}

// DayLabels is the full date of every point, in order, for the tooltip to read.
// The graph labels six days; the tooltip has to name all thirty.
func (c EnrollmentChart) DayLabels() string {
	labels := make([]string, len(c.Days))
	for i, day := range c.Days {
		labels[i] = day.Format("Mon, Jan 2")
	}
	return strings.Join(labels, "|")
}

// Counts is one series' values as the plain list chart.js reads back off the
// polyline. It is the same data the line was drawn from, in the same order.
func (c EnrollmentChart) Counts(series EnrollmentSeries) string {
	values := make([]string, len(series.Counts))
	for i, count := range series.Counts {
		values[i] = strconv.Itoa(count)
	}
	return strings.Join(values, ",")
}

// RangeLabel says what span the graph covers, for the card's description.
func (c EnrollmentChart) RangeLabel() string {
	if len(c.Days) == 0 {
		return ""
	}
	return c.Days[0].Format("Jan 2") + " – " + c.Days[len(c.Days)-1].Format("Jan 2")
}

// TotalLabel is the headline figure, worded so a count of one is not "1
// certificates".
func (c EnrollmentChart) TotalLabel() string {
	if c.Total == 1 {
		return "1 certificate"
	}
	return strconv.Itoa(c.Total) + " certificates"
}

// Rows is the table view: one row per day, one column per method, oldest last
// so the most recent day is the one already on screen.
func (c EnrollmentChart) Rows() []EnrollmentRow {
	rows := make([]EnrollmentRow, 0, len(c.Days))
	for i := len(c.Days) - 1; i >= 0; i-- {
		row := EnrollmentRow{Day: c.Days[i].Format("Mon, Jan 2 2006")}
		for _, series := range c.Series {
			row.Counts = append(row.Counts, strconv.Itoa(series.Counts[i]))
			row.Total += series.Counts[i]
		}
		rows = append(rows, row)
	}
	return rows
}

// EnrollmentRow is one day of the table view.
type EnrollmentRow struct {
	Day    string
	Counts []string
	Total  int
}

func coord(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func itoa(v int) string { return strconv.Itoa(v) }

// The plot rectangle as attribute strings, so the gridlines, the crosshair and
// chart.js all read the same numbers the coordinates were computed from rather
// than a second set written out by hand in the template.
func (c EnrollmentChart) ViewBox() string {
	return "0 0 " + itoa(enrollmentViewWidth) + " " + itoa(enrollmentViewHeight)
}
func (c EnrollmentChart) PlotLeft() string   { return itoa(enrollmentPlotLeft) }
func (c EnrollmentChart) PlotRight() string  { return itoa(enrollmentPlotRight) }
func (c EnrollmentChart) PlotTop() string    { return itoa(enrollmentPlotTop) }
func (c EnrollmentChart) PlotBottom() string { return itoa(enrollmentPlotBottom) }
func (c EnrollmentChart) DateLabelY() string { return itoa(enrollmentDateLabelY) }

// TickLabelX is where the y-axis numbers sit: clear of the plot, right-aligned
// against it.
func (c EnrollmentChart) TickLabelX() string { return itoa(enrollmentPlotLeft - 8) }

// MaxLabel is the top of the y axis, for chart.js to scale its hover dots by.
func (c EnrollmentChart) MaxLabel() string { return itoa(c.Max) }
