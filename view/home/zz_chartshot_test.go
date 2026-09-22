package home

import (
	"math"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"
)

func TestZZChartShot(t *testing.T) {
	if os.Getenv("SHOT_OUT") == "" {
		t.Skip("shot only")
	}
	start := EnrollmentWindowStart(time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	rng := rand.New(rand.NewSource(7))
	shape := map[string]func(int) float64{
		"csr":    func(d int) float64 { return 1.5 },
		"server": func(d int) float64 { return 2 },
		"client": func(d int) float64 { return 3 },
		"scep":   func(d int) float64 { return 14 + 9*math.Sin(float64(d)/4) },
		"acme":   func(d int) float64 { return 6 + float64(d)/4 },
		"est":    func(d int) float64 { return 4 },
	}
	var rows []EnrollmentCount
	for _, m := range testMethods {
		for d := 0; d < EnrollmentWindowDays; d++ {
			n := int(shape[m.Profile](d)) + rng.Intn(3) - 1
			if n <= 0 {
				continue
			}
			rows = append(rows, EnrollmentCount{Day: day(start, d), Profile: m.Profile, Count: n})
		}
	}
	data := OverviewData{
		IssuingCAs: 2, Identities: 412,
		EnabledEndpoints: 4, ExpiringSoon: 7,
		HasIssuingCA: true, HasProtocol: true, HasCertificate: true, HasTeam: true,
		Protocols:   []string{"SCEP", "ACME", "EST"},
		Enrollments: BuildEnrollments(start, testMethods, rows),
	}
	html := render(t, Index(testSession(), data))
	html = strings.Replace(html, `href="/static/app.css?v=20260829-1"`, `href="/static/app.css"`, 1)
	os.WriteFile(os.Getenv("SHOT_OUT"), []byte(html), 0o644)
}
