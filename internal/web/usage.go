package web

import (
	"net/http"
	"sort"

	"scrutineer/internal/db"
)

// SkillUsage is one row of the /usage page: aggregate cost and turn
// statistics for every completed scan of a given skill across the
// corpus. Percentiles are computed in Go because sqlite has no
// percentile_cont; with low-thousands of scans the sort is trivial.
type SkillUsage struct {
	Skill     string
	Runs      int
	Cost      Stats
	Turns     Stats
	TokensIn  int
	TokensOut int
}

type Stats struct {
	Min    float64
	Median float64
	P90    float64
	Max    float64
	Sum    float64
}

func (s *Server) usage(w http.ResponseWriter, r *http.Request) {
	// Only completed runs contribute to the distribution; queued/running
	// rows have zero cost and would drag the floor down, and failed runs
	// did still spend tokens so they stay in.
	var scans []db.Scan
	s.DB.Select("skill_name", "cost_usd", "turns",
		"input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens").
		Where("status IN ?", []db.ScanStatus{db.ScanDone, db.ScanFailed}).
		Where("skill_name != ''").
		Find(&scans)

	costBy := map[string][]float64{}
	turnsBy := map[string][]float64{}
	inBy := map[string]int{}
	outBy := map[string]int{}
	for _, sc := range scans {
		costBy[sc.SkillName] = append(costBy[sc.SkillName], sc.CostUSD)
		turnsBy[sc.SkillName] = append(turnsBy[sc.SkillName], float64(sc.Turns))
		inBy[sc.SkillName] += sc.TotalInputTokens()
		outBy[sc.SkillName] += sc.OutputTokens
	}

	rows := make([]SkillUsage, 0, len(costBy))
	var totalCost float64
	var totalRuns int
	for name, costs := range costBy {
		c := summarise(costs)
		rows = append(rows, SkillUsage{
			Skill:     name,
			Runs:      len(costs),
			Cost:      c,
			Turns:     summarise(turnsBy[name]),
			TokensIn:  inBy[name],
			TokensOut: outBy[name],
		})
		totalCost += c.Sum
		totalRuns += len(costs)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Cost.Sum > rows[j].Cost.Sum })

	s.render(w, r, "usage.html", map[string]any{
		"Rows":      rows,
		"TotalCost": totalCost,
		"TotalRuns": totalRuns,
	})
}

const (
	pMedian = 0.5
	p90     = 0.9
)

func summarise(xs []float64) Stats {
	if len(xs) == 0 {
		return Stats{}
	}
	sort.Float64s(xs)
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return Stats{
		Min:    xs[0],
		Median: percentile(xs, pMedian),
		P90:    percentile(xs, p90),
		Max:    xs[len(xs)-1],
		Sum:    sum,
	}
}

// percentile returns the p-th percentile (0..1) of a sorted slice using
// linear interpolation between the two nearest ranks (the same method
// numpy uses by default), so p50 of an even-length set is the midpoint.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := p * float64(len(sorted)-1)
	lo := int(pos)
	frac := pos - float64(lo)
	if lo+1 >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	return sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
}
