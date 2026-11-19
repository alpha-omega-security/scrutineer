package web

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const maxPageObservations = 20

var observationEvidenceOrder = []string{
	"locations", "sinks", "trace", "boundary", "validation", "reach",
	"affected", "quality_tier", "prior_art", "dup_check",
}

type observationEvidenceField struct {
	Name  string
	Value string
}

// findingObservationView is one observation prepared for the finding page.
// Evidence is the decoded, ordered field list; text is rendered through
// html/template escaping only.
type findingObservationView struct {
	db.FindingObservation
	Evidence []observationEvidenceField
}

type findingObservationsView struct {
	Rows  []findingObservationView
	Total int64
	// Disagreements names the fields on which observations differ.
	Disagreements []string
}

func loadFindingObservationViews(gdb *gorm.DB, findingID uint) (*findingObservationsView, error) {
	ids, err := db.ContributionFindingIDs(gdb, findingID)
	if err != nil {
		return nil, err
	}
	rows, total, err := db.ObservationsForFindings(gdb, ids, maxPageObservations)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	// The page shows only the newest rows; compare every contribution so an
	// older disagreement is not hidden by the cap.
	var compared []db.FindingObservation
	if err := gdb.Model(&db.FindingObservation{}).Select("severity", "reachability", "rating").
		Where("finding_id IN ?", ids).Find(&compared).Error; err != nil {
		return nil, err
	}
	out := &findingObservationsView{Total: total, Disagreements: observationDisagreements(compared)}
	for _, row := range rows {
		v := findingObservationView{FindingObservation: row}
		var raw map[string]string
		if json.Unmarshal([]byte(row.Evidence), &raw) == nil {
			for _, k := range observationEvidenceOrder {
				if raw[k] != "" {
					v.Evidence = append(v.Evidence, observationEvidenceField{Name: k, Value: raw[k]})
				}
			}
		}
		out.Rows = append(out.Rows, v)
	}
	return out, nil
}

// observationDisagreements lists the compared fields (severity, reachability
// and rating) whose non-empty values differ between observations. Agreement
// is deliberately not reported: two scans agreeing is not verification.
func observationDisagreements(rows []db.FindingObservation) []string {
	var out []string
	for _, f := range []struct {
		name string
		get  func(db.FindingObservation) string
	}{
		{"severity", func(o db.FindingObservation) string { return strings.ToLower(strings.TrimSpace(o.Severity)) }},
		{"reachability", func(o db.FindingObservation) string { return strings.TrimSpace(o.Reachability) }},
		{"rating", func(o db.FindingObservation) string { return strings.TrimSpace(o.Rating) }},
	} {
		var seen []string
		for _, o := range rows {
			if v := f.get(o); v != "" && !slices.Contains(seen, v) {
				seen = append(seen, v)
			}
		}
		if len(seen) > 1 {
			out = append(out, f.name)
		}
	}
	return out
}

// findingObservationJSON is the API shape of one observation.
type findingObservationJSON struct {
	ID              uint      `json:"id"`
	FindingID       uint      `json:"finding_id"`
	ScanID          uint      `json:"scan_id"`
	RepositoryID    uint      `json:"repository_id"`
	SkillName       string    `json:"skill_name"`
	Backend         string    `json:"backend"`
	Model           string    `json:"model"`
	Commit          string    `json:"commit"`
	ReportFindingID string    `json:"report_finding_id"`
	Fingerprint     string    `json:"fingerprint"`
	Title           string    `json:"title"`
	Severity        string    `json:"severity"`
	Confidence      string    `json:"confidence"`
	CWE             string    `json:"cwe"`
	Location        string    `json:"location"`
	Reachability    string    `json:"reachability"`
	Rule            string    `json:"rule,omitempty"`
	Anchor          string    `json:"anchor,omitempty"`
	Instance        string    `json:"instance,omitempty"`
	Rating          string    `json:"rating"`
	Evidence        any       `json:"evidence"`
	CreatedAt       time.Time `json:"created_at"`
}

func findingObservationResponse(o *db.FindingObservation) findingObservationJSON {
	var evidence any
	if o.Evidence != "" {
		_ = json.Unmarshal([]byte(o.Evidence), &evidence)
	}
	return findingObservationJSON{
		ID: o.ID, FindingID: o.FindingID, ScanID: o.ScanID, RepositoryID: o.RepositoryID,
		SkillName: o.SkillName, Backend: o.Backend, Model: o.Model, Commit: o.Commit,
		ReportFindingID: o.ReportFindingID, Fingerprint: o.Fingerprint, Title: o.Title,
		Severity: o.Severity, Confidence: o.Confidence, CWE: o.CWE, Location: o.Location,
		Reachability: o.Reachability, Rule: o.Rule, Anchor: o.Anchor, Instance: o.Instance, Rating: o.Rating, Evidence: evidence, CreatedAt: o.CreatedAt,
	}
}

func (s *Server) findingObservations(findingID uint) *findingObservationsView {
	v, err := loadFindingObservationViews(s.DB, findingID)
	if err != nil {
		s.Log.Warn("load finding observations", "finding", findingID, "err", err)
	}
	return v
}

// apiListFindingObservations returns every scan's report of the finding plus
// those of findings merged into it as duplicates, oldest first.
func (s *Server) apiListFindingObservations(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	rows, _, err := db.FindingContributions(s.DB.WithContext(r.Context()), id, 0)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "load observations")
		return
	}
	out := make([]findingObservationJSON, 0, len(rows))
	for i := range rows {
		out = append(out, findingObservationResponse(&rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}
