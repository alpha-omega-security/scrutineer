package db

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// WriteFindingField updates a Finding column and records the change in
// FindingHistory. Callers pass the JSON-style field name (severity,
// cvss_vector, status, resolution, ...); unknown fields are rejected so
// typos don't silently vanish.
//
// No-op when the new value equals the current stored value; the history
// row is only written on an actual change.
func WriteFindingField(gdb *gorm.DB, findingID uint, field, newValue string, source FindingSource, by string) error {
	var f Finding
	if err := gdb.First(&f, findingID).Error; err != nil {
		return fmt.Errorf("load finding %d: %w", findingID, err)
	}
	old, colName, err := findingFieldAccessor(&f, field)
	if err != nil {
		return err
	}
	if old == newValue {
		return nil
	}
	if err := gdb.Model(&Finding{}).Where("id = ?", f.ID).Update(colName, newValue).Error; err != nil {
		return fmt.Errorf("update %s: %w", colName, err)
	}
	if err := gdb.Create(&FindingHistory{
		FindingID: f.ID,
		Field:     field,
		OldValue:  old,
		NewValue:  newValue,
		Source:    source,
		By:        by,
		CreatedAt: time.Now(),
	}).Error; err != nil {
		return err
	}
	if field == "cvss_vector" {
		return syncCVSSScore(gdb, &f, newValue, source, by)
	}
	return nil
}

// syncCVSSScore keeps cvss_score in lock-step with cvss_vector. The
// vector is the canonical input (analyst form, disclose skill), the
// score is a pure function of it — anything else drifts. An empty or
// unparseable vector clears the score so stale numbers don't linger.
func syncCVSSScore(gdb *gorm.DB, f *Finding, vector string, source FindingSource, by string) error {
	score, _ := BaseScoreFromVector(vector)
	if f.CVSSScore == score {
		return nil
	}
	if err := gdb.Model(&Finding{}).Where("id = ?", f.ID).Update("cvss_score", score).Error; err != nil {
		return fmt.Errorf("update cvss_score: %w", err)
	}
	return gdb.Create(&FindingHistory{
		FindingID: f.ID,
		Field:     "cvss_score",
		OldValue:  strconv.FormatFloat(f.CVSSScore, 'f', -1, 64),
		NewValue:  strconv.FormatFloat(score, 'f', -1, 64),
		Source:    source,
		By:        by,
		CreatedAt: time.Now(),
	}).Error
}

// confidenceLevels and SeverityLevels are ordered low to high; the
// index is the rank used for threshold comparisons. An empty or
// unknown value ranks below everything. SeverityLevels is exported so
// the web layer can derive its ORDER BY CASE clause from the same
// list rather than hard-coding the four labels twice.
var confidenceLevels = []string{"low", "medium", "high"}
var SeverityLevels = []string{"Low", "Medium", "High", "Critical"}

func rank(levels []string, v string) int {
	for i, l := range levels {
		if l == v {
			return i + 1
		}
	}
	return 0
}

// ConfidenceAtLeast reports whether got ranks at or above min on the
// low/medium/high scale. A finding without a confidence value is
// dropped when a min_confidence is set; an empty min disables the
// check.
func ConfidenceAtLeast(got, minimum string) bool {
	if minimum == "" {
		return true
	}
	return rank(confidenceLevels, got) >= rank(confidenceLevels, minimum)
}

// SeverityAtLeast reports whether got ranks at or above the threshold
// on the Low/Medium/High/Critical scale. An empty threshold never
// matches.
func SeverityAtLeast(got, threshold string) bool {
	if threshold == "" {
		return false
	}
	return rank(SeverityLevels, got) >= rank(SeverityLevels, threshold)
}

// findingFieldAccessor maps the API-facing field name to the current
// value and the DB column name. It is the single list of mutable fields;
// adding a new editable field means adding it here.
func findingFieldAccessor(f *Finding, field string) (current, column string, err error) {
	switch field {
	case "title":
		return f.Title, "title", nil
	case "severity":
		return f.Severity, "severity", nil
	case "status":
		return string(f.Status), "status", nil
	case "cwe":
		return f.CWE, "cwe", nil
	case "location":
		return f.Location, "location", nil
	case "affected":
		return f.Affected, "affected", nil
	case "reachability":
		return f.Reachability, "reachability", nil
	case "quality_tier":
		return f.QualityTier, "quality_tier", nil
	case "cve_id":
		return f.CVEID, "cve_id", nil
	case "cvss_vector":
		return f.CVSSVector, "cvss_vector", nil
	case "fix_version":
		return f.FixVersion, "fix_version", nil
	case "fix_commit":
		return f.FixCommit, "fix_commit", nil
	case "resolution":
		return string(f.Resolution), "resolution", nil
	case "disclosure_draft":
		return f.DisclosureDraft, "disclosure_draft", nil
	case "assignee":
		return f.Assignee, "assignee", nil
	case "suggested_fix":
		return f.SuggestedFix, "suggested_fix", nil
	case "suggested_fix_commit":
		return f.SuggestedFixCommit, "suggested_fix_commit", nil
	case "breaking_change":
		return f.BreakingChange, "breaking_change", nil
	case "breaking_change_rationale":
		return f.BreakingChangeRationale, "breaking_change_rationale", nil
	case "exploited_in_wild":
		return f.ExploitedInWild, "exploited_in_wild", nil
	case "exploited_in_wild_evidence":
		return f.ExploitedInWildEvidence, "exploited_in_wild_evidence", nil
	default:
		return "", "", fmt.Errorf("field %q is not editable", field)
	}
}

// AddFindingNote appends a timestamped note.
func AddFindingNote(gdb *gorm.DB, findingID uint, body, by string) (*FindingNote, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil, fmt.Errorf("note body is empty")
	}
	n := &FindingNote{FindingID: findingID, Body: body, By: by, CreatedAt: time.Now()}
	if err := gdb.Create(n).Error; err != nil {
		return nil, err
	}
	return n, nil
}

// AddFindingCommunication records one external interaction.
func AddFindingCommunication(gdb *gorm.DB, findingID uint, channel, direction, actor, body, offeredHelp string, at time.Time) (*FindingCommunication, error) {
	if at.IsZero() {
		at = time.Now()
	}
	c := &FindingCommunication{
		FindingID:   findingID,
		Channel:     channel,
		Direction:   direction,
		Actor:       actor,
		Body:        body,
		OfferedHelp: offeredHelp,
		At:          at,
		CreatedAt:   time.Now(),
	}
	if err := gdb.Create(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

// AddFindingReference records an external URL related to the finding.
func AddFindingReference(gdb *gorm.DB, findingID uint, url, tags, summary string) (*FindingReference, error) {
	if strings.TrimSpace(url) == "" {
		return nil, fmt.Errorf("reference url is empty")
	}
	r := &FindingReference{
		FindingID: findingID,
		URL:       url,
		Tags:      tags,
		Summary:   summary,
		CreatedAt: time.Now(),
	}
	if err := gdb.Create(r).Error; err != nil {
		return nil, err
	}
	return r, nil
}

// SetFindingLabels replaces a finding's label set with the given names.
// Labels not already in the DB are created with a default (no color).
// Empty slice clears all labels.
func SetFindingLabels(gdb *gorm.DB, findingID uint, names []string) error {
	var f Finding
	if err := gdb.First(&f, findingID).Error; err != nil {
		return err
	}
	labels := make([]FindingLabel, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		var l FindingLabel
		if err := gdb.Where(FindingLabel{Name: name}).FirstOrCreate(&l).Error; err != nil {
			return err
		}
		labels = append(labels, l)
	}
	return gdb.Model(&f).Association("Labels").Replace(labels)
}

// SeedDefaultLabels ensures a baseline set of labels exists on startup.
// Calling again is idempotent; existing rows are left alone so users can
// re-colour them without having their edits overwritten.
func SeedDefaultLabels(gdb *gorm.DB) error {
	defaults := []FindingLabel{
		{Name: "wontfix", Color: "#6b7280"},
		{Name: "in-progress", Color: "#2563eb"},
		{Name: "needs-info", Color: "#f59e0b"},
		{Name: "duplicate", Color: "#9333ea"},
		{Name: "regression", Color: "#dc2626"},
	}
	for _, l := range defaults {
		var existing FindingLabel
		if err := gdb.Where(FindingLabel{Name: l.Name}).FirstOrCreate(&existing, l).Error; err != nil {
			return err
		}
	}
	return nil
}
