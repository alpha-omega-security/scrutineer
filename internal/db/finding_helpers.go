package db

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/git-pkgs/vulns"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// GHSAIDPattern matches a GitHub Security Advisory id: the GHSA prefix
// followed by three 4-character base32 groups, e.g. GHSA-jfh8-c2jp-5v3q.
// Case-insensitive. Exported as the unanchored body so the web layer can
// reuse it for FindString scanning of free text without the format
// drifting between packages; this package anchors it for input validation.
const GHSAIDPattern = `(?i)GHSA(-[0-9a-z]{4}){3}`

var ghsaIDRE = regexp.MustCompile("^" + GHSAIDPattern + "$")

const (
	findingWriteMaxAttempts = 5
	sqliteBusyCode          = 5
)

var errFindingWriteConflict = errors.New("finding changed concurrently")

// validateFindingField rejects values that must follow a fixed format
// before they reach the column. Most fields are free text and pass
// through untouched; an empty value is always allowed so a field can be
// cleared. Errors surface to the analyst (422 in the web/API layer).
func validateFindingField(field, value string) error {
	if value == "" {
		return nil
	}
	if field == "ghsa_id" && !ghsaIDRE.MatchString(value) {
		return fmt.Errorf("ghsa_id %q is not a valid GHSA id (expected GHSA-xxxx-xxxx-xxxx)", value)
	}
	return nil
}

// WriteFindingField updates a Finding column and records the change in
// FindingHistory. Callers pass the JSON-style field name (severity,
// cvss_vector, status, resolution, ...); unknown fields are rejected so
// typos don't silently vanish.
//
// No-op when the new value equals the current stored value; the history
// row is only written on an actual change.
func WriteFindingField(gdb *gorm.DB, findingID uint, field, newValue string, source FindingSource, by string) error {
	// The column update, its history row, and any dependent CVSS-score
	// sync must commit together: a failure between them would change the
	// stored value with no matching history row (breaking the audit
	// trail) or leave cvss_score inconsistent with cvss_vector.
	return retryFindingWrite(gdb, findingID, func(tx *gorm.DB) error {
		var f Finding
		if err := tx.First(&f, findingID).Error; err != nil {
			return fmt.Errorf("load finding %d: %w", findingID, err)
		}
		old, colName, err := findingFieldAccessor(&f, field)
		if err != nil {
			return err
		}
		if old == newValue {
			return nil
		}
		if err := validateFindingField(field, newValue); err != nil {
			return err
		}
		if err := conditionalFindingUpdate(tx, f.ID, colName, old, newValue); err != nil {
			return fmt.Errorf("update %s: %w", colName, err)
		}
		if err := tx.Create(&FindingHistory{
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
			return syncCVSSScore(tx, &f, newValue, source, by)
		}
		if field == "cvss_v4_vector" {
			return syncCVSSv4Score(tx, &f, newValue, source, by)
		}
		return nil
	})
}

// UpsertFindingDependent records the current exposure verdict for one
// finding/dependent pair. The pair has a database unique index, so using the
// same conflict target as that index makes concurrent writers update the row
// instead of racing between a lookup and insert.
func UpsertFindingDependent(gdb *gorm.DB, row FindingDependent) error {
	return gdb.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "finding_id"}, {Name: "dependent_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"status", "justification", "rationale", "scan_id", "scan_commit", "updated_at",
		}),
	}).Create(&row).Error
}

// EnsureFindingDependent creates a finding/dependent row when it is missing,
// but deliberately preserves any existing exposure verdict. Use this for
// placeholder rows that only make a dependent visible in the finding view.
func EnsureFindingDependent(gdb *gorm.DB, row FindingDependent) error {
	return gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "finding_id"}, {Name: "dependent_id"}},
		DoNothing: true,
	}).Create(&row).Error
}

// WriteFindingTimeField is the time.Time twin of WriteFindingField for
// timestamp columns the analyst (or a skill) can set. The closed set
// of writable timestamp columns lives in findingTimeFieldAccessor, so
// typos surface here rather than reach the DB. The new value is
// normalised to UTC before write and storage; the history row formats
// it as RFC3339 so it slots into the existing OldValue/NewValue text
// columns alongside the string-typed history rows.
//
// No-op when the new value equals the stored value (a re-run that
// reports the same release timestamp does not log a redundant history
// row).
func WriteFindingTimeField(gdb *gorm.DB, findingID uint, field string, newValue time.Time, source FindingSource, by string) error {
	newUTC := newValue.UTC()
	// Column update and history row must commit together so the audit
	// trail can't lose a row on a mid-write failure.
	return retryFindingWrite(gdb, findingID, func(tx *gorm.DB) error {
		var f Finding
		if err := tx.First(&f, findingID).Error; err != nil {
			return fmt.Errorf("load finding %d: %w", findingID, err)
		}
		old, colName, err := findingTimeFieldAccessor(&f, field)
		if err != nil {
			return err
		}
		if old != nil && old.Equal(newUTC) {
			return nil
		}
		oldStr := ""
		if old != nil {
			oldStr = old.UTC().Format(time.RFC3339)
		}
		if err := conditionalFindingUpdate(tx, f.ID, colName, old, newUTC); err != nil {
			return fmt.Errorf("update %s: %w", colName, err)
		}
		return tx.Create(&FindingHistory{
			FindingID: f.ID,
			Field:     field,
			OldValue:  oldStr,
			NewValue:  newUTC.Format(time.RFC3339),
			Source:    source,
			By:        by,
			CreatedAt: time.Now(),
		}).Error
	})
}

// retryFindingWrite owns and retries transactions created for raw database
// handles. A caller-owned transaction cannot be restarted here, so it gets
// one conditional attempt and returns any conflict to its caller for rollback.
func retryFindingWrite(gdb *gorm.DB, findingID uint, write func(*gorm.DB) error) error {
	if _, inTransaction := gdb.Statement.ConnPool.(gorm.TxCommitter); inTransaction {
		// Keep the helper atomic with a single GORM savepoint, but leave any
		// outer transaction retry to its owner because its earlier work and
		// read snapshot cannot be safely reconstructed here.
		return gdb.Transaction(write)
	}

	var err error
	for attempt := 1; attempt <= findingWriteMaxAttempts; attempt++ {
		err = gdb.Transaction(write)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errFindingWriteConflict) && !isSQLiteBusy(err) {
			return err
		}
		if attempt < findingWriteMaxAttempts {
			time.Sleep(time.Millisecond << (attempt - 1))
		}
	}
	return fmt.Errorf("write finding %d failed after %d attempts: %w", findingID, findingWriteMaxAttempts, err)
}

// conditionalFindingUpdate is the optimistic compare-and-swap shared by
// string, timestamp, and derived-score writes. clause.Eq renders nil as IS
// NULL, which is required for an unset ReleasedAt value.
func conditionalFindingUpdate(gdb *gorm.DB, findingID uint, column string, oldValue, newValue any) error {
	result := gdb.Model(&Finding{}).
		Where("id = ?", findingID).
		Where(clause.Eq{Column: clause.Column{Name: column}, Value: oldValue}).
		Update(column, newValue)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errFindingWriteConflict
	}
	return nil
}

// SQLite reports a stale WAL read transaction as SQLITE_BUSY_SNAPSHOT (an
// extended SQLITE_BUSY code) instead of returning zero rows from the compare-
// and-swap. The whole owned transaction must be restarted to get a new snapshot.
func isSQLiteBusy(err error) bool {
	var sqliteErr interface{ Code() int }
	return errors.As(err, &sqliteErr) && sqliteErr.Code()&0xff == sqliteBusyCode
}

// findingTimeFieldAccessor mirrors findingFieldAccessor for timestamp
// columns. Same closed-list pattern: adding a new editable timestamp
// means adding a case here.
func findingTimeFieldAccessor(f *Finding, field string) (current *time.Time, column string, err error) {
	switch field {
	case "released_at":
		return f.ReleasedAt, "released_at", nil
	default:
		return nil, "", fmt.Errorf("field %q is not an editable timestamp", field)
	}
}

// syncCVSSScore keeps cvss_score in lock-step with cvss_vector. The
// vector is the canonical input (analyst form, disclose skill), the
// score is a pure function of it — anything else drifts. An empty or
// unparseable vector clears the score so stale numbers don't linger.
func syncCVSSScore(gdb *gorm.DB, f *Finding, vector string, source FindingSource, by string) error {
	score, _ := CVSSV3ScoreFromVector(vector)
	if err := conditionalFindingUpdate(gdb, f.ID, "cvss_score", f.CVSSScore, score); err != nil {
		return fmt.Errorf("update cvss_score: %w", err)
	}
	if f.CVSSScore == score {
		return nil
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

// syncCVSSv4Score is the v4 twin of syncCVSSScore. CVSS v4 changes the
// metric set and the base-score formula, so it lives in its own
// vector/score columns rather than overloading the v3 ones.
func syncCVSSv4Score(gdb *gorm.DB, f *Finding, vector string, source FindingSource, by string) error {
	score, _ := CVSSV4ScoreFromVector(vector)
	if err := conditionalFindingUpdate(gdb, f.ID, "cvss_v4_score", f.CVSSv4Score, score); err != nil {
		return fmt.Errorf("update cvss_v4_score: %w", err)
	}
	if f.CVSSv4Score == score {
		return nil
	}
	return gdb.Create(&FindingHistory{
		FindingID: f.ID,
		Field:     "cvss_v4_score",
		OldValue:  strconv.FormatFloat(f.CVSSv4Score, 'f', -1, 64),
		NewValue:  strconv.FormatFloat(score, 'f', -1, 64),
		Source:    source,
		By:        by,
		CreatedAt: time.Now(),
	}).Error
}

// CVSSV3ScoreFromVector returns the CVSS v3.0/v3.1 base score for a vector,
// or (0, false) when the vector is empty, unparseable, or not a v3 vector.
// Exported so the import path can recompute a bundle's score from its carried
// vector rather than trusting a number that may have been hand-edited.
func CVSSV3ScoreFromVector(vector string) (float64, bool) {
	cvss, err := vulns.ParseCVSS(vector)
	if err != nil {
		return 0, false
	}
	switch cvss.Version {
	case "3.0", "3.1":
		return cvss.Score, true
	default:
		return 0, false
	}
}

// CVSSV4ScoreFromVector is the v4.0 twin of CVSSV3ScoreFromVector.
func CVSSV4ScoreFromVector(vector string) (float64, bool) {
	cvss, err := vulns.ParseCVSS(vector)
	if err != nil || cvss.Version != "4.0" {
		return 0, false
	}
	return cvss.Score, true
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
	case "ghsa_id":
		return f.GHSAID, "ghsa_id", nil
	case "cvss_vector":
		return f.CVSSVector, "cvss_vector", nil
	case "cvss_v4_vector":
		return f.CVSSv4Vector, "cvss_v4_vector", nil
	case "fix_version":
		return f.FixVersion, "fix_version", nil
	case "fix_commit":
		return f.FixCommit, "fix_commit", nil
	case "resolution":
		return string(f.Resolution), "resolution", nil
	case "disclosure_draft":
		return f.DisclosureDraft, "disclosure_draft", nil
	case "suggested_recipients":
		return f.SuggestedRecipients, "suggested_recipients", nil
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
	case "mitigation":
		return f.Mitigation, "mitigation", nil
	case "mitigation_semgrep":
		return f.MitigationSemgrep, "mitigation_semgrep", nil
	case "release_tag":
		return f.ReleaseTag, "release_tag", nil
	case "release_url":
		return f.ReleaseURL, "release_url", nil
	case "last_revalidate_verdict":
		return f.LastRevalidateVerdict, "last_revalidate_verdict", nil
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
