package db

import (
	"encoding/json"
	"slices"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	maxContributionFindings = 64
	observationBatchSize    = 100
)

// FindingObservation is one immutable record of a scan reporting a finding.
// Its text and Evidence are untrusted model output, stored and shown as data only.
type FindingObservation struct {
	ID              uint `gorm:"primarykey"`
	FindingID       uint `gorm:"index;not null;uniqueIndex:idx_finding_observation_scan,priority:1"`
	ScanID          uint `gorm:"index;not null;uniqueIndex:idx_finding_observation_scan,priority:2"`
	RepositoryID    uint `gorm:"index;not null"`
	SkillName       string
	Backend         string
	Model           string
	Commit          string
	ReportFindingID string // the finding's id inside the scan report, e.g. F1
	Fingerprint     string
	Title           string
	Severity        string
	Confidence      string
	CWE             string
	Location        string
	Reachability    string
	Rating          string `gorm:"type:text"`
	Evidence        string `gorm:"type:text"` // JSON object of the unpromoted evidence fields
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ObservationFromFinding builds the observation row for a scan reporting f.
// f must be the content the scan itself reported (not the stored canonical
// row) and must already carry its database id.
func ObservationFromFinding(scan *Scan, f *Finding) FindingObservation {
	evidence := map[string]string{}
	for k, v := range map[string]string{
		"locations":    f.Locations,
		"sinks":        f.Sinks,
		"trace":        f.Trace,
		"boundary":     f.Boundary,
		"validation":   f.Validation,
		"reach":        f.Reach,
		"affected":     f.Affected,
		"quality_tier": f.QualityTier,
		"prior_art":    f.PriorArt,
		"dup_check":    f.DupCheck,
	} {
		if v != "" {
			evidence[k] = v
		}
	}
	raw := ""
	if len(evidence) > 0 {
		if b, err := json.Marshal(evidence); err == nil {
			raw = string(b)
		}
	}
	return FindingObservation{
		FindingID:       f.ID,
		ScanID:          scan.ID,
		RepositoryID:    scan.RepositoryID,
		SkillName:       scan.SkillName,
		Backend:         scan.Backend,
		Model:           scan.Model,
		Commit:          scan.Commit,
		ReportFindingID: f.FindingID,
		Fingerprint:     f.Fingerprint,
		Title:           f.Title,
		Severity:        f.Severity,
		Confidence:      f.Confidence,
		CWE:             f.CWE,
		Location:        f.Location,
		Reachability:    f.Reachability,
		Rating:          f.Rating,
		Evidence:        raw,
	}
}

// RecordFindingObservation upserts each observation for its (finding, scan)
// pair. A repeat write from the same scan replaces the content columns so the
// final report wins over the scan's streamed preview.
func RecordFindingObservation(gdb *gorm.DB, obs ...FindingObservation) error {
	if len(obs) == 0 {
		return nil
	}
	return gdb.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "finding_id"}, {Name: "scan_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"repository_id", "skill_name", "backend", "model", "commit", "report_finding_id",
			"fingerprint", "title", "severity", "confidence", "cwe", "location",
			"reachability", "rating", "evidence", "updated_at",
		}),
	}).CreateInBatches(&obs, observationBatchSize).Error
}

// ContributionFindingIDs returns the finding plus the findings that
// finding-dedup merged into it (Status duplicate with DuplicateOfID pointing
// into the set), followed transitively and within the same repository. The
// walk is capped at maxContributionFindings findings.
func ContributionFindingIDs(gdb *gorm.DB, findingID uint) ([]uint, error) {
	var root Finding
	if err := gdb.Select("id", "repository_id").First(&root, findingID).Error; err != nil {
		return nil, err
	}
	ids := []uint{root.ID}
	visited := map[uint]bool{root.ID: true}
	frontier := []uint{root.ID}
	for len(frontier) > 0 && len(ids) < maxContributionFindings {
		var children []uint
		if err := gdb.Model(&Finding{}).
			Where("repository_id = ? AND status = ? AND duplicate_of_id IN ?", root.RepositoryID, FindingDuplicate, frontier).
			Order("id").Limit(maxContributionFindings).Pluck("id", &children).Error; err != nil {
			return nil, err
		}
		frontier = frontier[:0]
		for _, id := range children {
			if visited[id] || len(ids) >= maxContributionFindings {
				continue
			}
			visited[id] = true
			ids = append(ids, id)
			frontier = append(frontier, id)
		}
	}
	return ids, nil
}

// ObservationsForFindings returns the observations of the given findings. A
// positive limit keeps only the newest limit rows. Rows are ordered by
// creation time then id. total counts every matching row.
func ObservationsForFindings(gdb *gorm.DB, ids []uint, limit int) (rows []FindingObservation, total int64, err error) {
	q := func() *gorm.DB { return gdb.Model(&FindingObservation{}).Where("finding_id IN ?", ids) }
	if err := q().Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		err = q().Order("created_at, id").Find(&rows).Error
		return rows, total, err
	}
	if err := q().Order("created_at DESC, id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	slices.Reverse(rows)
	return rows, total, nil
}

// FindingContributions returns the observations that make up a finding.
func FindingContributions(gdb *gorm.DB, findingID uint, limit int) ([]FindingObservation, int64, error) {
	ids, err := ContributionFindingIDs(gdb, findingID)
	if err != nil {
		return nil, 0, err
	}
	return ObservationsForFindings(gdb, ids, limit)
}
