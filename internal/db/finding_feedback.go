package db

import (
	"time"

	"gorm.io/gorm"
)

const MaxFindingFeedback = 20

// FindingFeedback is historical evidence, never an instruction to suppress a finding.
type FindingFeedback struct {
	ReviewID     uint      `json:"review_id"`
	FindingID    uint      `json:"finding_id"`
	Fingerprint  string    `json:"fingerprint"`
	SourceScanID uint      `json:"source_scan_id"`
	SourceCommit string    `json:"source_commit"`
	Path         string    `json:"path"`
	CWE          string    `json:"cwe,omitempty"`
	Reason       string    `json:"reason"`
	Reviewer     string    `json:"reviewer,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// FindingFeedbackForPaths selects the latest human decision per still-rejected
// case. Legacy reviews without snapshots are not silently assigned a new source.
func FindingFeedbackForPaths(gdb *gorm.DB, repoID uint, paths []string) ([]FindingFeedback, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	var rows []FindingFeedback
	err := gdb.Table("finding_reviews AS r").
		Select(`r.id AS review_id, r.finding_id, r.finding_fingerprint AS fingerprint,
			r.source_scan_id, r.source_commit, r.finding_path AS path, r.cwe,
			substr(r.reason, 1, ?) AS reason, substr(r.reviewer, 1, 256) AS reviewer, r.created_at`, MaxReviewReasonBytes).
		Joins("JOIN findings f ON f.id = r.finding_id").
		Where("f.repository_id = ? AND f.status = ?", repoID, FindingRejected).
		Where("r.verdict = ? AND r.source_scan_id > 0 AND trim(r.reason) <> ''", "false_positive").
		Where("r.finding_path IN ?", paths).
		Where("NOT EXISTS (SELECT 1 FROM finding_reviews newer WHERE newer.finding_id = r.finding_id AND newer.id > r.id)").
		Where("NOT EXISTS (SELECT 1 FROM finding_histories h WHERE h.finding_id = r.finding_id AND h.field = 'status' AND h.new_value <> ? AND h.created_at > r.created_at)", FindingRejected).
		Order("r.id DESC").Limit(MaxFindingFeedback).Scan(&rows).Error
	return rows, err
}
