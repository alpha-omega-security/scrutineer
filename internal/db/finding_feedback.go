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

// eligibleFeedbackQuery is the single definition of which analyst decisions may
// inform later scans. Callers add path or ID filters and ordering.
func eligibleFeedbackQuery(gdb *gorm.DB, repoID uint) *gorm.DB {
	return gdb.Table("finding_reviews AS r").
		Select(`r.id AS review_id, r.finding_id, r.finding_fingerprint AS fingerprint,
			r.source_scan_id, r.source_commit, r.finding_path AS path, r.cwe,
			substr(r.reason, 1, ?) AS reason, substr(r.reviewer, 1, 256) AS reviewer, r.created_at`, MaxReviewReasonChars).
		Joins("JOIN findings f ON f.id = r.finding_id").
		Where("f.repository_id = ? AND f.status = ?", repoID, FindingRejected).
		Where("r.verdict = ? AND r.source_scan_id > 0 AND trim(r.reason) <> ''", "false_positive").
		Where("NOT EXISTS (SELECT 1 FROM finding_reviews newer WHERE newer.finding_id = r.finding_id AND newer.id > r.id)").
		Where("NOT EXISTS (SELECT 1 FROM finding_histories h WHERE h.finding_id = r.finding_id AND h.field = 'status' AND h.new_value <> ? AND h.created_at > r.created_at)", FindingRejected)
}

// FindingFeedbackForPaths selects the latest human decision per still-rejected
// case. Legacy reviews without snapshots are not silently assigned a new source.
func FindingFeedbackForPaths(gdb *gorm.DB, repoID uint, paths []string) ([]FindingFeedback, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	var rows []FindingFeedback
	err := eligibleFeedbackQuery(gdb, repoID).
		Where("r.finding_path IN ?", paths).
		Order("r.id DESC").Limit(MaxFindingFeedback).Scan(&rows).Error
	return rows, err
}

// EligibleFeedbackForReviews returns the named reviews that are currently
// eligible feedback for path in the repository. The usual limit does not apply
// because the caller names specific decisions.
func EligibleFeedbackForReviews(gdb *gorm.DB, repoID uint, path string, reviewIDs []uint) ([]FindingFeedback, error) {
	if path == "" || len(reviewIDs) == 0 {
		return nil, nil
	}
	var rows []FindingFeedback
	err := eligibleFeedbackQuery(gdb, repoID).
		Where("r.finding_path = ? AND r.id IN ?", path, reviewIDs).
		Order("r.id").Scan(&rows).Error
	return rows, err
}

// EligibleFeedbackReviewIDs lists every currently eligible decision in the
// repository regardless of path.
func EligibleFeedbackReviewIDs(gdb *gorm.DB, repoID uint) (map[uint]bool, error) {
	var ids []uint
	if err := eligibleFeedbackQuery(gdb, repoID).Select("r.id").Pluck("r.id", &ids).Error; err != nil {
		return nil, err
	}
	out := make(map[uint]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}
