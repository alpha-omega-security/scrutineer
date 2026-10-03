package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// FeedbackConfirmation records that a revalidate scan independently re-checked
// a finding and relied on one analyst decision. The unique (review, scan) index
// keeps retried or re-parsed scans from counting twice.
type FeedbackConfirmation struct {
	ID        uint   `gorm:"primarykey"`
	ReviewID  uint   `gorm:"not null;index;uniqueIndex:idx_feedback_confirmation_scan,priority:1"`
	ScanID    uint   `gorm:"not null;uniqueIndex:idx_feedback_confirmation_scan,priority:2"`
	FindingID uint   `gorm:"not null"`
	Commit    string `gorm:"not null"`
	CreatedAt time.Time
}

// RecordFeedbackConfirmation inserts the confirmation and reports whether it
// was new.
func RecordFeedbackConfirmation(gdb *gorm.DB, c *FeedbackConfirmation) (bool, error) {
	res := gdb.Clauses(clause.OnConflict{DoNothing: true}).Create(c)
	return res.RowsAffected == 1, res.Error
}

// FeedbackConfirmations lists a review's confirmations oldest first.
func FeedbackConfirmations(gdb *gorm.DB, reviewID uint) ([]FeedbackConfirmation, error) {
	var out []FeedbackConfirmation
	err := gdb.Where("review_id = ?", reviewID).Order("id").Find(&out).Error
	return out, err
}

// DistinctConfirmedCommits counts the distinct commits that confirmed a
// decision, excluding the commit the analyst originally reviewed.
func DistinctConfirmedCommits(confirmations []FeedbackConfirmation, sourceCommit string) int {
	seen := map[string]bool{}
	for _, c := range confirmations {
		if c.Commit != "" && c.Commit != sourceCommit {
			seen[c.Commit] = true
		}
	}
	return len(seen)
}
