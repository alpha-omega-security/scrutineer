package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ScanGroupBudget is the optional shared spend cap for every scan in one ScanGroup.
type ScanGroupBudget struct {
	ID           uint    `gorm:"primarykey"`
	ScanGroup    string  `gorm:"uniqueIndex;not null"`
	RepositoryID uint    `gorm:"index;not null"`
	MaxCostUSD   float64 `gorm:"not null"`
	CreatedAt    time.Time
}

// SetScanGroupBudget records the shared cap for a group, replacing an earlier
// one. An empty group or a non-positive cap records nothing.
func SetScanGroupBudget(gdb *gorm.DB, group string, repoID uint, limit float64) error {
	if group == "" || limit <= 0 {
		return nil
	}
	return gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "scan_group"}},
		DoUpdates: clause.AssignmentColumns([]string{"max_cost_usd"}),
	}).Create(&ScanGroupBudget{ScanGroup: group, RepositoryID: repoID, MaxCostUSD: limit}).Error
}

// ScanGroupBudgetFor returns the group's cap, or 0 when it has none.
func ScanGroupBudgetFor(gdb *gorm.DB, group string) (float64, error) {
	if group == "" {
		return 0, nil
	}
	var b ScanGroupBudget
	err := gdb.Where("scan_group = ?", group).Limit(1).Find(&b).Error
	return b.MaxCostUSD, err
}

// ScanGroupSpend sums cost_usd over every scan in the group, skipping the scan
// with id exclude (0 skips none).
func ScanGroupSpend(gdb *gorm.DB, group string, exclude uint) (float64, error) {
	var total float64
	err := gdb.Model(&Scan{}).Where("scan_group = ? AND id <> ?", group, exclude).
		Select("COALESCE(SUM(cost_usd), 0)").Scan(&total).Error
	return total, err
}
