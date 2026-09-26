package db

import (
	"fmt"

	"gorm.io/gorm"
)

// UpdateThreatModel retries a compare-and-swap so background writers merge
// against the latest operator edits rather than a scan's stale repository copy.
func UpdateThreatModel(gdb *gorm.DB, repoID uint, update func(string) (string, error)) error {
	const attempts = 5
	for range attempts {
		var repo Repository
		if err := gdb.Select("id, threat_model").First(&repo, repoID).Error; err != nil {
			return err
		}
		model, err := update(repo.ThreatModel)
		if err != nil {
			return err
		}
		result := gdb.Model(&Repository{}).Where("id = ? AND COALESCE(threat_model, '') = ?", repoID, repo.ThreatModel).Update("threat_model", model)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 1 {
			return nil
		}
	}
	return fmt.Errorf("threat model changed concurrently; retry the scan")
}
