package db

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const maintainerStatusColumn = "status"

// MaintainerActivity records activity within one repository.
type MaintainerActivity struct {
	RepositoryID uint `gorm:"primaryKey"`
	MaintainerID uint `gorm:"primaryKey;index"`
	Status       MaintainerStatus
	Repository   Repository `gorm:"constraint:OnDelete:CASCADE"`
	Maintainer   Maintainer `gorm:"constraint:OnDelete:CASCADE"`
}

func RecordMaintainerActivity(gdb *gorm.DB, repositoryID, maintainerID uint, status string) error {
	switch MaintainerStatus(status) {
	case MaintainerActive, MaintainerInactive:
	default:
		return nil
	}
	activity := MaintainerActivity{RepositoryID: repositoryID, MaintainerID: maintainerID, Status: MaintainerStatus(status)}
	return gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "repository_id"}, {Name: "maintainer_id"}},
		DoUpdates: clause.AssignmentColumns([]string{maintainerStatusColumn}),
	}).Create(&activity).Error
}

// RepositoryMaintainers uses the shared status until repository activity is available.
func RepositoryMaintainers(gdb *gorm.DB, repositoryID uint) ([]Maintainer, error) {
	var rows []struct {
		Maintainer
		RepositoryStatus *MaintainerStatus
	}
	err := gdb.Model(&Maintainer{}).
		Select("maintainers.*, activity.status AS repository_status").
		Joins("JOIN repository_maintainers rm ON rm.maintainer_id = maintainers.id").
		Joins("LEFT JOIN maintainer_activities activity ON activity.maintainer_id = maintainers.id AND activity.repository_id = rm.repository_id").
		Where("rm.repository_id = ?", repositoryID).
		Order("maintainers.login").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	maintainers := make([]Maintainer, 0, len(rows))
	for _, row := range rows {
		if row.RepositoryStatus != nil {
			row.Status = *row.RepositoryStatus
		}
		maintainers = append(maintainers, row.Maintainer)
	}
	return maintainers, nil
}

var ErrInvalidMaintainerStatus = errors.New("invalid maintainer status")

func UpdateMaintainerDetails(gdb *gorm.DB, id uint, fields map[string][]string) error {
	updates := make(map[string]any)
	for _, field := range []string{"name", "email", "notes", maintainerStatusColumn} {
		values, ok := fields[field]
		if !ok || len(values) == 0 {
			continue
		}
		value := strings.TrimSpace(values[0])
		if field == maintainerStatusColumn {
			switch MaintainerStatus(value) {
			case MaintainerActive, MaintainerInactive, MaintainerUnknown:
			default:
				return fmt.Errorf("%w: %q", ErrInvalidMaintainerStatus, value)
			}
		}
		updates[field] = value
	}
	return gdb.Model(&Maintainer{}).Where("id = ?", id).Updates(updates).Error
}
