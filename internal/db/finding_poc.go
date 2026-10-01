package db

import (
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/poc"
)

// FindingPoC retains the first captured reproduction independently of its
// scan workspace. Only deleting the finding removes the capture.
type FindingPoC struct {
	ID        uint `gorm:"primarykey"`
	FindingID uint `gorm:"not null;uniqueIndex"`
	ScanID    uint `gorm:"not null"`
	Commit    string
	Files     []byte `json:"-"`
	CreatedAt time.Time
}

type PoCManifest struct {
	FindingID  uint          `json:"finding_id"`
	ScanID     uint          `json:"scan_id"`
	Commit     string        `json:"commit"`
	CapturedAt time.Time     `json:"captured_at"`
	Directory  string        `json:"directory"`
	Files      []PoCFileInfo `json:"files"`
}

type PoCFileInfo struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Bytes      int    `json:"bytes"`
	Executable bool   `json:"executable"`
}

func (row FindingPoC) Manifest(files []poc.File) PoCManifest {
	manifest := PoCManifest{FindingID: row.FindingID, ScanID: row.ScanID, Commit: row.Commit, CapturedAt: row.CreatedAt, Directory: "./poc"}
	for _, file := range files {
		manifest.Files = append(manifest.Files, PoCFileInfo{Path: file.Path, SHA256: file.SHA256, Bytes: len(file.Data), Executable: file.Executable})
	}
	return manifest
}

func LoadFindingPoC(gdb *gorm.DB, findingID uint) (*FindingPoC, error) {
	var row FindingPoC
	result := gdb.Where("finding_id = ?", findingID).Limit(1).Find(&row)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, nil
	}
	return &row, nil
}
