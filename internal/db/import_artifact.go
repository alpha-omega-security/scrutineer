package db

import "time"

// ImportArtifact retains a file an external producer shipped beside its
// findings, such as an OSS-CRS PoV, patch or report bundle, with the import
// that first brought it. FindingID is 0 when the producer did not associate
// the file with a finding, and a file associated with several findings has
// one row per finding.
type ImportArtifact struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	RepositoryID uint      `gorm:"not null;uniqueIndex:idx_import_artifact_identity" json:"repository_id"`
	FindingID    uint      `gorm:"not null;default:0;index;uniqueIndex:idx_import_artifact_identity" json:"finding_id"`
	Kind         string    `gorm:"not null;uniqueIndex:idx_import_artifact_identity" json:"kind"`
	SHA256       string    `gorm:"not null;uniqueIndex:idx_import_artifact_identity" json:"sha256"`
	ScanID       uint      `gorm:"not null;index" json:"scan_id"`
	Path         string    `gorm:"not null" json:"path"`
	Bytes        int       `json:"bytes"`
	Data         []byte    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

func (ImportArtifact) TableName() string { return "import_artifacts" }
