package web

import (
	"encoding/json"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

// autoSeedRepoScanConfig accepts a threat-model proposal only for an
// unconfigured root/default-branch repository. The conditional update keeps a
// concurrent analyst edit authoritative.
func (s *Server) autoSeedRepoScanConfig(scan *db.Scan) {
	if scan == nil || scan.Status != db.ScanDone || scan.SkillName != threatModelSkillName ||
		scan.SubPath != "" || scan.Ref != "" || strings.TrimSpace(scan.Report) == "" {
		return
	}
	var report struct {
		ScanConfig json.RawMessage `json:"scan_config"`
	}
	if err := json.Unmarshal([]byte(scan.Report), &report); err != nil || len(report.ScanConfig) == 0 {
		return
	}
	config, parsed, err := repoconfig.Normalise(string(report.ScanConfig))
	if err != nil {
		s.Log.Warn("scan config proposal invalid", "scan", scan.ID, "err", err)
		return
	}
	if parsed.Empty() {
		return
	}
	if err := s.DB.Model(&db.Repository{}).
		Where("id = ? AND (scan_config = '' OR scan_config IS NULL)", scan.RepositoryID).
		Update("scan_config", config).Error; err != nil {
		s.Log.Warn("save scan config proposal", "scan", scan.ID, "err", err)
	}
}
