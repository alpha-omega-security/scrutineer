package web

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// packagesSkillName is the registry-inventory skill whose parser refreshes
// Package.LatestReleaseAt, making its completion the natural moment to check
// whether upstream shipped a new release.
const packagesSkillName = "packages"

// autoEnqueueAdvisoryAudit is the regression watch for published advisories,
// wired onto Worker.OnScanFinalized. When a packages scan completes, it
// re-enqueues advisory-deep-dive if all three hold:
//
//  1. A prior advisory-deep-dive run completed on this repository — the
//     operator opted into the audit once; a repo never audited is not
//     re-audited behind their back.
//  2. The newest Package.LatestReleaseAt postdates that run: upstream shipped
//     a release since the last audit, so a fix could have regressed.
//  3. No advisory-deep-dive scan is already queued or running for the repo.
//
// Errors are logged and swallowed: failing to enqueue the re-audit must never
// fail the packages scan that triggered it.
func (s *Server) autoEnqueueAdvisoryAudit(scan *db.Scan) {
	if scan == nil || scan.SkillName != packagesSkillName {
		return
	}

	var last db.Scan
	res := s.DB.Select("id, finished_at").
		Where("repository_id = ? AND skill_name = ? AND status = ?",
			scan.RepositoryID, advisoryDeepDiveSkillName, db.ScanDone).
		Order("id desc").Limit(1).Find(&last)
	if res.Error != nil {
		s.Log.Warn("advisory regression watch: last audit lookup",
			"repo", scan.RepositoryID, "err", res.Error)
		return
	}
	if res.RowsAffected == 0 || last.FinishedAt == nil {
		return
	}

	var pkg db.Package
	pres := s.DB.Select("latest_release_at").
		Where("repository_id = ? AND latest_release_at IS NOT NULL", scan.RepositoryID).
		Order("latest_release_at desc").Limit(1).Find(&pkg)
	if pres.Error != nil {
		s.Log.Warn("advisory regression watch: latest release lookup",
			"repo", scan.RepositoryID, "err", pres.Error)
		return
	}
	if pres.RowsAffected == 0 || pkg.LatestReleaseAt == nil || !pkg.LatestReleaseAt.After(*last.FinishedAt) {
		return
	}

	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", advisoryDeepDiveSkillName, true).First(&skill).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			s.Log.Warn("advisory regression watch: skill lookup", "err", err)
		}
		return
	}
	if s.hasOpenRepoScopedScan(scan.RepositoryID, skill.ID) {
		return
	}
	if _, err := s.enqueueSkillWith(context.Background(), scan.RepositoryID, skill.ID, ScanOpts{}); err != nil {
		s.Log.Warn("advisory regression watch: enqueue",
			"repo", scan.RepositoryID, "skill", advisoryDeepDiveSkillName, "err", err)
	}
}
