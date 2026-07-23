package web

import (
	"testing"
	"time"

	"scrutineer/internal/db"
)

// advisoryAuditSetup creates a repo and an active advisory-deep-dive skill,
// and returns a counter for its queued repo-scoped scans.
func advisoryAuditSetup(t *testing.T) (s *Server, done func(), repoID, skillID uint) {
	t.Helper()
	s, done = newTestServer(t)
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: advisoryDeepDiveSkillName, OutputFile: "report.json", OutputKind: "advisory_audit", Version: 1, Active: true}
	s.DB.Create(&skill)
	return s, done, repo.ID, skill.ID
}

func advisoryAuditQueued(s *Server, repoID, skillID uint) int64 {
	var n int64
	s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND skill_id = ? AND status = ?", repoID, skillID, db.ScanQueued).
		Count(&n)
	return n
}

// seedDoneAudit records a completed advisory-deep-dive scan finished at ts, so
// the regression watch has a prior audit to compare a release against.
func seedDoneAudit(s *Server, repoID uint, ts time.Time) {
	s.DB.Create(&db.Scan{
		RepositoryID: repoID, SkillName: advisoryDeepDiveSkillName,
		Status: db.ScanDone, FinishedAt: &ts,
	})
}

func seedPackage(s *Server, repoID uint, releasedAt *time.Time) {
	s.DB.Create(&db.Package{RepositoryID: repoID, Name: "p", Ecosystem: "npm", LatestReleaseAt: releasedAt})
}

func TestAutoEnqueueAdvisoryAudit_reenqueuesOnNewerRelease(t *testing.T) {
	s, done, repoID, skillID := advisoryAuditSetup(t)
	defer done()

	auditedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	released := auditedAt.Add(48 * time.Hour)
	seedDoneAudit(s, repoID, auditedAt)
	seedPackage(s, repoID, &released)

	s.autoEnqueueAdvisoryAudit(newScan(t, s, repoID, packagesSkillName))

	if got := advisoryAuditQueued(s, repoID, skillID); got != 1 {
		t.Fatalf("queued audits = %d, want 1", got)
	}
}

func TestAutoEnqueueAdvisoryAudit_skips(t *testing.T) {
	auditedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	older := auditedAt.Add(-48 * time.Hour)
	newer := auditedAt.Add(48 * time.Hour)

	cases := []struct {
		name string
		// setup seeds repo state before the packages scan finalizes.
		setup func(s *Server, repoID uint)
		// triggerSkill is the skill the finalizing scan ran.
		triggerSkill string
	}{
		{
			name:         "not a packages scan",
			setup:        func(s *Server, repoID uint) { seedDoneAudit(s, repoID, auditedAt); seedPackage(s, repoID, &newer) },
			triggerSkill: "metadata",
		},
		{
			name:         "no prior audit",
			setup:        func(s *Server, repoID uint) { seedPackage(s, repoID, &newer) },
			triggerSkill: packagesSkillName,
		},
		{
			name:         "release predates last audit",
			setup:        func(s *Server, repoID uint) { seedDoneAudit(s, repoID, auditedAt); seedPackage(s, repoID, &older) },
			triggerSkill: packagesSkillName,
		},
		{
			name:         "no release timestamp",
			setup:        func(s *Server, repoID uint) { seedDoneAudit(s, repoID, auditedAt); seedPackage(s, repoID, nil) },
			triggerSkill: packagesSkillName,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done, repoID, skillID := advisoryAuditSetup(t)
			defer done()
			tc.setup(s, repoID)

			s.autoEnqueueAdvisoryAudit(newScan(t, s, repoID, tc.triggerSkill))

			if got := advisoryAuditQueued(s, repoID, skillID); got != 0 {
				t.Fatalf("queued audits = %d, want 0", got)
			}
		})
	}
}

func TestAutoEnqueueAdvisoryAudit_skipsWhenAlreadyInFlight(t *testing.T) {
	s, done, repoID, skillID := advisoryAuditSetup(t)
	defer done()

	auditedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	released := auditedAt.Add(48 * time.Hour)
	seedDoneAudit(s, repoID, auditedAt)
	seedPackage(s, repoID, &released)
	// A repo-scoped audit already queued.
	s.DB.Create(&db.Scan{RepositoryID: repoID, SkillID: &skillID, Status: db.ScanQueued})

	s.autoEnqueueAdvisoryAudit(newScan(t, s, repoID, packagesSkillName))

	if got := advisoryAuditQueued(s, repoID, skillID); got != 1 {
		t.Fatalf("queued audits = %d, want 1 (no duplicate enqueue)", got)
	}
}
