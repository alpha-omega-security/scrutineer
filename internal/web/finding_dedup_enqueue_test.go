package web

import (
	"sync"
	"testing"

	"scrutineer/internal/db"
)

// dedupTestSetup creates a repo and an active finding-dedup skill, and
// returns helpers for creating scans and findings the callback tests act on.
func dedupTestSetup(t *testing.T) (s *Server, done func(), repoID uint, dedupID uint) {
	t.Helper()
	s, done = newTestServer(t)
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	dedup := db.Skill{Name: "finding-dedup", OutputFile: "report.json", OutputKind: "finding_dedup", Version: 1, Active: true}
	s.DB.Create(&dedup)
	return s, done, repo.ID, dedup.ID
}

func newScan(t *testing.T, s *Server, repoID uint, skillName string) *db.Scan {
	t.Helper()
	scan := db.Scan{RepositoryID: repoID, Status: db.ScanDone, SkillName: skillName}
	s.DB.Create(&scan)
	return &scan
}

func newFindingUnder(t *testing.T, s *Server, repoID, scanID uint, status db.FindingLifecycle) {
	t.Helper()
	f := db.Finding{ScanID: scanID, RepositoryID: repoID, Title: "t", Severity: "High", Status: status}
	s.DB.Create(&f)
}

func dedupQueued(s *Server, repoID, dedupID uint) int64 {
	var n int64
	s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND skill_id = ? AND status = ?", repoID, dedupID, db.ScanQueued).
		Count(&n)
	return n
}

// TestAutoEnqueueFindingDedup_conditions covers the two gating conditions:
// a curated LLM audit (security-deep-dive or vuln-scan) must produce at least
// one new finding, and the repo must end up with at least two open non-scanner
// findings to compare against (the new rows count, so a first-ever audit
// emitting several findings qualifies).
func TestAutoEnqueueFindingDedup_conditions(t *testing.T) {
	cases := []struct {
		name string
		// scanSkill is the skill the just-completed scan ran.
		scanSkill string
		// newFindings is how many fresh findings are attached to the
		// completed scan (condition 1 needs at least one).
		newFindings int
		// hasPrior, when set, creates a pre-existing finding from an earlier
		// scan described by priorSkill/priorKind/priorStatus (counts toward
		// condition 2). priorKind defaults to a skill run when empty.
		hasPrior    bool
		priorSkill  string
		priorKind   string
		priorStatus db.FindingLifecycle
		wantQueued  bool
	}{
		{
			name:        "deep-dive new finding with prior open non-scanner finding",
			scanSkill:   "security-deep-dive",
			newFindings: 1, hasPrior: true, priorSkill: "security-deep-dive", priorStatus: db.FindingNew,
			wantQueued: true,
		},
		{
			name:        "first-ever deep-dive emitting two new findings",
			scanSkill:   "security-deep-dive",
			newFindings: 2, hasPrior: false,
			wantQueued: true,
		},
		{
			name:        "prior legacy (empty skill) finding also counts",
			scanSkill:   "security-deep-dive",
			newFindings: 1, hasPrior: true, priorSkill: "", priorStatus: db.FindingNew,
			wantQueued: true,
		},
		{
			name:        "first-ever vuln-scan emitting two new findings",
			scanSkill:   "vuln-scan",
			newFindings: 2, hasPrior: false,
			wantQueued: true,
		},
		{
			name:        "vuln-scan new finding with prior vuln-scan finding",
			scanSkill:   "vuln-scan",
			newFindings: 1, hasPrior: true, priorSkill: "vuln-scan", priorStatus: db.FindingNew,
			wantQueued: true,
		},
		{
			name:        "no new finding does not enqueue",
			scanSkill:   "security-deep-dive",
			newFindings: 0, hasPrior: true, priorSkill: "security-deep-dive", priorStatus: db.FindingNew,
			wantQueued: false,
		},
		{
			name:        "single new finding with no other does not enqueue",
			scanSkill:   "security-deep-dive",
			newFindings: 1, hasPrior: false,
			wantQueued: false,
		},
		{
			name:        "prior scanner finding does not count",
			scanSkill:   "security-deep-dive",
			newFindings: 1, hasPrior: true, priorSkill: "semgrep", priorStatus: db.FindingNew,
			wantQueued: false,
		},
		{
			// An import (kind=import) is curated data, not noisy scanner
			// output: it shows in the Findings list by default and so counts
			// toward the dedup-pass threshold, unlike a tool-scanner skill.
			name:        "prior import finding now counts (kind=import)",
			scanSkill:   "security-deep-dive",
			newFindings: 1, hasPrior: true, priorSkill: "CodeQL", priorKind: "import", priorStatus: db.FindingNew,
			wantQueued: true,
		},
		{
			name:        "prior closed non-scanner finding does not count",
			scanSkill:   "security-deep-dive",
			newFindings: 1, hasPrior: true, priorSkill: "security-deep-dive", priorStatus: db.FindingDuplicate,
			wantQueued: false,
		},
		{
			name:        "non-deep-dive scan does not enqueue",
			scanSkill:   "semgrep",
			newFindings: 1, hasPrior: true, priorSkill: "security-deep-dive", priorStatus: db.FindingNew,
			wantQueued: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, done, repoID, dedupID := dedupTestSetup(t)
			defer done()

			if c.hasPrior {
				prior := newScan(t, s, repoID, c.priorSkill)
				if c.priorKind != "" {
					prior.Kind = c.priorKind
					s.DB.Save(prior)
				}
				newFindingUnder(t, s, repoID, prior.ID, c.priorStatus)
			}

			scan := newScan(t, s, repoID, c.scanSkill)
			for i := 0; i < c.newFindings; i++ {
				newFindingUnder(t, s, repoID, scan.ID, db.FindingNew)
			}

			s.autoEnqueueFindingDedup(scan)

			got := dedupQueued(s, repoID, dedupID) > 0
			if got != c.wantQueued {
				t.Errorf("queued=%v, want %v", got, c.wantQueued)
			}
		})
	}
}

func TestAutoEnqueueFindingDedup_doesNotDoubleQueueConcurrently(t *testing.T) {
	s, done, repoID, dedupID := dedupTestSetup(t)
	defer done()

	prior := newScan(t, s, repoID, "security-deep-dive")
	newFindingUnder(t, s, repoID, prior.ID, db.FindingNew)

	const finalizers = 16
	scans := make([]*db.Scan, finalizers)
	for i := range scans {
		scans[i] = newScan(t, s, repoID, "security-deep-dive")
		newFindingUnder(t, s, repoID, scans[i].ID, db.FindingNew)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, scan := range scans {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.autoEnqueueFindingDedup(scan)
		}()
	}
	close(start)
	wg.Wait()

	if n := dedupQueued(s, repoID, dedupID); n != 1 {
		t.Errorf("queued = %d, want 1 (re-queue guard)", n)
	}
}

func TestAutoEnqueueFindingDedup_gracefulWhenSkillAbsent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	// No finding-dedup skill registered: must not panic.
	prior := newScan(t, s, repo.ID, "security-deep-dive")
	newFindingUnder(t, s, repo.ID, prior.ID, db.FindingNew)
	scan := newScan(t, s, repo.ID, "security-deep-dive")
	newFindingUnder(t, s, repo.ID, scan.ID, db.FindingNew)

	s.autoEnqueueFindingDedup(scan)
}

func TestAutoEnqueueFindingDedup_nilScan(t *testing.T) {
	s, done, _, _ := dedupTestSetup(t)
	defer done()
	s.autoEnqueueFindingDedup(nil) // must not panic
}

// newGroupScan creates a focus-area scan belonging to a batch cohort.
func newGroupScan(t *testing.T, s *Server, repoID uint, group, focus string, status db.ScanStatus) *db.Scan {
	t.Helper()
	scan := db.Scan{RepositoryID: repoID, Status: status, SkillName: "security-deep-dive",
		ScanGroup: group, FocusArea: focus}
	s.DB.Create(&scan)
	return &scan
}

// A batch of focus-area deep dives finishing one at a time must produce one
// dedup pass, not one per sibling. The in-flight guard alone does not give
// that: it only suppresses while a dedup is queued or running, so as soon as
// one completes between two sibling completions the gate reopens.
func TestAutoEnqueueFindingDedup_waitsForBatchSiblings(t *testing.T) {
	s, done, repoID, dedupID := dedupTestSetup(t)
	defer done()

	const group = "batch-1"
	first := newGroupScan(t, s, repoID, group, `{"name":"auth"}`, db.ScanDone)
	second := newGroupScan(t, s, repoID, group, `{"name":"ssrf"}`, db.ScanRunning)
	third := newGroupScan(t, s, repoID, group, `{"name":"deser"}`, db.ScanQueued)
	for _, sc := range []*db.Scan{first, second, third} {
		newFindingUnder(t, s, repoID, sc.ID, db.FindingNew)
	}

	s.autoEnqueueFindingDedup(first)
	if n := dedupQueued(s, repoID, dedupID); n != 0 {
		t.Errorf("queued = %d, want 0 while %d batch siblings are still outstanding", n, 2)
	}

	// Second finishes; the last sibling is still queued, so still too early.
	s.DB.Model(second).Update("status", db.ScanDone)
	s.autoEnqueueFindingDedup(second)
	if n := dedupQueued(s, repoID, dedupID); n != 0 {
		t.Errorf("queued = %d, want 0 while 1 batch sibling is still outstanding", n)
	}

	// Last one home enqueues exactly one pass for the whole batch.
	s.DB.Model(third).Update("status", db.ScanDone)
	s.autoEnqueueFindingDedup(third)
	if n := dedupQueued(s, repoID, dedupID); n != 1 {
		t.Errorf("queued = %d, want 1 once the batch has drained", n)
	}
}

// An ungrouped scan keeps the old behaviour: nothing to wait for.
func TestAutoEnqueueFindingDedup_ungroupedScanEnqueuesImmediately(t *testing.T) {
	s, done, repoID, dedupID := dedupTestSetup(t)
	defer done()

	prior := newScan(t, s, repoID, "security-deep-dive")
	newFindingUnder(t, s, repoID, prior.ID, db.FindingNew)
	scan := newScan(t, s, repoID, "security-deep-dive")
	newFindingUnder(t, s, repoID, scan.ID, db.FindingNew)

	s.autoEnqueueFindingDedup(scan)
	if n := dedupQueued(s, repoID, dedupID); n != 1 {
		t.Errorf("queued = %d, want 1 for an ungrouped scan", n)
	}
}
