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
			// An import (kind=import) is operator-submitted, with a raw
			// scanner export capped before it is written: it shows in the
			// Findings list by default and so counts toward the dedup-pass
			// threshold, unlike a tool-scanner skill.
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

// testScanGroup is the cohort id the batch tests launch their scans under.
// Production uses uuid.NewString(); the value only has to be shared.
const testScanGroup = "batch-1"

// newGroupScan creates a focus-area deep dive belonging to a batch cohort.
func newGroupScan(t *testing.T, s *Server, repoID uint, focus string, status db.ScanStatus) *db.Scan {
	t.Helper()
	return newGroupScanOfSkill(t, s, repoID, focus, "security-deep-dive", status)
}

// newGroupScanOfSkill is newGroupScan for the cohort members that are not
// deep dives: enqueueDiffRescanGroup puts recon, threat-model and semgrep in
// the same scan_group as the fanned-out deep dives.
func newGroupScanOfSkill(t *testing.T, s *Server, repoID uint, focus, skillName string, status db.ScanStatus) *db.Scan {
	t.Helper()
	scan := db.Scan{RepositoryID: repoID, Status: status, SkillName: skillName,
		ScanGroup: testScanGroup, FocusArea: focus}
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

	first := newGroupScan(t, s, repoID, `{"name":"auth"}`, db.ScanDone)
	second := newGroupScan(t, s, repoID, `{"name":"ssrf"}`, db.ScanRunning)
	third := newGroupScan(t, s, repoID, `{"name":"deser"}`, db.ScanQueued)
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

// The sibling that arrives last is arbitrary, so the batch's pass cannot
// depend on that sibling qualifying on its own. Each case here is one where
// main runs a pass and gating on the finalizing scan would run none: the last
// one home produced nothing, is not an LLM audit at all, or ended failed or
// cancelled rather than done.
func TestAutoEnqueueFindingDedup_lastSiblingNeedNotQualify(t *testing.T) {
	cases := []struct {
		name     string
		skill    string
		status   db.ScanStatus
		findings bool
	}{
		{name: "no new findings", skill: "security-deep-dive", status: db.ScanDone},
		{name: "not an LLM audit", skill: "semgrep", status: db.ScanDone},
		{name: "failed", skill: "security-deep-dive", status: db.ScanFailed},
		{name: "cancelled", skill: "security-deep-dive", status: db.ScanCancelled},
		{name: "qualifies itself", skill: "security-deep-dive", status: db.ScanDone, findings: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done, repoID, dedupID := dedupTestSetup(t)
			defer done()

			// The whole cohort exists up front, as it does in production:
			// the batch is launched as one unit and its members finish one
			// at a time.
			var earlier []*db.Scan
			for _, focus := range []string{`{"name":"auth"}`, `{"name":"ssrf"}`} {
				sibling := newGroupScan(t, s, repoID, focus, db.ScanDone)
				// Both found something, so the cohort has new findings and
				// the repo ends up with a pair to compare.
				newFindingUnder(t, s, repoID, sibling.ID, db.FindingNew)
				earlier = append(earlier, sibling)
			}
			last := newGroupScanOfSkill(t, s, repoID, `{"name":"deser"}`, tc.skill, db.ScanRunning)
			if tc.findings {
				newFindingUnder(t, s, repoID, last.ID, db.FindingNew)
			}

			for _, sibling := range earlier {
				s.autoEnqueueFindingDedup(sibling)
			}
			if n := dedupQueued(s, repoID, dedupID); n != 0 {
				t.Fatalf("queued = %d, want 0 while the last sibling is outstanding", n)
			}

			s.DB.Model(last).Update("status", tc.status)
			s.autoEnqueueFindingDedup(last)
			if n := dedupQueued(s, repoID, dedupID); n != 1 {
				t.Errorf("queued = %d, want 1: the batch produced findings and has drained", n)
			}
		})
	}
}

// A sibling paused on a rate limit will resume and file more findings, so the
// cohort has not drained and the pass must not fire against a half-filled
// working set.
func TestAutoEnqueueFindingDedup_pausedSiblingIsOutstanding(t *testing.T) {
	s, done, repoID, dedupID := dedupTestSetup(t)
	defer done()

	first := newGroupScan(t, s, repoID, `{"name":"auth"}`, db.ScanDone)
	newFindingUnder(t, s, repoID, first.ID, db.FindingNew)
	second := newGroupScan(t, s, repoID, `{"name":"ssrf"}`, db.ScanDone)
	newFindingUnder(t, s, repoID, second.ID, db.FindingNew)
	newGroupScan(t, s, repoID, `{"name":"deser"}`, db.ScanPaused)

	s.autoEnqueueFindingDedup(first)
	s.autoEnqueueFindingDedup(second)
	if n := dedupQueued(s, repoID, dedupID); n != 0 {
		t.Errorf("queued = %d, want 0 while a sibling is paused on a rate limit", n)
	}
}

// A cohort that produced no new findings at all still gets no pass: the batch
// gate widens which scan may trigger the work, not whether there is any.
func TestAutoEnqueueFindingDedup_emptyBatchEnqueuesNothing(t *testing.T) {
	s, done, repoID, dedupID := dedupTestSetup(t)
	defer done()

	prior := newScan(t, s, repoID, "security-deep-dive")
	newFindingUnder(t, s, repoID, prior.ID, db.FindingNew)
	newFindingUnder(t, s, repoID, prior.ID, db.FindingNew)

	first := newGroupScan(t, s, repoID, `{"name":"auth"}`, db.ScanDone)
	last := newGroupScan(t, s, repoID, `{"name":"ssrf"}`, db.ScanDone)
	s.autoEnqueueFindingDedup(first)
	s.autoEnqueueFindingDedup(last)

	if n := dedupQueued(s, repoID, dedupID); n != 0 {
		t.Errorf("queued = %d, want 0: the batch found nothing new", n)
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

// A queued sibling can be cancelled without ever reaching the worker:
// scanCancel and scansCancelAll flip the row in place, and a federation
// opt-out sweeps queued and paused rows in bulk. Each is a queued-to-terminal
// transition the worker never observes, so the cohort hook has to be fired by
// the path that made the transition. Without that, the earlier siblings have
// all suppressed on the cancelled one's account and the batch gets no pass at
// all — andrew's repro on #855: a completed sibling holding two findings,
// followed by cancellation of its queued sibling, left the dedup queue empty.
func TestCancelledQueuedSiblingSettlesBatch(t *testing.T) {
	cases := []struct {
		name   string
		cancel func(s *Server, repoID uint, queued *db.Scan)
	}{{
		name: "per-row cancel",
		cancel: func(s *Server, _ uint, queued *db.Scan) {
			s.cancelScan(queued, "cancelled by user")
		},
	}, {
		name: "federation opt-out sweep",
		cancel: func(s *Server, repoID uint, _ *db.Scan) {
			if err := s.stopScansForOptOut(repoID); err != nil {
				t.Fatalf("stopScansForOptOut: %v", err)
			}
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done, repoID, dedupID := dedupTestSetup(t)
			defer done()

			// The cohort exists in full before any member settles, as it does
			// in production: a done sibling carrying the batch's findings, and
			// one still queued that the earlier one is waiting on.
			finished := newGroupScan(t, s, repoID, `{"name":"auth"}`, db.ScanDone)
			queued := newGroupScan(t, s, repoID, `{"name":"ssrf"}`, db.ScanQueued)
			newFindingUnder(t, s, repoID, finished.ID, db.FindingNew)
			newFindingUnder(t, s, repoID, finished.ID, db.FindingNew)

			s.autoEnqueueFindingDedup(finished)
			if n := dedupQueued(s, repoID, dedupID); n != 0 {
				t.Fatalf("queued = %d, want 0 while the sibling is still queued", n)
			}

			tc.cancel(s, repoID, queued)

			if n := dedupQueued(s, repoID, dedupID); n != 1 {
				t.Errorf("queued = %d, want 1 after the last outstanding sibling was cancelled", n)
			}
		})
	}
}

// A bulk cancel settles each cohort once rather than once per row: the handler
// answers for the whole batch, so firing per sibling would be redundant work
// on a path that can flip an entire repository's queue in one click.
func TestCancelledQueuedSiblingsSettleGroupOnce(t *testing.T) {
	s, done, repoID, dedupID := dedupTestSetup(t)
	defer done()

	finished := newGroupScan(t, s, repoID, `{"name":"auth"}`, db.ScanDone)
	newGroupScan(t, s, repoID, `{"name":"ssrf"}`, db.ScanQueued)
	newGroupScan(t, s, repoID, `{"name":"deser"}`, db.ScanQueued)
	newFindingUnder(t, s, repoID, finished.ID, db.FindingNew)
	newFindingUnder(t, s, repoID, finished.ID, db.FindingNew)

	if err := s.stopScansForOptOut(repoID); err != nil {
		t.Fatalf("stopScansForOptOut: %v", err)
	}
	if n := dedupQueued(s, repoID, dedupID); n != 1 {
		t.Errorf("queued = %d, want 1 for the cohort", n)
	}
}

// A scan the worker claimed between the caller's read and its write keeps
// running, so the row is not flipped and its cohort has not drained. The
// settle pass must re-read the status rather than assume the update landed.
func TestSettleCancelledScanGroupsIgnoresUnflippedRows(t *testing.T) {
	s, done, repoID, dedupID := dedupTestSetup(t)
	defer done()

	finished := newGroupScan(t, s, repoID, `{"name":"auth"}`, db.ScanDone)
	running := newGroupScan(t, s, repoID, `{"name":"ssrf"}`, db.ScanRunning)
	newFindingUnder(t, s, repoID, finished.ID, db.FindingNew)
	newFindingUnder(t, s, repoID, finished.ID, db.FindingNew)

	s.settleCancelledScanGroups(running.ID)
	if n := dedupQueued(s, repoID, dedupID); n != 0 {
		t.Errorf("queued = %d, want 0 while the sibling is still running", n)
	}
}
