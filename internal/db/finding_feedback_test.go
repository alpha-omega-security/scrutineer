package db

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func feedbackFixture(t *testing.T) (*gorm.DB, Finding) {
	t.Helper()
	gdb, err := Open(filepath.Join(t.TempDir(), "feedback.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/feedback"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone, Commit: "original"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	f := Finding{RepositoryID: repo.ID, ScanID: scan.ID, Status: FindingNew, Location: "parse.go:42", SubPath: "lib", Commit: scan.Commit, Fingerprint: "identity", CWE: "CWE-20"}
	if err := gdb.Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	return gdb, f
}

func TestRejectFindingSnapshotAndRollback(t *testing.T) {
	for _, failTable := range []string{"", "finding_reviews", "finding_histories"} {
		t.Run(failTable, func(t *testing.T) {
			gdb, f := feedbackFixture(t)
			latest := Scan{RepositoryID: f.RepositoryID, Status: ScanDone, Commit: "latest"}
			if err := gdb.Create(&latest).Error; err != nil {
				t.Fatal(err)
			}
			if err := gdb.Model(&f).Updates(map[string]any{"last_seen_scan_id": latest.ID, "last_seen_commit": latest.Commit}).Error; err != nil {
				t.Fatal(err)
			}
			if failTable != "" {
				if err := gdb.Exec(fmt.Sprintf("CREATE TRIGGER fail_review BEFORE INSERT ON %s BEGIN SELECT RAISE(ABORT, 'forced'); END", failTable)).Error; err != nil {
					t.Fatal(err)
				}
			}
			err := RejectFinding(gdb, f.ID, "false_positive", " checked guard ", " operator ")
			if (err != nil) != (failTable != "") {
				t.Fatalf("error = %v", err)
			}
			if failTable != "" {
				assertRejectionStored(t, gdb, f.ID, FindingNew, 0)
				return
			}
			reviews := assertRejectionStored(t, gdb, f.ID, FindingRejected, 1)
			r := reviews[0]
			if r.SourceScanID != latest.ID || r.SourceCommit != "latest" || r.FindingPath != "lib/parse.go" || r.FindingFingerprint != "identity" || r.CWE != "CWE-20" || r.Reason != "checked guard" || r.Reviewer != "operator" {
				t.Fatalf("bad snapshot: %+v", r)
			}
		})
	}
}

func assertRejectionStored(t *testing.T, gdb *gorm.DB, id uint, status FindingLifecycle, count int) []FindingReview {
	t.Helper()
	var stored Finding
	if err := gdb.First(&stored, id).Error; err != nil {
		t.Fatal(err)
	}
	reviews, err := ListFindingReviews(gdb, id)
	if err != nil {
		t.Fatal(err)
	}
	var histories int64
	if err := gdb.Model(&FindingHistory{}).Where("finding_id = ?", id).Count(&histories).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Status != status || len(reviews) != count || histories != int64(count) {
		t.Fatalf("unexpected rejection state: %s, %v, %d", stored.Status, reviews, histories)
	}
	return reviews
}

func TestFindingFeedbackExcludesLegacyAndOtherDecisions(t *testing.T) {
	for _, verdict := range []string{"legacy", "already_fixed", "uncertain"} {
		t.Run(verdict, func(t *testing.T) {
			gdb, f := feedbackFixture(t)
			if verdict == "legacy" {
				if err := WriteFindingField(gdb, f.ID, "status", string(FindingRejected), SourceAnalyst, ""); err != nil {
					t.Fatal(err)
				}
				if err := gdb.Create(&FindingReview{FindingID: f.ID, Verdict: "false_positive", Reason: "old reason", FindingPath: "lib/parse.go"}).Error; err != nil {
					t.Fatal(err)
				}
			} else if err := RejectFinding(gdb, f.ID, verdict, "reason", ""); err != nil {
				t.Fatal(err)
			}
			rows, err := FindingFeedbackForPaths(gdb, f.RepositoryID, []string{"lib/parse.go"})
			if err != nil || len(rows) != 0 {
				t.Fatalf("unexpected feedback: %+v, %v", rows, err)
			}
		})
	}
}

func TestRejectFindingValidation(t *testing.T) {
	gdb, f := feedbackFixture(t)
	for _, tc := range []struct{ verdict, reason string }{
		{"", "reason"}, {"true_positive", "reason"}, {"false_positive", " \n\t"}, {"uncertain", ""}, {"already_fixed", strings.Repeat("x", MaxReviewReasonBytes+1)},
	} {
		if err := RejectFinding(gdb, f.ID, tc.verdict, tc.reason, ""); !errors.Is(err, ErrInvalidFindingReview) {
			t.Fatalf("accepted invalid review: %v", err)
		}
	}
	if _, err := AddFindingReview(gdb, f.ID, "false_positive", "", "", ""); !errors.Is(err, ErrInvalidFindingReview) {
		t.Fatalf("empty FP reason accepted: %v", err)
	}
}

func TestFindingFeedbackLatestScopedAndBounded(t *testing.T) {
	gdb, f := feedbackFixture(t)
	if err := RejectFinding(gdb, f.ID, "false_positive", "guarded", ""); err != nil {
		t.Fatal(err)
	}
	rows, err := FindingFeedbackForPaths(gdb, f.RepositoryID, []string{"lib/parse.go"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("feedback=%v err=%v", rows, err)
	}
	for _, tc := range []struct {
		repo  uint
		paths []string
	}{
		{f.RepositoryID + 1, []string{"lib/parse.go"}}, {f.RepositoryID, []string{"other/parse.go"}}, {f.RepositoryID, nil},
	} {
		rows, err := FindingFeedbackForPaths(gdb, tc.repo, tc.paths)
		if err != nil || len(rows) != 0 {
			t.Fatalf("scope leak: %v %v", rows, err)
		}
	}
	if _, err := AddFindingReview(gdb, f.ID, "uncertain", "reconsider", "", ""); err != nil {
		t.Fatal(err)
	}
	rows, err = FindingFeedbackForPaths(gdb, f.RepositoryID, []string{"lib/parse.go"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("superseded feedback: %v %v", rows, err)
	}
	if err := RejectFinding(gdb, f.ID, "false_positive", "guarded again", ""); err != nil {
		t.Fatal(err)
	}
	if err := WriteFindingField(gdb, f.ID, "status", string(FindingNew), SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	rows, err = FindingFeedbackForPaths(gdb, f.RepositoryID, []string{"lib/parse.go"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("reopened feedback: %v %v", rows, err)
	}
	// An automatic later close must not resurrect a human decision that was
	// retired by reopening the finding.
	if err := WriteFindingField(gdb, f.ID, "status", string(FindingRejected), SourceSystem, "rescan"); err != nil {
		t.Fatal(err)
	}
	rows, err = FindingFeedbackForPaths(gdb, f.RepositoryID, []string{"lib/parse.go"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("retired feedback reappeared: %v %v", rows, err)
	}
	for i := 0; i < MaxFindingFeedback+1; i++ {
		copyFinding := f
		copyFinding.ID = 0
		if err := gdb.Create(&copyFinding).Error; err != nil {
			t.Fatal(err)
		}
		if err := RejectFinding(gdb, copyFinding.ID, "false_positive", "guarded", ""); err != nil {
			t.Fatal(err)
		}
	}
	rows, err = FindingFeedbackForPaths(gdb, f.RepositoryID, []string{"lib/parse.go"})
	if err != nil || len(rows) != MaxFindingFeedback {
		t.Fatalf("unbounded feedback: %d %v", len(rows), err)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].ReviewID >= rows[i-1].ReviewID {
			t.Fatal("not newest first")
		}
	}
}
