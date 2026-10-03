package db

import "testing"

func TestFeedbackConfirmationUniquePerReviewAndScan(t *testing.T) {
	gdb, f := feedbackFixture(t)
	c := FeedbackConfirmation{ReviewID: 1, ScanID: 2, FindingID: f.ID, Commit: "c1"}
	if ok, err := RecordFeedbackConfirmation(gdb, &c); err != nil || !ok {
		t.Fatalf("first insert: %v %v", ok, err)
	}
	dup := FeedbackConfirmation{ReviewID: 1, ScanID: 2, FindingID: f.ID, Commit: "c1"}
	if ok, err := RecordFeedbackConfirmation(gdb, &dup); err != nil || ok {
		t.Fatalf("duplicate: inserted=%v err=%v", ok, err)
	}
	other := FeedbackConfirmation{ReviewID: 1, ScanID: 3, FindingID: f.ID, Commit: "c2"}
	if ok, err := RecordFeedbackConfirmation(gdb, &other); err != nil || !ok {
		t.Fatalf("new scan: %v %v", ok, err)
	}
	rows, err := FeedbackConfirmations(gdb, 1)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows = %+v, %v", rows, err)
	}
}

func TestDistinctConfirmedCommitsExcludesSource(t *testing.T) {
	rows := []FeedbackConfirmation{
		{Commit: "src"}, {Commit: "a"}, {Commit: "a"}, {Commit: "b"}, {Commit: ""},
	}
	if got := DistinctConfirmedCommits(rows, "src"); got != 2 {
		t.Fatalf("distinct = %d, want 2", got)
	}
}

func TestEligibleFeedbackForReviews(t *testing.T) {
	gdb, f := feedbackFixture(t)
	if err := RejectFinding(gdb, f.ID, "false_positive", "guarded", ""); err != nil {
		t.Fatal(err)
	}
	reviews, err := ListFindingReviews(gdb, f.ID)
	if err != nil || len(reviews) != 1 {
		t.Fatalf("reviews = %v, %v", reviews, err)
	}
	id := reviews[0].ID
	rows, err := EligibleFeedbackForReviews(gdb, f.RepositoryID, "lib/parse.go", []uint{id, id + 100})
	if err != nil || len(rows) != 1 || rows[0].ReviewID != id || rows[0].SourceCommit != "original" {
		t.Fatalf("eligible = %+v, %v", rows, err)
	}
	if rows, _ := EligibleFeedbackForReviews(gdb, f.RepositoryID, "other/parse.go", []uint{id}); len(rows) != 0 {
		t.Fatalf("other path eligible: %+v", rows)
	}
	if rows, _ := EligibleFeedbackForReviews(gdb, f.RepositoryID+1, "lib/parse.go", []uint{id}); len(rows) != 0 {
		t.Fatalf("other repo eligible: %+v", rows)
	}
	ids, err := EligibleFeedbackReviewIDs(gdb, f.RepositoryID)
	if err != nil || !ids[id] || len(ids) != 1 {
		t.Fatalf("ids = %v, %v", ids, err)
	}
	// Superseded by a newer review.
	if _, err := AddFindingReview(gdb, f.ID, "uncertain", "reconsider", "", ""); err != nil {
		t.Fatal(err)
	}
	if rows, _ := EligibleFeedbackForReviews(gdb, f.RepositoryID, "lib/parse.go", []uint{id}); len(rows) != 0 {
		t.Fatalf("superseded eligible: %+v", rows)
	}
	if ids, _ := EligibleFeedbackReviewIDs(gdb, f.RepositoryID); len(ids) != 0 {
		t.Fatalf("superseded ids: %v", ids)
	}
}

func TestEligibleFeedbackForReviewsRejectsReopenedAndOtherVerdicts(t *testing.T) {
	gdb, f := feedbackFixture(t)
	if err := RejectFinding(gdb, f.ID, "already_fixed", "fixed upstream", ""); err != nil {
		t.Fatal(err)
	}
	reviews, _ := ListFindingReviews(gdb, f.ID)
	if rows, _ := EligibleFeedbackForReviews(gdb, f.RepositoryID, "lib/parse.go", []uint{reviews[0].ID}); len(rows) != 0 {
		t.Fatalf("already_fixed eligible: %+v", rows)
	}
	if err := RejectFinding(gdb, f.ID, "false_positive", "guarded", ""); err != nil {
		t.Fatal(err)
	}
	reviews, _ = ListFindingReviews(gdb, f.ID)
	id := reviews[0].ID
	if err := WriteFindingField(gdb, f.ID, "status", string(FindingNew), SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	if rows, _ := EligibleFeedbackForReviews(gdb, f.RepositoryID, "lib/parse.go", []uint{id}); len(rows) != 0 {
		t.Fatalf("reopened eligible: %+v", rows)
	}
}
