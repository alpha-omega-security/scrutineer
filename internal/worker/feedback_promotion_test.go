package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

type promotionFixture struct {
	t        *testing.T
	w        *Worker
	repo     db.Repository
	source   db.Finding
	reviewID uint
	events   []Event
}

const promotionModel = `{"description":"d","reflection_notes":[{"summary":"kept"}],"known_non_findings":[{"reported_as":"model item","why_safe":"model"}]}`

func newPromotionFixture(t *testing.T, model string) *promotionFixture {
	t.Helper()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "file:///promo", Name: "promo", ThreatModel: model}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, Commit: "src"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	source := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "overflow", Severity: "High", Status: db.FindingNew, Location: "parse.go:10", Commit: "src", CWE: "CWE-787"}
	if err := gdb.Create(&source).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.RejectFinding(gdb, source.ID, "false_positive", "length is bounded at parse.go:5", "analyst"); err != nil {
		t.Fatal(err)
	}
	reviews, err := db.ListFindingReviews(gdb, source.ID)
	if err != nil || len(reviews) != 1 {
		t.Fatalf("reviews = %v, %v", reviews, err)
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return &promotionFixture{t: t, w: w, repo: repo, source: source, reviewID: reviews[0].ID}
}

func (p *promotionFixture) newFinding(location string) db.Finding {
	p.t.Helper()
	f := db.Finding{ScanID: p.source.ScanID, RepositoryID: p.repo.ID, Title: "again", Severity: "High", Status: db.FindingNew, Location: location}
	if err := p.w.DB.Create(&f).Error; err != nil {
		p.t.Fatal(err)
	}
	return f
}

func (p *promotionFixture) newScan(commit string, f db.Finding) *db.Scan {
	p.t.Helper()
	scan := &db.Scan{RepositoryID: p.repo.ID, Kind: JobSkill, SkillName: "revalidate", Commit: commit, FindingID: &f.ID}
	if err := p.w.DB.Create(scan).Error; err != nil {
		p.t.Fatal(err)
	}
	return scan
}

func (p *promotionFixture) parse(scan *db.Scan, report string) {
	p.t.Helper()
	p.events = nil
	if err := p.w.parseRevalidateOutput(scan, report, func(e Event) { p.events = append(p.events, e) }); err != nil {
		p.t.Fatal(err)
	}
}

func (p *promotionFixture) cite(commit string) {
	p.t.Helper()
	f := p.newFinding("parse.go:20")
	p.parse(p.newScan(commit, f), fmt.Sprintf(`{"verdict":"false_positive","reason":"bound still at parse.go:5","analyst_feedback_ids":[%d]}`, p.reviewID))
}

func (p *promotionFixture) model() string {
	p.t.Helper()
	var repo db.Repository
	if err := p.w.DB.First(&repo, p.repo.ID).Error; err != nil {
		p.t.Fatal(err)
	}
	return repo.ThreatModel
}

func (p *promotionFixture) confirmations() int64 {
	p.t.Helper()
	var n int64
	if err := p.w.DB.Model(&db.FeedbackConfirmation{}).Count(&n).Error; err != nil {
		p.t.Fatal(err)
	}
	return n
}

func promotedItems(t *testing.T, model string) []map[string]any {
	t.Helper()
	var obj struct {
		Items []map[string]any `json:"known_non_findings"`
	}
	if err := json.Unmarshal([]byte(model), &obj); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, item := range obj.Items {
		if _, ok := item["promoted_from"]; ok {
			out = append(out, item)
		}
	}
	return out
}

func TestFeedbackPromotedAfterThreeDistinctCommits(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	p.cite("c1")
	p.cite("c2")
	if len(promotedItems(t, p.model())) != 0 {
		t.Fatal("promoted before threshold")
	}
	p.cite("c3")
	model := p.model()
	items := promotedItems(t, model)
	if len(items) != 1 {
		t.Fatalf("promoted = %d in %s", len(items), model)
	}
	prov := items[0]["promoted_from"].(map[string]any)
	if uint(prov["review_id"].(float64)) != p.reviewID || prov["source_commit"] != "src" || len(prov["confirmations"].([]any)) != 3 {
		t.Fatalf("provenance = %v", prov)
	}
	if items[0]["why_safe"] != "length is bounded at parse.go:5" || !strings.Contains(items[0]["reported_as"].(string), "parse.go") {
		t.Fatalf("entry = %v", items[0])
	}
	for _, want := range []string{`"model item"`, `"reflection_notes"`, `"kept"`, `"description"`} {
		if !strings.Contains(model, want) {
			t.Fatalf("lost %s: %s", want, model)
		}
	}
	// A fourth confirmation replaces rather than duplicates.
	p.cite("c4")
	if len(promotedItems(t, p.model())) != 1 {
		t.Fatalf("duplicate promotion: %s", p.model())
	}
}

func TestFeedbackNotPromotedWithoutIndependentCommits(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	for range 4 {
		p.cite("same")
	}
	for range 4 {
		p.cite("src")
	}
	if p.confirmations() != 8 {
		t.Fatalf("confirmations = %d", p.confirmations())
	}
	if len(promotedItems(t, p.model())) != 0 {
		t.Fatalf("promoted: %s", p.model())
	}
}

// The source commit is not an independent re-check, so two independent
// commits plus the source commit stay one short of the threshold. A third
// independent commit is what promotes.
func TestFeedbackSourceCommitDoesNotReachThreshold(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	p.cite("c1")
	p.cite("c2")
	p.cite("src")
	if len(promotedItems(t, p.model())) != 0 {
		t.Fatalf("promoted with the source commit counted: %s", p.model())
	}
	p.cite("c3")
	if len(promotedItems(t, p.model())) != 1 {
		t.Fatalf("not promoted after three independent commits: %s", p.model())
	}
}

func TestFeedbackRecordsNothingForOtherCitations(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	f := p.newFinding("parse.go:20")
	relied := fmt.Sprintf(`"analyst_feedback_ids":[%d]`, p.reviewID)
	other := p.newFinding("other.go:1")
	p.parse(p.newScan("c1", f), `{"verdict":"true_positive","reason":"r",`+relied+`}`)
	p.parse(p.newScan("c2", f), `{"verdict":"false_positive","reason":"no feedback relied on"}`)
	p.parse(p.newScan("c3", f), `{"verdict":"false_positive","reason":"r","analyst_feedback_ids":[9999]}`)
	p.parse(p.newScan("c4", other), `{"verdict":"false_positive","reason":"r",`+relied+`}`)
	p.parse(p.newScan("", f), `{"verdict":"false_positive","reason":"r",`+relied+`}`)
	srcScan := p.newScan("c5", p.source)
	p.parse(srcScan, `{"verdict":"false_positive","reason":"r",`+relied+`}`)
	// A reason that names the decision while saying it was not reused records
	// nothing: only the structured field counts.
	p.parse(p.newScan("c6", f), fmt.Sprintf(`{"verdict":"false_positive","reason":"I did not reuse analyst_feedback: %d, the guard is gone"}`, p.reviewID))
	if p.confirmations() != 0 {
		t.Fatalf("confirmations = %d, want 0", p.confirmations())
	}
}

func TestFeedbackNoThreatModelNoPromotionNoError(t *testing.T) {
	for _, model := range []string{"", "[1,2]"} {
		p := newPromotionFixture(t, model)
		p.cite("c1")
		p.cite("c2")
		p.cite("c3")
		if got := p.model(); got != model {
			t.Fatalf("model changed to %q", got)
		}
		for _, e := range p.events {
			if e.Kind == KindError {
				t.Fatalf("unexpected error event %q", e.Text)
			}
		}
		// Once a model object exists a later confirmation promotes.
		if err := p.w.DB.Model(&db.Repository{}).Where("id = ?", p.repo.ID).Update("threat_model", `{}`).Error; err != nil {
			t.Fatal(err)
		}
		p.cite("c4")
		if len(promotedItems(t, p.model())) != 1 {
			t.Fatalf("retry did not promote: %s", p.model())
		}
	}
}

func TestFeedbackRetriedScanDoesNotDoubleCount(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	f := p.newFinding("parse.go:20")
	scan := p.newScan("c1", f)
	report := fmt.Sprintf(`{"verdict":"false_positive","reason":"r","analyst_feedback_ids":[%d,%d]}`, p.reviewID, p.reviewID)
	p.parse(scan, report)
	p.parse(scan, report)
	if p.confirmations() != 1 {
		t.Fatalf("confirmations = %d, want 1", p.confirmations())
	}
}

func TestFeedbackBookkeepingFailureKeepsVerdict(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	if err := p.w.DB.Migrator().DropTable(&db.FeedbackConfirmation{}); err != nil {
		t.Fatal(err)
	}
	f := p.newFinding("parse.go:20")
	p.parse(p.newScan("c1", f), fmt.Sprintf(`{"verdict":"false_positive","reason":"r","analyst_feedback_ids":[%d]}`, p.reviewID))
	var errs int
	for _, e := range p.events {
		if e.Kind == KindError {
			errs++
		}
	}
	var got db.Finding
	if err := p.w.DB.First(&got, f.ID).Error; err != nil || errs != 1 || got.LastRevalidateVerdict != "false_positive" {
		t.Fatalf("errs=%d verdict=%q err=%v", errs, got.LastRevalidateVerdict, err)
	}
}

func TestStagedThreatModelDropsRetiredPromotion(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	p.cite("c1")
	p.cite("c2")
	p.cite("c3")
	stage := func() string { return stagePromotionModel(t, p, deepDiveSkillName) }
	if staged := stage(); len(promotedItems(t, staged)) != 1 {
		t.Fatalf("active promotion missing: %s", staged)
	}
	if err := db.WriteFindingField(p.w.DB, p.source.ID, "status", string(db.FindingNew), db.SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	staged := stage()
	if len(promotedItems(t, staged)) != 0 || !strings.Contains(staged, `"model item"`) {
		t.Fatalf("staged = %s", staged)
	}
}

// The analyst can reopen a decision after confirmFeedback selected it. The
// compare-and-swap re-reads eligibility, so the entry is not merged and a
// retired entry already in the contract is tidied away.
func TestPromotionSkippedWhenReviewRetiredBeforeMerge(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	stale := fmt.Sprintf(`{"known_non_findings":[{"reported_as":"model","why_safe":"m"},{"reported_as":"old","why_safe":"w","promoted_from":{"review_id":%d}}]}`, p.reviewID)
	review := db.FindingFeedback{ReviewID: p.reviewID, FindingID: p.source.ID, SourceCommit: "src", Path: "parse.go", Reason: "bounded"}
	if err := db.WriteFindingField(p.w.DB, p.source.ID, "status", string(db.FindingNew), db.SourceAnalyst, "analyst"); err != nil {
		t.Fatal(err)
	}
	if err := p.w.DB.Model(&db.Repository{}).Where("id = ?", p.repo.ID).Update("threat_model", stale).Error; err != nil {
		t.Fatal(err)
	}
	var events []Event
	if err := p.w.promoteFeedback(p.repo.ID, review, nil, func(e Event) { events = append(events, e) }); err != nil {
		t.Fatal(err)
	}
	if got := p.model(); strings.Contains(got, "promoted_from") || !strings.Contains(got, `"model"`) {
		t.Fatalf("retired review merged or model item lost: %s", got)
	}
	if len(events) != 1 || !strings.Contains(events[0].Text, "no longer eligible") {
		t.Fatalf("events = %+v, want a skipped promotion", events)
	}
}

// old_threat_model.json comes from a raw report, so it must carry no promotion.
func TestStageOldThreatModelStripsPromotions(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	report := fmt.Sprintf(`{"known_non_findings":[{"reported_as":"model","why_safe":"m"},{"reported_as":"p","why_safe":"w","promoted_from":{"review_id":%d}}]}`, p.reviewID)
	tm := db.Scan{RepositoryID: p.repo.ID, Kind: JobSkill, SkillName: "threat-model", Status: db.ScanDone, Report: report}
	if err := p.w.DB.Create(&tm).Error; err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	diff := db.Scan{RepositoryID: p.repo.ID, Kind: JobSkill, SkillName: "threat-model"}
	if err := p.w.DB.Create(&diff).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := p.w.stageOldThreatModel(work, &diff); err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(filepath.Join(work, oldThreatModelFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(staged), "promoted_from") || !strings.Contains(string(staged), `"model"`) {
		t.Fatalf("staged old model = %s", staged)
	}
}

// stagePromotionModel stages the fixture repository for skillName and returns
// the threat_model.json the skill would read.
func stagePromotionModel(t *testing.T, p *promotionFixture, skillName string) string {
	t.Helper()
	work := t.TempDir()
	var repo db.Repository
	if err := p.w.DB.First(&repo, p.repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Repository: repo}
	skill := db.Skill{Name: skillName, Body: "# Test", Source: "ui"}
	if _, err := p.w.stageWorkspace(context.Background(), work, filepath.Join(work, ".claude", "skills", skillName), &scan, &skill); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(work, "threat_model.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The threat-model skill never sees a promotion, even an eligible one, so it
// cannot re-emit it without promoted_from and launder it into the contract.
func TestThreatModelSkillStagedWithoutPromotions(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	p.cite("c1")
	p.cite("c2")
	p.cite("c3")
	if staged := stagePromotionModel(t, p, deepDiveSkillName); len(promotedItems(t, staged)) != 1 {
		t.Fatalf("consumer skill lost the eligible promotion: %s", staged)
	}
	staged := stagePromotionModel(t, p, threatModelSkillName)
	if strings.Contains(staged, "promoted_from") || len(promotedItems(t, staged)) != 0 {
		t.Fatalf("threat-model skill saw a promotion: %s", staged)
	}
	if !strings.Contains(staged, `"model item"`) {
		t.Fatalf("threat-model skill lost model-authored items: %s", staged)
	}
}
