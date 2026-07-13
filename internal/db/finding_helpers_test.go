package db

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"
)

const severityField = "severity"

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	return gdb
}

func seedFinding(t *testing.T, gdb *gorm.DB) Finding {
	t.Helper()
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Kind: "skill", Status: ScanDone}
	gdb.Create(&scan)
	f := Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "t", Severity: "High", Status: FindingNew}
	gdb.Create(&f)
	return f
}

func TestConfidenceAtLeast(t *testing.T) {
	cases := []struct {
		got, min string
		want     bool
	}{
		{"high", "medium", true},
		{"medium", "medium", true},
		{"low", "medium", false},
		{"", "low", false},
		{"high", "", true},
		{"garbage", "low", false},
	}
	for _, tc := range cases {
		if r := ConfidenceAtLeast(tc.got, tc.min); r != tc.want {
			t.Errorf("ConfidenceAtLeast(%q, %q) = %v, want %v", tc.got, tc.min, r, tc.want)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	cases := []struct {
		got, threshold string
		want           bool
	}{
		{"Critical", "High", true},
		{"High", "High", true},
		{"Medium", "High", false},
		{"Low", "Critical", false},
		{"High", "", false},
		{"", "Low", false},
	}
	for _, tc := range cases {
		if r := SeverityAtLeast(tc.got, tc.threshold); r != tc.want {
			t.Errorf("SeverityAtLeast(%q, %q) = %v, want %v", tc.got, tc.threshold, r, tc.want)
		}
	}
}

func TestWriteFindingField_logsHistory(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	if err := WriteFindingField(gdb, f.ID, severityField, "Critical", SourceAnalyst, "me"); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.Severity != "Critical" {
		t.Errorf("severity = %q, want Critical", refreshed.Severity)
	}
	var history []FindingHistory
	gdb.Where("finding_id = ?", f.ID).Find(&history)
	if len(history) != 1 {
		t.Fatalf("history len = %d, want 1", len(history))
	}
	h := history[0]
	if h.Field != severityField || h.OldValue != "High" || h.NewValue != "Critical" || h.Source != SourceAnalyst || h.By != "me" {
		t.Errorf("history row: %+v", h)
	}
}

func TestWriteFindingField_noOpWhenUnchanged(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	if err := WriteFindingField(gdb, f.ID, severityField, "High", SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	var count int64
	gdb.Model(&FindingHistory{}).Where("finding_id = ?", f.ID).Count(&count)
	if count != 0 {
		t.Errorf("history rows = %d, want 0", count)
	}
}

func TestWriteFindingField_concurrentUpdatesKeepHistoryChain(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	// Hold both first reads until each writer has loaded the same value. The
	// second write must detect that its snapshot lost the race, reload, and
	// record a transition from the first writer's value.
	const callbackName = "test:barrier_finding_reads"
	var reads atomic.Int32
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	if err := gdb.Callback().Query().After("gorm:query").Register(callbackName, func(d *gorm.DB) {
		loaded, ok := d.Statement.Dest.(*Finding)
		if !ok || loaded.ID != f.ID || d.Error != nil {
			return
		}
		if reads.Add(1) <= 2 {
			arrived <- struct{}{}
			<-release
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := gdb.Callback().Query().Remove(callbackName); err != nil {
			t.Errorf("remove query barrier: %v", err)
		}
	})

	errs := make(chan error, 2)
	go func() {
		errs <- WriteFindingField(gdb, f.ID, severityField, "Critical", SourceAnalyst, "analyst-a")
	}()
	go func() {
		errs <- WriteFindingField(gdb, f.ID, severityField, "Medium", SourceModel, "worker-b")
	}()

	for range 2 {
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("timed out waiting for concurrent finding reads")
		}
	}
	close(release)
	for range 2 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("concurrent WriteFindingField: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for concurrent finding writes")
		}
	}

	var refreshed Finding
	if err := gdb.First(&refreshed, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	var history []FindingHistory
	if err := gdb.Where("finding_id = ? AND field = ?", f.ID, severityField).Order("id").Find(&history).Error; err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("history len = %d, want 2: %+v", len(history), history)
	}
	if history[0].OldValue != "High" {
		t.Errorf("first OldValue = %q, want High", history[0].OldValue)
	}
	if history[1].OldValue != history[0].NewValue {
		t.Errorf("history chain is broken: first transition %q -> %q, second %q -> %q",
			history[0].OldValue, history[0].NewValue, history[1].OldValue, history[1].NewValue)
	}
	if refreshed.Severity != history[1].NewValue {
		t.Errorf("final severity = %q, want last history value %q", refreshed.Severity, history[1].NewValue)
	}
	written := map[string]bool{
		history[0].NewValue: true,
		history[1].NewValue: true,
	}
	if !written["Critical"] || !written["Medium"] {
		t.Errorf("history transitions = %+v, want both concurrent values", history)
	}
}

func TestWriteFindingField_acceptsSuggestedRecipients(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	if err := WriteFindingField(gdb, f.ID, "suggested_recipients", "@alice (CODEOWNERS: crypto/*)", SourceModel, "disclose"); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.SuggestedRecipients != "@alice (CODEOWNERS: crypto/*)" {
		t.Errorf("suggested_recipients = %q", refreshed.SuggestedRecipients)
	}
}

func TestWriteFindingField_rejectsUnknownField(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	if err := WriteFindingField(gdb, f.ID, "does_not_exist", "x", SourceAnalyst, ""); err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestWriteFindingField_cvssVectorSyncsScore(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	const vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if err := WriteFindingField(gdb, f.ID, "cvss_vector", vec, SourceAnalyst, "me"); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.CVSSVector != vec {
		t.Errorf("vector = %q, want %q", refreshed.CVSSVector, vec)
	}
	if refreshed.CVSSScore != 9.8 {
		t.Errorf("score = %v, want 9.8", refreshed.CVSSScore)
	}
	var history []FindingHistory
	gdb.Where("finding_id = ?", f.ID).Order("id").Find(&history)
	if len(history) != 2 {
		t.Fatalf("history len = %d, want 2 (vector + score)", len(history))
	}
	if history[0].Field != "cvss_vector" || history[1].Field != "cvss_score" {
		t.Errorf("history fields = %q, %q", history[0].Field, history[1].Field)
	}
	if history[1].NewValue != "9.8" || history[1].Source != SourceAnalyst || history[1].By != "me" {
		t.Errorf("score history row: %+v", history[1])
	}
	if refreshed.CVSSv4Score != 0 || refreshed.CVSSv4Vector != "" {
		t.Errorf("v4 columns mutated by v3 write: vec=%q score=%v",
			refreshed.CVSSv4Vector, refreshed.CVSSv4Score)
	}
}

func TestWriteFindingField_cvssSameScoreKeepsScoreHistoryNoOp(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	const (
		oldVector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		newVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	)
	if err := gdb.Model(&Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
		"cvss_vector": oldVector,
		"cvss_score":  9.8,
	}).Error; err != nil {
		t.Fatal(err)
	}

	if err := WriteFindingField(gdb, f.ID, "cvss_vector", newVector, SourceAnalyst, "me"); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	if err := gdb.First(&refreshed, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if refreshed.CVSSVector != newVector || refreshed.CVSSScore != 9.8 {
		t.Fatalf("vector=%q score=%v, want %q and 9.8", refreshed.CVSSVector, refreshed.CVSSScore, newVector)
	}
	var history []FindingHistory
	if err := gdb.Where("finding_id = ?", f.ID).Order("id").Find(&history).Error; err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Field != "cvss_vector" {
		t.Fatalf("history = %+v, want only the vector transition", history)
	}
}

func TestWriteFindingField_cvssV4VectorSyncsScore(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	const vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	if err := WriteFindingField(gdb, f.ID, "cvss_v4_vector", vec, SourceAnalyst, "me"); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.CVSSv4Vector != vec {
		t.Errorf("v4 vector = %q, want %q", refreshed.CVSSv4Vector, vec)
	}
	if refreshed.CVSSv4Score <= 0 || refreshed.CVSSv4Score > 10 {
		t.Errorf("v4 score = %v, want > 0 (out of [0,10])", refreshed.CVSSv4Score)
	}
	if refreshed.CVSSScore != 0 {
		t.Errorf("v3 score = %v, want 0 (v4 write must not touch v3 column)", refreshed.CVSSScore)
	}
}

func TestWriteFindingField_cvssV4VectorInvalidClearsScore(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	gdb.Model(&Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
		"cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"cvss_v4_score":  9.3,
	})
	if err := WriteFindingField(gdb, f.ID, "cvss_v4_vector", "garbage", SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.CVSSv4Score != 0 {
		t.Errorf("v4 score = %v, want 0", refreshed.CVSSv4Score)
	}
}

func TestWriteFindingField_cvssVectorInvalidClearsScore(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	gdb.Model(&Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"cvss_score":  9.8,
	})

	if err := WriteFindingField(gdb, f.ID, "cvss_vector", "garbage", SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.CVSSScore != 0 {
		t.Errorf("score = %v, want 0 (vector unparseable clears stale score)", refreshed.CVSSScore)
	}
}

func TestWriteFindingField_cvssVectorEmptyClearsScore(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	gdb.Model(&Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"cvss_score":  9.8,
	})

	if err := WriteFindingField(gdb, f.ID, "cvss_vector", "", SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.CVSSScore != 0 {
		t.Errorf("score = %v, want 0", refreshed.CVSSScore)
	}
}

// failCreate registers a before-create callback that fails any insert for
// which pred returns true, simulating a mid-write database error. The
// returned func removes the injection.
func failCreate(t *testing.T, gdb *gorm.DB, pred func(*gorm.DB) bool) func() {
	t.Helper()
	const name = "test:fail_create"
	if err := gdb.Callback().Create().Before("gorm:create").Register(name, func(d *gorm.DB) {
		if pred(d) {
			_ = d.AddError(errors.New("injected insert failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := gdb.Callback().Create().Remove(name); err != nil {
			t.Fatal(err)
		}
	}
}

// If the history insert fails, the column update must roll back with it:
// the stored value is unchanged and no audit row is left behind.
func TestWriteFindingField_rollsBackOnHistoryFailure(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	remove := failCreate(t, gdb, func(d *gorm.DB) bool {
		return d.Statement.Table == "finding_histories"
	})
	if err := WriteFindingField(gdb, f.ID, severityField, "Critical", SourceAnalyst, "me"); err == nil {
		t.Fatal("expected error when the history insert fails")
	}
	remove()

	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.Severity != "High" {
		t.Errorf("severity = %q, want High (column update must roll back with the failed history row)", refreshed.Severity)
	}
	var count int64
	gdb.Model(&FindingHistory{}).Where("finding_id = ?", f.ID).Count(&count)
	if count != 0 {
		t.Errorf("history rows = %d, want 0", count)
	}
}

// A caller-owned transaction gets one savepoint-backed helper attempt. Even
// if that caller handles the error and commits its other work, the finding
// column cannot escape without its history row.
func TestWriteFindingField_existingTransactionKeepsFailedWriteAtomic(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	remove := failCreate(t, gdb, func(d *gorm.DB) bool {
		return d.Statement.Table == "finding_histories"
	})
	var writeErr error
	if err := gdb.Transaction(func(tx *gorm.DB) error {
		writeErr = WriteFindingField(tx, f.ID, severityField, "Critical", SourceAnalyst, "me")
		return nil
	}); err != nil {
		t.Fatalf("outer transaction: %v", err)
	}
	remove()
	if writeErr == nil {
		t.Fatal("expected helper error when the history insert fails")
	}

	var refreshed Finding
	if err := gdb.First(&refreshed, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if refreshed.Severity != "High" {
		t.Errorf("severity = %q, want High after helper savepoint rollback", refreshed.Severity)
	}
	var count int64
	if err := gdb.Model(&FindingHistory{}).Where("finding_id = ?", f.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("history rows = %d, want 0", count)
	}
}

// A cvss_vector write fans out to three database writes (the vector column +
// its history row, then the synced score column + its history row). Failing
// the score history insert — which happens last — must roll back the whole
// chain, so the vector never lands without a matching score.
func TestWriteFindingField_cvssSyncRollsBackAtomically(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	remove := failCreate(t, gdb, func(d *gorm.DB) bool {
		fh, ok := d.Statement.Dest.(*FindingHistory)
		return ok && fh.Field == "cvss_score"
	})
	const vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if err := WriteFindingField(gdb, f.ID, "cvss_vector", vec, SourceAnalyst, "me"); err == nil {
		t.Fatal("expected error when the cvss_score history insert fails")
	}
	remove()

	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.CVSSVector != "" || refreshed.CVSSScore != 0 {
		t.Errorf("vector=%q score=%v, want both cleared (vector column, vector history, and score must roll back together)",
			refreshed.CVSSVector, refreshed.CVSSScore)
	}
	var count int64
	gdb.Model(&FindingHistory{}).Where("finding_id = ?", f.ID).Count(&count)
	if count != 0 {
		t.Errorf("history rows = %d, want 0 (vector history must roll back with the failed score history)", count)
	}
}

func TestWriteFindingField_ghsaIDValidates(t *testing.T) {
	cases := []struct {
		value   string
		wantErr bool
	}{
		{"GHSA-jfh8-c2jp-5v3q", false},
		{"ghsa-jfh8-c2jp-5v3q", false}, // case-insensitive
		{"", false},                    // clearing is allowed
		{"GHSA-jfh8-c2jp", true},       // too few groups
		{"CVE-2026-12345", true},       // wrong prefix
		{"GHSA-jfh8-c2jp-5v3q-extra", true},
		{"not an id", true},
	}
	for _, tc := range cases {
		gdb := newTestDB(t)
		f := seedFinding(t, gdb)
		err := WriteFindingField(gdb, f.ID, "ghsa_id", tc.value, SourceAnalyst, "")
		if tc.wantErr && err == nil {
			t.Errorf("ghsa_id %q: expected error, got nil", tc.value)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ghsa_id %q: unexpected error: %v", tc.value, err)
		}
		if !tc.wantErr {
			var refreshed Finding
			gdb.First(&refreshed, f.ID)
			if refreshed.GHSAID != tc.value {
				t.Errorf("ghsa_id = %q, want %q", refreshed.GHSAID, tc.value)
			}
		}
	}
}

// editableFindingFields lists every API field name findingFieldAccessor
// accepts. Kept next to the round-trip test so a new accessor case that
// isn't added here trips the unknown-field check below.
var editableFindingFields = []string{
	"title", "severity", "status", "cwe", "location", "affected",
	"reachability", "quality_tier", "cve_id", "ghsa_id",
	"cvss_vector", "cvss_v4_vector", "fix_version", "fix_commit",
	"resolution", "disclosure_draft", "assignee",
	"suggested_fix", "suggested_fix_commit",
	"breaking_change", "breaking_change_rationale",
	"exploited_in_wild", "exploited_in_wild_evidence",
	"mitigation", "mitigation_semgrep",
	"release_tag", "release_url", "last_revalidate_verdict",
}

// fieldTestValue returns a value WriteFindingField will accept for field.
// Most fields are free text; a few have format constraints.
func fieldTestValue(field string) string {
	switch field {
	case "ghsa_id":
		return "GHSA-aaaa-bbbb-cccc"
	case "cvss_vector":
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	case "cvss_v4_vector":
		return "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	default:
		return "v-" + field
	}
}

func TestWriteFindingField_allEditableFieldsRoundTrip(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	for _, field := range editableFindingFields {
		want := fieldTestValue(field)
		if err := WriteFindingField(gdb, f.ID, field, want, SourceAnalyst, "tester"); err != nil {
			t.Fatalf("WriteFindingField(%q): %v", field, err)
		}
		var refreshed Finding
		gdb.First(&refreshed, f.ID)
		got, col, err := findingFieldAccessor(&refreshed, field)
		if err != nil {
			t.Fatalf("findingFieldAccessor(%q): %v", field, err)
		}
		if got != want {
			t.Errorf("field %q -> column %q = %q, want %q", field, col, got, want)
		}
	}

	if _, _, err := findingFieldAccessor(&f, "not-a-field"); err == nil {
		t.Error("findingFieldAccessor accepted an unknown field")
	}
}

func TestWriteFindingTimeField(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := WriteFindingTimeField(gdb, f.ID, "released_at", at, SourceModel, "release-watch"); err != nil {
		t.Fatalf("WriteFindingTimeField: %v", err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.ReleasedAt == nil || !refreshed.ReleasedAt.Equal(at) {
		t.Fatalf("ReleasedAt = %v, want %v", refreshed.ReleasedAt, at)
	}
	var hist []FindingHistory
	gdb.Where("finding_id = ? AND field = ?", f.ID, "released_at").Find(&hist)
	if len(hist) != 1 || hist[0].NewValue != at.Format(time.RFC3339) {
		t.Fatalf("history = %+v, want one row with NewValue=%q", hist, at.Format(time.RFC3339))
	}

	// Same value is a no-op: no second history row.
	if err := WriteFindingTimeField(gdb, f.ID, "released_at", at, SourceModel, "release-watch"); err != nil {
		t.Fatalf("WriteFindingTimeField (noop): %v", err)
	}
	gdb.Where("finding_id = ? AND field = ?", f.ID, "released_at").Find(&hist)
	if len(hist) != 1 {
		t.Errorf("noop write logged a second history row: %+v", hist)
	}

	// A non-UTC value is normalised to UTC, so a re-run reporting the same
	// instant in a different zone is still a no-op.
	if err := WriteFindingTimeField(gdb, f.ID, "released_at", at.In(time.FixedZone("PST", -8*3600)), SourceModel, ""); err != nil {
		t.Fatalf("WriteFindingTimeField (zone): %v", err)
	}
	gdb.Where("finding_id = ? AND field = ?", f.ID, "released_at").Find(&hist)
	if len(hist) != 1 {
		t.Errorf("same-instant different-zone write logged history: %+v", hist)
	}

	// Changing the value writes OldValue from the stored timestamp.
	later := at.Add(24 * time.Hour)
	if err := WriteFindingTimeField(gdb, f.ID, "released_at", later, SourceModel, ""); err != nil {
		t.Fatalf("WriteFindingTimeField (update): %v", err)
	}
	gdb.Where("finding_id = ? AND field = ?", f.ID, "released_at").Order("id").Find(&hist)
	if len(hist) != 2 || hist[1].OldValue != at.Format(time.RFC3339) {
		t.Errorf("update history = %+v, want OldValue=%q on second row", hist, at.Format(time.RFC3339))
	}

	if err := WriteFindingTimeField(gdb, f.ID, "not_a_field", at, SourceModel, ""); err == nil {
		t.Error("unknown timestamp field should error")
	}
	if err := WriteFindingTimeField(gdb, 999999, "released_at", at, SourceModel, ""); err == nil {
		t.Error("missing finding should error")
	}
}

func TestAddFindingCommunication(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	at := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	c, err := AddFindingCommunication(gdb, f.ID, "email", "outbound", "alice", "sent disclosure", "patch", at)
	if err != nil {
		t.Fatalf("AddFindingCommunication: %v", err)
	}
	if c.ID == 0 || c.Channel != "email" || c.Direction != "outbound" || !c.At.Equal(at) {
		t.Errorf("communication = %+v", c)
	}

	// Zero At defaults to now.
	c2, err := AddFindingCommunication(gdb, f.ID, "github", "inbound", "bot", "ack", "", time.Time{})
	if err != nil {
		t.Fatalf("AddFindingCommunication (zero at): %v", err)
	}
	if c2.At.IsZero() {
		t.Error("zero At should default to now")
	}

	var n int64
	gdb.Model(&FindingCommunication{}).Where("finding_id = ?", f.ID).Count(&n)
	if n != 2 {
		t.Errorf("communication count = %d, want 2", n)
	}
}

func TestAddFindingReference(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	ref, err := AddFindingReference(gdb, f.ID, "https://example.com/advisory", "advisory,upstream", "Upstream advisory")
	if err != nil {
		t.Fatalf("AddFindingReference: %v", err)
	}
	if ref.ID == 0 || ref.URL != "https://example.com/advisory" || ref.Tags != "advisory,upstream" {
		t.Errorf("reference = %+v", ref)
	}

	if _, err := AddFindingReference(gdb, f.ID, "   ", "", ""); err == nil {
		t.Error("empty URL should error")
	}

	var n int64
	gdb.Model(&FindingReference{}).Where("finding_id = ?", f.ID).Count(&n)
	if n != 1 {
		t.Errorf("reference count = %d, want 1 (empty rejected)", n)
	}
}

func TestAddFindingNote_rejectsEmpty(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	if _, err := AddFindingNote(gdb, f.ID, "   ", ""); err == nil {
		t.Error("expected error on empty note")
	}
}

func TestSetFindingLabels_replacesSet(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	if err := SetFindingLabels(gdb, f.ID, []string{"wontfix", "needs-info"}); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.Preload("Labels").First(&refreshed, f.ID)
	if len(refreshed.Labels) != 2 {
		t.Fatalf("labels len = %d, want 2", len(refreshed.Labels))
	}

	if err := SetFindingLabels(gdb, f.ID, []string{"duplicate"}); err != nil {
		t.Fatal(err)
	}
	var again Finding
	gdb.Preload("Labels").First(&again, f.ID)
	if len(again.Labels) != 1 || again.Labels[0].Name != "duplicate" {
		t.Errorf("expected only duplicate label, got %+v", again.Labels)
	}
}

func TestSeedDefaultLabels_idempotent(t *testing.T) {
	gdb := newTestDB(t)
	if err := SeedDefaultLabels(gdb); err != nil {
		t.Fatal(err)
	}
	var count1 int64
	gdb.Model(&FindingLabel{}).Count(&count1)
	if err := SeedDefaultLabels(gdb); err != nil {
		t.Fatal(err)
	}
	var count2 int64
	gdb.Model(&FindingLabel{}).Count(&count2)
	if count1 != count2 {
		t.Errorf("second seed inserted rows: %d -> %d", count1, count2)
	}
}
