package db

import (
	"path/filepath"
	"testing"

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
