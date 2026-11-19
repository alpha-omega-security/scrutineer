package worker

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

func identityWorker(t *testing.T) (*Worker, func(string) *db.Scan) {
	t.Helper()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://x/identity", Name: "identity"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	mkScan := func(commit string) *db.Scan {
		s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanDone, Commit: commit}
		gdb.Create(s)
		return s
	}
	return w, mkScan
}

func TestParseFindingsOutput_storesIdentity(t *testing.T) {
	w, mkScan := identityWorker(t)
	report := `{"findings":[{"id":"F1","title":"Zip slip","severity":"High","cwe":"CWE-22","location":"src/unzip.go:42",
		"rule":"  Path-Traversal ","anchor":"archive entry names\n   joined to the root  without rejecting ..","instance":"extract API"}]}`
	scan := mkScan("abc")
	if err := w.parseFindingsOutput(&db.Skill{}, scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var f db.Finding
	w.DB.First(&f)
	if f.Rule != "path-traversal" || f.Anchor != "archive entry names joined to the root without rejecting .." || f.Instance != "extract API" {
		t.Fatalf("identity = %q / %q / %q", f.Rule, f.Anchor, f.Instance)
	}
	var obs db.FindingObservation
	w.DB.Where("finding_id = ?", f.ID).First(&obs)
	if obs.Rule != f.Rule || obs.Anchor != f.Anchor || obs.Instance != f.Instance {
		t.Fatalf("observation identity = %q / %q / %q", obs.Rule, obs.Anchor, obs.Instance)
	}
	// The identity is recorded but does not drive matching yet.
	if want := db.FingerprintFinding("security-deep-dive", "", "CWE-22", "src/unzip.go:42", "Zip slip"); f.Fingerprint != want {
		t.Fatalf("fingerprint = %s, want the location fingerprint %s", f.Fingerprint, want)
	}
}

func TestParseFindingsOutput_identityFillsOnlyAnEmptyRow(t *testing.T) {
	w, mkScan := identityWorker(t)
	emit := func(Event) {}
	plain := `{"findings":[{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"src/users.rb:42"}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("a"), plain, emit); err != nil {
		t.Fatal(err)
	}
	labelled := `{"findings":[{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"src/users.rb:50",
		"rule":"sql-injection","anchor":"user filter is concatenated into the query"}]}`
	scan2 := mkScan("b")
	if err := w.parseFindingsOutput(&db.Skill{}, scan2, labelled, emit); err != nil {
		t.Fatal(err)
	}
	var f db.Finding
	w.DB.First(&f)
	if f.Rule != "sql-injection" || f.Anchor != "user filter is concatenated into the query" {
		t.Fatalf("row without an identity did not take the reported one: %q / %q", f.Rule, f.Anchor)
	}

	relabelled := `{"findings":[{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"src/users.rb:51",
		"rule":"sqli","anchor":"reworded anchor"}]}`
	scan3 := mkScan("c")
	if err := w.parseFindingsOutput(&db.Skill{}, scan3, relabelled, emit); err != nil {
		t.Fatal(err)
	}
	w.DB.First(&f, f.ID)
	if f.Rule != "sql-injection" || f.Anchor != "user filter is concatenated into the query" {
		t.Fatalf("a recorded identity was overwritten by a later scan: %q / %q", f.Rule, f.Anchor)
	}
	// Each scan's own label stays on its observation.
	var obs db.FindingObservation
	w.DB.Where("finding_id = ? AND scan_id = ?", f.ID, scan3.ID).First(&obs)
	if obs.Rule != "sqli" || obs.Anchor != "reworded anchor" {
		t.Fatalf("observation identity = %q / %q, want the third scan's labels", obs.Rule, obs.Anchor)
	}
}

func TestIdentityFieldCapsLength(t *testing.T) {
	long := strings.Repeat("é", maxIdentityAnchorRunes+10)
	if got := identityField(long, maxIdentityAnchorRunes); len([]rune(got)) != maxIdentityAnchorRunes {
		t.Fatalf("capped length = %d runes", len([]rune(got)))
	}
	if got := identityField("  a \t b\n c ", 10); got != "a b c" {
		t.Fatalf("collapsed = %q", got)
	}
	if got := identityField("   ", 10); got != "" {
		t.Fatalf("blank = %q", got)
	}
}
