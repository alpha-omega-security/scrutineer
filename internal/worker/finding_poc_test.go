package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/poc"
	"scrutineer/internal/queue"
)

type pocTestRunner struct {
	fakeRunner
	run func(SkillJob) SkillResult
}

func (r pocTestRunner) RunSkill(_ context.Context, job SkillJob, _ func(Event)) (SkillResult, error) {
	return r.run(job), nil
}

func writePoCTestFile(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

func runPoCTestJob(t *testing.T, w *Worker, scan *db.Scan) {
	t.Helper()
	if err := w.DB.Create(scan).Error; err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.wrap(w.doSkill)(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	if err := w.DB.First(scan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
}

func TestPoCCaptureSurvivesCleanupAndStagesForVerification(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/poc", Name: "poc"}
	audit := db.Skill{Name: "poc-audit", Body: "audit", OutputFile: "report.json", OutputKind: "findings", Active: true}
	verify := db.Skill{Name: "verify", Body: "verify", OutputFile: "report.json", OutputKind: "verify", Active: true}
	for _, row := range []any{&repo, &audit, &verify} {
		if err := gdb.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), PrepareRepoSrc: stubPrepareRepoSrc}
	payload := []byte{0, 255, '\n'}
	run := []byte("#!/bin/sh\nset -eu\ncat \"$1/target.txt\" inputs/payload.bin\n")
	w.Runner = pocTestRunner{run: func(job SkillJob) SkillResult {
		writePoCTestFile(t, job.WorkRoot, "poc/F1/run.sh", run)
		writePoCTestFile(t, job.WorkRoot, "poc/F1/inputs/payload.bin", payload)
		writePoCTestFile(t, job.WorkRoot, "poc/F1/README.md", []byte("Run sh run.sh /path/to/current/src\n"))
		return SkillResult{Commit: "original", Report: `{"findings":[{"id":"F1","title":"binary input bug","severity":"High","location":"parser.go:1","validation":"prose contains no files"}]}`}
	}}
	first := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &audit.ID}
	runPoCTestJob(t, w, &first)
	if first.Status != db.ScanDone {
		t.Fatalf("audit status %s: %s", first.Status, first.Error)
	}
	if _, err := os.Stat(w.workRoot(first.ID)); !os.IsNotExist(err) {
		t.Fatalf("workspace not cleaned up: %v", err)
	}
	var finding db.Finding
	if err := gdb.First(&finding).Error; err != nil {
		t.Fatal(err)
	}
	capture, err := db.LoadFindingPoC(gdb, finding.ID)
	if err != nil || capture == nil || capture.ScanID != first.ID || capture.Commit != "original" {
		t.Fatalf("capture = %+v, %v", capture, err)
	}
	verified := false
	w.Runner = pocTestRunner{run: func(job SkillJob) SkillResult {
		verified = true
		data, err := os.ReadFile(filepath.Join(job.WorkRoot, "poc/inputs/payload.bin"))
		if err != nil || !bytes.Equal(data, payload) {
			t.Fatalf("staged payload = %v, %v", data, err)
		}
		manifest, err := os.ReadFile(filepath.Join(job.WorkRoot, "poc-manifest.json"))
		if err != nil || !strings.Contains(string(manifest), `"commit": "original"`) {
			t.Fatalf("manifest = %s, %v", manifest, err)
		}
		writePoCTestFile(t, job.WorkRoot, "src/target.txt", []byte("new branch\n"))
		t.Run("execute", func(t *testing.T) {
			shell, err := exec.LookPath("sh")
			if err != nil {
				t.Skip("sh unavailable")
			}
			cmd := exec.CommandContext(t.Context(), shell, "run.sh", "../src")
			cmd.Dir = filepath.Join(job.WorkRoot, "poc")
			output, err := cmd.CombinedOutput()
			if err != nil || !bytes.Equal(output, append([]byte("new branch\n"), payload...)) {
				t.Fatalf("staged reproduction = %q, %v", output, err)
			}
		})
		writePoCTestFile(t, job.WorkRoot, "poc/inputs/payload.bin", []byte("modified during verification"))
		return SkillResult{Commit: "new-branch", Report: verificationReport(t, "inconclusive", nil)}
	}}
	second := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &verify.ID, FindingID: &finding.ID, Ref: "new-branch"}
	runPoCTestJob(t, w, &second)
	if !verified || second.Status != db.ScanDone {
		t.Fatalf("verify invoked=%v, status=%s: %s", verified, second.Status, second.Error)
	}
	retained, err := db.LoadFindingPoC(gdb, finding.ID)
	if err != nil || !bytes.Equal(retained.Files, capture.Files) {
		t.Fatalf("verification changed original capture: %v", err)
	}
}

func TestCapturePoCFilesRejectsLinkedRoot(t *testing.T) {
	for _, relative := range []string{"poc", "poc/F1"} {
		t.Run(relative, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			writePoCTestFile(t, outside, "run.sh", []byte("secret"))
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, relative)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, relative)); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}
			if files, err := capturePoCFiles(root, "F1"); err == nil || files != nil {
				t.Fatalf("accepted linked capture root: %+v, %v", files, err)
			}
		})
	}
}

func TestPoCCaptureFailureKeepsAllReportedFindings(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/capture-failure", Name: "capture-failure"}
	skill := db.Skill{Name: "capture-failure", Body: "audit", OutputFile: "report.json", OutputKind: "findings", Active: true}
	for _, row := range []any{&repo, &skill} {
		if err := gdb.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), PrepareRepoSrc: stubPrepareRepoSrc}
	created, finalized := 0, 0
	w.OnFindingCreated = func(*db.Scan, *db.Finding) { created++ }
	w.OnScanFinalized = func(*db.Scan) { finalized++ }
	const report = `{"findings":[{"id":"F1","title":"first","severity":"High","location":"parser.go:1"},{"id":"F2","title":"second","severity":"High","location":"parser.go:2"}]}`
	w.Runner = pocTestRunner{run: func(job SkillJob) SkillResult {
		writePoCTestFile(t, job.WorkRoot, "poc/F1/large", make([]byte, poc.MaxFileBytes+1))
		writePoCTestFile(t, job.WorkRoot, "poc/F2/run.sh", []byte("echo second\n"))
		return SkillResult{Report: report}
	}}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	runPoCTestJob(t, w, &scan)
	if scan.Status != db.ScanDone || scan.Error != "" || scan.FindingsCount != 2 {
		t.Fatalf("scan status=%s, findings=%d: %s", scan.Status, scan.FindingsCount, scan.Error)
	}
	if scan.Report != report || !strings.Contains(scan.Log, "capture PoC") || created != 2 || finalized != 1 {
		t.Fatalf("capture warning lost report or callbacks: report=%q log=%q created=%d finalized=%d", scan.Report, scan.Log, created, finalized)
	}
	var count int64
	if err := gdb.Model(&db.Finding{}).Where("scan_id = ?", scan.ID).Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("capture failure dropped findings: count=%d, %v", count, err)
	}
	if err := gdb.Model(&db.FindingPoC{}).Where("scan_id = ?", scan.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("capture failure skipped later capture: count=%d, %v", count, err)
	}
}

func TestStreamedCaptureIsImmutableAndFailureKeepsFinding(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/stream", Name: "stream"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "poc-audit", Status: db.ScanRunning, Commit: "abc"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: gdb, DataDir: t.TempDir()}
	raw := []byte(`{"id":"F1","title":"streamed bug","severity":"High","location":"parser.go:1"}`)
	writePoCTestFile(t, w.workRoot(scan.ID), "poc/F1/run.sh", []byte("original"))
	finding, err := w.PersistStreamedFinding(&scan, raw)
	if err != nil {
		t.Fatal(err)
	}
	writePoCTestFile(t, w.workRoot(scan.ID), "poc/F1/run.sh", []byte("changed"))
	if _, err := w.PersistStreamedFinding(&scan, raw); err != nil {
		t.Fatal(err)
	}
	row, err := db.LoadFindingPoC(gdb, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	files, err := poc.Decode(row.Files)
	if err != nil || string(files[0].Data) != "original" {
		t.Fatalf("original capture replaced: %+v, %v", files, err)
	}
	writePoCTestFile(t, w.workRoot(scan.ID), "poc/F2/large", make([]byte, poc.MaxFileBytes+1))
	if _, err := w.PersistStreamedFinding(&scan, []byte(`{"id":"F2","title":"oversize PoC","severity":"High","location":"parser.go:2"}`)); err == nil {
		t.Fatal("oversize capture accepted")
	}
	var count int64
	if err := gdb.Model(&db.Finding{}).Where("title = ?", "oversize PoC").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("capture failure lost finding: count=%d, %v", count, err)
	}
}

func TestCaptureWarningPreservesAdvisoryVerdictsAndFailOn(t *testing.T) {
	for _, failOn := range []string{"", "High"} {
		t.Run("fail_on="+failOn, func(t *testing.T) {
			gdb := dbtest.Open(t)
			repo := db.Repository{URL: "https://example.com/capture-audit", Name: "capture-audit"}
			skill := db.Skill{Name: "capture-audit", Body: "audit", OutputFile: "report.json", OutputKind: "advisory_audit", Active: true, FailOn: failOn}
			for _, row := range []any{&repo, &skill} {
				if err := gdb.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), PrepareRepoSrc: stubPrepareRepoSrc}
			finalized := 0
			w.OnScanFinalized = func(*db.Scan) { finalized++ }
			const report = `{"audits":[{"advisory_uuid":"test-advisory","status":"bypass","evidence":"Reproduction fires.","finding_ids":["F1"]}],"findings":[{"id":"F1","title":"bypass","severity":"High","location":"parser.go:1"}]}`
			w.Runner = pocTestRunner{run: func(job SkillJob) SkillResult {
				writePoCTestFile(t, job.WorkRoot, "poc/F1/large", make([]byte, poc.MaxFileBytes+1))
				return SkillResult{Report: report}
			}}
			scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
			runPoCTestJob(t, w, &scan)
			wantStatus := db.ScanDone
			if failOn != "" {
				wantStatus = db.ScanFailed
			}
			if scan.Status != wantStatus || scan.Report != report || finalized != 1 {
				t.Fatalf("scan=%+v, finalized=%d", scan, finalized)
			}
			if strings.Contains(scan.Error, "capture PoC") || !strings.Contains(scan.Log, "capture PoC") {
				t.Fatalf("capture warning was lost or replaced fail_on: error=%q log=%q", scan.Error, scan.Log)
			}
			var finding db.Finding
			if err := gdb.Where("scan_id = ?", scan.ID).First(&finding).Error; err != nil {
				t.Fatal(err)
			}
			var audit db.AdvisoryAudit
			if err := gdb.Where("scan_id = ?", scan.ID).First(&audit).Error; err != nil {
				t.Fatal(err)
			}
			if audit.Status != "bypass" || audit.FindingIDs != strconv.FormatUint(uint64(finding.ID), 10) {
				t.Fatalf("audit verdict lost finding: %+v", audit)
			}
		})
	}
}
