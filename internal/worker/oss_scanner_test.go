package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

const ossRepoURL = "https://github.com/example/project"

func writeOSSFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ossFixtureRegistry(t *testing.T) string {
	t.Helper()
	reg := t.TempDir()
	writeOSSFile(t, reg, "projects/proj/project.yaml", "repo: "+ossRepoURL+"\n")
	writeOSSFile(t, reg, "projects/proj/threat_model.md", "registry tm")
	writeOSSFile(t, reg, "projects/proj/Dockerfile", "FROM scratch")
	return reg
}

func ossWorker(reg string, err error) *Worker {
	w := &Worker{OSSScannerRegistry: "https://example.test/registry"}
	w.PrepareOSSScannerRegistry = func(context.Context, string, func(Event)) (string, error) { return reg, err }
	return w
}

func ossScan() *db.Scan {
	return &db.Scan{Repository: db.Repository{URL: ossRepoURL}}
}

func noEmit(Event) {}

func TestStageOSSScannerThreatModel(t *testing.T) {
	work := t.TempDir()
	w := ossWorker(ossFixtureRegistry(t), nil)
	scan := ossScan()
	doc := skillContext{}
	w.attachOSSScanner(t.Context(), work, "", scan, &db.Skill{Name: "threat-model"}, &doc, noEmit)

	got, err := os.ReadFile(filepath.Join(work, "oss_scanner", "threat_model.md"))
	if err != nil || string(got) != "registry tm" {
		t.Fatalf("staged threat model = %q, %v", got, err)
	}
	data, err := os.ReadFile(filepath.Join(work, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Scrutineer struct {
			OSSScanner map[string]any `json:"oss_scanner"`
		} `json:"scrutineer"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	o := stored.Scrutineer.OSSScanner
	if o["project"] != "proj" || o["registry"] != true || o["threat_model_file"] != "oss_scanner/threat_model.md" ||
		o["dockerfile_file"] != "oss_scanner/Dockerfile" || o["registry_url"] != w.OSSScannerRegistry {
		t.Fatalf("oss_scanner = %v", o)
	}
}

func TestStageOSSScannerOtherSkillStagesNothing(t *testing.T) {
	work := t.TempDir()
	w := ossWorker(ossFixtureRegistry(t), nil)
	if got := w.stageOSSScanner(t.Context(), work, ossScan(), &db.Skill{Name: "semgrep"}, noEmit); got != nil {
		t.Fatalf("staged = %+v", got)
	}
	if _, err := os.Stat(filepath.Join(work, "oss_scanner")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oss_scanner dir exists: %v", err)
	}
}

func TestStageOSSScannerRegistryErrorKeepsFallback(t *testing.T) {
	work := t.TempDir()
	writeOSSFile(t, work, "src/.oss-scanner/Dockerfile", "FROM alpine")
	w := ossWorker("", errors.New("offline"))
	var events []Event
	got := w.stageOSSScanner(t.Context(), work, ossScan(), &db.Skill{Name: "verify"}, func(e Event) { events = append(events, e) })
	if got == nil || got.Registry || got.DockerfileFile != "oss_scanner/Dockerfile" {
		t.Fatalf("staged = %+v", got)
	}
	if len(events) == 0 || events[0].Kind != KindText {
		t.Fatalf("events = %+v", events)
	}
}

func TestStageOSSScannerDisabledAddsNothing(t *testing.T) {
	work := t.TempDir()
	writeOSSFile(t, work, "src/.oss-scanner/threat_model.md", "repo tm")
	w := &Worker{}
	doc := skillContext{}
	w.attachOSSScanner(t.Context(), work, "", ossScan(), &db.Skill{Name: "threat-model"}, &doc, noEmit)
	if doc.Scrutineer.OSSScanner != nil {
		t.Fatalf("oss_scanner = %+v", doc.Scrutineer.OSSScanner)
	}
	if _, err := os.Stat(filepath.Join(work, "context.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("context.json rewritten: %v", err)
	}
}

func TestOSSScannerRegistryRootReusesRecentClone(t *testing.T) {
	w := &Worker{DataDir: t.TempDir(), OSSScannerRegistry: "https://example.invalid/registry"}
	src := filepath.Join(RepoCacheRoot(w.DataDir, w.OSSScannerRegistry), ossScannerCacheDir, "src")
	if err := os.MkdirAll(filepath.Join(src, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.ossScannerFetched.Store(w.OSSScannerRegistry, time.Now())

	got, release, err := w.ossScannerRegistryRoot(context.Background(), func(Event) {})
	if err != nil || got != src {
		t.Fatalf("registry root = %q, %v; want the cached clone %q without fetching", got, err, src)
	}
	mu := w.cacheMutex(w.OSSScannerRegistry)
	if mu.TryLock() {
		t.Fatal("registry cache lock released before the caller finished reading")
	}
	release()
	if !mu.TryLock() {
		t.Fatal("release did not unlock the registry cache")
	}
	mu.Unlock()
}

func TestOSSScannerRegistryRootUnlocksOnError(t *testing.T) {
	w := &Worker{DataDir: t.TempDir(), OSSScannerRegistry: "http://example.invalid/registry"}
	_, release, err := w.ossScannerRegistryRoot(context.Background(), func(Event) {})
	if err == nil {
		t.Fatal("expected an error for a non-https registry URL")
	}
	release()
	mu := w.cacheMutex(w.OSSScannerRegistry)
	if !mu.TryLock() {
		t.Fatal("registry cache lock still held after a failed fetch")
	}
	mu.Unlock()
}

func TestLocalThreatModelScanHonoursOSSScannerSwitch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		registry string
		staged   bool
	}{
		{"enabled", "https://example.test/registry", true},
		{"disabled", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gdb := dbtest.Open(t)
			local := t.TempDir()
			writeOSSFile(t, local, ".oss-scanner/threat_model.md", "repo tm")
			repo := db.Repository{URL: "file://" + local, Name: "local"}
			skill := db.Skill{Name: threatModelSkillName, Body: "threat model", OutputFile: "report.json", Active: true}
			for _, row := range []any{&repo, &skill} {
				if err := gdb.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), OSSScannerRegistry: tc.registry}
			w.PrepareOSSScannerRegistry = func(context.Context, string, func(Event)) (string, error) {
				t.Error("local scan consulted the registry")
				return "", nil
			}
			ran := false
			w.Runner = pocTestRunner{run: func(job SkillJob) SkillResult {
				ran = true
				_, err := os.Stat(filepath.Join(job.WorkRoot, "oss_scanner", "threat_model.md"))
				if staged := err == nil; staged != tc.staged {
					t.Errorf("staged threat model = %v, want %v (%v)", staged, tc.staged, err)
				}
				data, err := os.ReadFile(filepath.Join(fakeRunner{}.SkillDir(job.WorkRoot, job.Name), "context.json"))
				if err != nil {
					t.Errorf("skill dir context.json: %v", err)
					return SkillResult{Report: "{}"}
				}
				var stored struct {
					Scrutineer struct {
						OSSScanner map[string]any `json:"oss_scanner"`
					} `json:"scrutineer"`
				}
				if err := json.Unmarshal(data, &stored); err != nil {
					t.Errorf("context.json: %v", err)
				}
				if got := stored.Scrutineer.OSSScanner != nil; got != tc.staged {
					t.Errorf("oss_scanner in context = %v, want %v", stored.Scrutineer.OSSScanner, tc.staged)
				}
				return SkillResult{Report: "{}"}
			}}
			scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
			runPoCTestJob(t, w, &scan)
			if !ran {
				t.Fatalf("runner not invoked, status=%s: %s", scan.Status, scan.Error)
			}
		})
	}
}

func TestThreatModelScanStagesOSSScannerThroughDoSkill(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: ossRepoURL, Name: "project"}
	skill := db.Skill{Name: threatModelSkillName, Body: "threat model", OutputFile: "report.json", Active: true}
	for _, row := range []any{&repo, &skill} {
		if err := gdb.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	w := ossWorker(ossFixtureRegistry(t), nil)
	w.DB = gdb
	w.DataDir = t.TempDir()
	w.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	w.PrepareRepoSrc = stubPrepareRepoSrc
	ran := false
	w.Runner = pocTestRunner{run: func(job SkillJob) SkillResult {
		ran = true
		tm, err := os.ReadFile(filepath.Join(job.WorkRoot, "oss_scanner", "threat_model.md"))
		if err != nil || string(tm) != "registry tm" {
			t.Errorf("staged threat model = %q, %v", tm, err)
		}
		skillDir := fakeRunner{}.SkillDir(job.WorkRoot, job.Name)
		data, err := os.ReadFile(filepath.Join(skillDir, "context.json"))
		if err != nil {
			t.Errorf("skill dir context.json: %v", err)
			return SkillResult{Report: "{}"}
		}
		var stored struct {
			Scrutineer struct {
				ScanID     uint           `json:"scan_id"`
				OSSScanner map[string]any `json:"oss_scanner"`
			} `json:"scrutineer"`
		}
		if err := json.Unmarshal(data, &stored); err != nil {
			t.Errorf("context.json: %v", err)
		}
		o := stored.Scrutineer.OSSScanner
		if o["project"] != "proj" || o["threat_model_file"] != "oss_scanner/threat_model.md" {
			t.Errorf("skill dir oss_scanner = %v", o)
		}
		if stored.Scrutineer.ScanID != job.ScanID {
			t.Errorf("context.json lost the fields stageWorkspace wrote: %s", data)
		}
		return SkillResult{Report: "{}"}
	}}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	runPoCTestJob(t, w, &scan)
	if !ran {
		t.Fatalf("runner not invoked, status=%s: %s", scan.Status, scan.Error)
	}
}
