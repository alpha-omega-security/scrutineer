package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/web"
	"scrutineer/internal/worker"
)

// auditFakeRunner dispatches each skill run to a per-skill behaviour.
type auditFakeRunner struct {
	behave func(ctx context.Context, sj worker.SkillJob) (worker.SkillResult, error)
}

func (r auditFakeRunner) RunSkill(ctx context.Context, sj worker.SkillJob, _ func(worker.Event)) (worker.SkillResult, error) {
	return r.behave(ctx, sj)
}

func (auditFakeRunner) SkillDir(workRoot, name string) string {
	return worker.ClaudeHarness{}.SkillDir(workRoot, name)
}

// auditHarness captures the audit's database through auditAppHook and shrinks
// the waits for the duration of a test.
type auditHarness struct {
	mu  sync.Mutex
	app *app
}

func (h *auditHarness) db() *app {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.app
}

func newAuditHarness(t *testing.T) *auditHarness {
	t.Helper()
	h := &auditHarness{}
	oldPoll, oldSettle, oldDrain, oldHook := auditPollInterval, auditSettlePolls, auditDrainTimeout, auditAppHook
	auditPollInterval, auditSettlePolls, auditDrainTimeout = 20*time.Millisecond, 2, 5*time.Second
	auditAppHook = func(a *app) {
		h.mu.Lock()
		h.app = a
		h.mu.Unlock()
	}
	t.Cleanup(func() {
		auditPollInterval, auditSettlePolls, auditDrainTimeout, auditAppHook = oldPoll, oldSettle, oldDrain, oldHook
	})
	return h
}

func auditSource(t *testing.T) (dir, head string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		return dir, ""
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "."},
		{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, b)
		}
	}
	b, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return dir, strings.TrimSpace(string(b))
}

// auditArgs builds an argv with a fresh data dir next to outDir so the temp
// dir cleanup removes both.
func auditArgs(src, outDir string, extra ...string) []string {
	data := filepath.Join(filepath.Dir(outDir), "data")
	return append([]string{"-no-container", "-data", data, "-source", src, "-out", outDir}, extra...)
}

func fakeSetup(r worker.SkillRunner) runnerSetup {
	return func(f *flags, _ *config.Config, _ *slog.Logger) (worker.SkillRunner, string, error) {
		return r, hostAPIBase(f.addr), nil
	}
}

func TestAuditConfiguredMaxTier(t *testing.T) {
	h := newAuditHarness(t)
	saved := web.Models
	t.Cleanup(func() { web.Models = saved })
	src, _ := auditSource(t)
	outDir := filepath.Join(t.TempDir(), "out")
	configPath := filepath.Join(t.TempDir(), "scrutineer.yaml")
	if err := os.WriteFile(configPath, []byte("default_model: claude-opus-4-8\nmodels:\n  - name: Mythos\n    id: claude-mythos-preview\n    tier: max\n  - name: Opus\n    id: claude-opus-4-8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	runner := auditFakeRunner{behave: func(_ context.Context, _ worker.SkillJob) (worker.SkillResult, error) {
		called = true
		if got := web.ModelForTier(h.db().db, web.ModelTierMax, "fallback"); got != "claude-mythos-preview" {
			return worker.SkillResult{}, fmt.Errorf("max tier = %q, want claude-mythos-preview", got)
		}
		return worker.SkillResult{Report: "{}"}, nil
	}}
	args := auditArgs(src, outDir, "-config", configPath)
	if err := runAuditWith(args, &bytes.Buffer{}, fakeSetup(runner)); err != nil {
		t.Fatal(err)
	}
	if !called || readManifest(t, outDir).Status != "complete" {
		t.Fatal("configured audit did not complete")
	}
}

func readManifest(t *testing.T, outDir string) auditManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(outDir, "scrutineer-audit", "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m auditManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	return exitCodeFor(err)
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return len(strings.Split(strings.TrimSpace(string(b)), "\n"))
}

func TestAudit_complete(t *testing.T) {
	h := newAuditHarness(t)
	src, head := auditSource(t)
	outDir := filepath.Join(t.TempDir(), "out")

	fake := auditFakeRunner{behave: func(_ context.Context, sj worker.SkillJob) (worker.SkillResult, error) {
		if sj.Name != "triage" {
			return worker.SkillResult{Report: "{}"}, nil
		}
		gdb := h.db().db
		for i, st := range []db.FindingLifecycle{db.FindingNew, db.FindingRejected} {
			f := db.Finding{
				ScanID: sj.ScanID, RepositoryID: sj.Repo.ID, FindingID: "F" + string(rune('1'+i)),
				Fingerprint: "fp-" + string(rune('a'+i)), Title: "Issue " + string(rune('A'+i)),
				Severity: "High", Status: st, Location: "main.go:3",
			}
			if err := gdb.Create(&f).Error; err != nil {
				return worker.SkillResult{}, err
			}
		}
		return worker.SkillResult{Report: "{}"}, nil
	}}
	var buf bytes.Buffer
	err := runAuditWith(auditArgs(src, outDir), &buf, fakeSetup(fake))
	if err != nil {
		t.Fatalf("runAuditWith: %v", err)
	}
	m := readManifest(t, outDir)
	if m.Status != "complete" || m.RepositoryID == 0 {
		t.Errorf("manifest = %+v, want complete with a repository id", m)
	}
	if head != "" && m.Revision != head {
		t.Errorf("revision = %q, want %q", m.Revision, head)
	}
	var triageDone bool
	for _, s := range m.Scans {
		if s.Skill == "triage" && s.Status == "done" {
			triageDone = true
		}
	}
	if !triageDone {
		t.Errorf("scans = %+v, want a done triage", m.Scans)
	}
	if m.Findings != 2 || m.BugCandidates != 1 {
		t.Errorf("findings=%d bug_candidates=%d, want 2 and 1", m.Findings, m.BugCandidates)
	}
	if n := countLines(t, filepath.Join(outDir, "scrutineer-audit", "findings.jsonl")); n != 2 {
		t.Errorf("findings.jsonl lines = %d, want 2", n)
	}
	if n := countLines(t, filepath.Join(outDir, "scrutineer-audit", "scans.jsonl")); n < 1 {
		t.Errorf("scans.jsonl empty")
	}
	if _, err := os.Stat(filepath.Join(outDir, "bug-candidates", "scrutineer.sarif")); err != nil {
		t.Errorf("bug candidate file: %v", err)
	}
}

func TestAudit_failedScanIsIncomplete(t *testing.T) {
	newAuditHarness(t)
	src, _ := auditSource(t)
	outDir := filepath.Join(t.TempDir(), "out")
	fake := auditFakeRunner{behave: func(context.Context, worker.SkillJob) (worker.SkillResult, error) {
		return worker.SkillResult{}, errors.New("boom")
	}}

	err := runAuditWith(auditArgs(src, outDir), &bytes.Buffer{}, fakeSetup(fake))
	if got := exitCodeOf(err); got != auditIncompleteExitCode {
		t.Fatalf("exit code = %d (err %v), want %d", got, err, auditIncompleteExitCode)
	}
	m := readManifest(t, outDir)
	if m.Status != "incomplete" || !strings.Contains(m.Reason, "failed") {
		t.Errorf("status=%q reason=%q, want incomplete with failed scans", m.Status, m.Reason)
	}
	if _, err := os.Stat(filepath.Join(outDir, "bug-candidates", "scrutineer.sarif")); !os.IsNotExist(err) {
		t.Errorf("bug candidate file present without candidates: %v", err)
	}
}

func TestAudit_timeoutIsInterrupted(t *testing.T) {
	newAuditHarness(t)
	src, _ := auditSource(t)
	outDir := filepath.Join(t.TempDir(), "out")
	started := make(chan struct{})
	var once sync.Once
	fake := auditFakeRunner{behave: func(ctx context.Context, _ worker.SkillJob) (worker.SkillResult, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return worker.SkillResult{}, ctx.Err()
	}}

	// The queue polls once a second, so the timeout leaves room for the scan
	// to be claimed and running before the audit stops it.
	err := runAuditWith(auditArgs(src, outDir, "-audit-timeout", "5s"), &bytes.Buffer{}, fakeSetup(fake))
	select {
	case <-started:
	default:
		t.Fatal("triage never started, so the timeout cancelled nothing")
	}
	if got := exitCodeOf(err); got != auditIncompleteExitCode {
		t.Fatalf("exit code = %d (err %v), want %d", got, err, auditIncompleteExitCode)
	}
	m := readManifest(t, outDir)
	if m.Status != "interrupted" {
		t.Errorf("status = %q, want interrupted", m.Status)
	}
	// The timeout must have cancelled the running triage scan with the
	// audit's reason, not the default "cancelled by user".
	var triage *auditScan
	for i := range m.Scans {
		if m.Scans[i].Skill == "triage" {
			triage = &m.Scans[i]
		}
	}
	if triage == nil {
		t.Fatalf("scans = %+v, want a triage scan", m.Scans)
	}
	if triage.Status != "cancelled" || triage.Error != "audit interrupted: audit timeout reached" {
		t.Errorf("triage = %+v, want cancelled with the audit timeout reason", *triage)
	}
}

func TestExitCodeFor(t *testing.T) {
	if got := exitCodeFor(&auditIncompleteError{Status: "incomplete", Reason: "1 scan failed"}); got != auditIncompleteExitCode {
		t.Errorf("incomplete audit exit = %d, want %d", got, auditIncompleteExitCode)
	}
	if got := exitCodeFor(fmt.Errorf("wrapped: %w", &auditIncompleteError{Status: "interrupted"})); got != auditIncompleteExitCode {
		t.Errorf("wrapped incomplete audit exit = %d, want %d", got, auditIncompleteExitCode)
	}
	// A child process that exits 3 must not read as an incomplete audit.
	name, args := "sh", []string{"-c", "exit 3"}
	if runtime.GOOS == "windows" {
		name, args = "cmd", []string{"/c", "exit 3"}
	}
	childErr := exec.Command(name, args...).Run()
	var exitErr *exec.ExitError
	if !errors.As(childErr, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("child err = %v, want exit status 3", childErr)
	}
	if got := exitCodeFor(fmt.Errorf("run child: %w", childErr)); got != 1 {
		t.Errorf("wrapped child exit error maps to %d, want 1", got)
	}
}

func TestAudit_flagValidation(t *testing.T) {
	newAuditHarness(t)
	src, _ := auditSource(t)
	file := filepath.Join(src, "main.go")
	staleData := t.TempDir()
	if err := os.WriteFile(filepath.Join(staleData, dbFileName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// An instance with its database in Postgres keeps only workspaces here.
	busyData := t.TempDir()
	if err := os.MkdirAll(filepath.Join(busyData, "work", "scan-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "out")
	fake := fakeSetup(auditFakeRunner{behave: func(context.Context, worker.SkillJob) (worker.SkillResult, error) {
		return worker.SkillResult{Report: "{}"}, nil
	}})

	tests := map[string][]string{
		"missing source":   {"-out", outDir},
		"missing out":      {"-source", src},
		"source not a dir": {"-source", file, "-out", outDir},
		"source missing":   {"-source", filepath.Join(src, "nope"), "-out", outDir},
		"data has a db":    {"-source", src, "-out", outDir, "-data", staleData},
		"data not empty":   {"-source", src, "-out", outDir, "-data", busyData},
		"stray positional": {"-source", src, "-out", outDir, "extra"},
		"unknown flag":     {"-source", src, "-out", outDir, "-no-such-flag"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if err := runAuditWith(args, &bytes.Buffer{}, fake); err == nil {
				t.Errorf("runAuditWith(%v) = nil, want an error", args)
			}
		})
	}
}

// TestAudit_modelPinsEveryTier runs an audit with a -model no harness lists, as
// a LiteLLM alias would be. Triage queues a mid-tier and a max-tier skill
// through the skill API the way the agent does. Both must run on -model
// rather than on the harness's tier models.
func TestAudit_modelPinsEveryTier(t *testing.T) {
	h := newAuditHarness(t)
	saved := web.Models
	t.Cleanup(func() { web.Models = saved })
	src, _ := auditSource(t)
	outDir := filepath.Join(t.TempDir(), "out")
	const pinned = "litellm-proxy-model"
	tiered := map[string]string{"repo-overview": web.ModelTierMid, "investigate": web.ModelTierMax}

	var apiBase string
	var mu sync.Mutex
	ran := map[string]string{}
	fake := auditFakeRunner{behave: func(ctx context.Context, sj worker.SkillJob) (worker.SkillResult, error) {
		mu.Lock()
		ran[sj.Name] = sj.Model
		mu.Unlock()
		if sj.Name != "triage" {
			return worker.SkillResult{Report: "{}"}, nil
		}
		gdb := h.db().db
		var scan db.Scan
		if err := gdb.First(&scan, sj.ScanID).Error; err != nil {
			return worker.SkillResult{}, err
		}
		for name, tier := range tiered {
			var sk db.Skill
			if err := gdb.Where("name = ?", name).First(&sk).Error; err != nil || sk.Model != tier {
				return worker.SkillResult{}, fmt.Errorf("skill %s declares model %q (err %v), want tier %s", name, sk.Model, err, tier)
			}
			url := fmt.Sprintf("%s/repositories/%d/skills/%s/run", apiBase, sj.Repo.ID, name)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
			if err != nil {
				return worker.SkillResult{}, err
			}
			req.Header.Set("Authorization", "Bearer "+scan.APIToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return worker.SkillResult{}, err
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= http.StatusBadRequest {
				return worker.SkillResult{}, fmt.Errorf("run %s: status %d", name, resp.StatusCode)
			}
		}
		return worker.SkillResult{Report: "{}"}, nil
	}}
	setup := func(f *flags, _ *config.Config, _ *slog.Logger) (worker.SkillRunner, string, error) {
		apiBase = hostAPIBase(f.addr)
		return fake, apiBase, nil
	}
	if err := runAuditWith(auditArgs(src, outDir, "-model", pinned), &bytes.Buffer{}, setup); err != nil {
		t.Fatalf("runAuditWith: %v", err)
	}
	for _, name := range []string{"triage", "repo-overview", "investigate"} {
		if got, ok := ran[name]; !ok || got != pinned {
			t.Errorf("%s ran=%v model=%q, want %q", name, ok, got, pinned)
		}
	}
}
