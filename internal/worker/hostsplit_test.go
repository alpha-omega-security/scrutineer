package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

// contextCapturingRunner reads context.json out of the workspace at RunSkill
// time, before the worker tears the scan directory down.
type contextCapturingRunner struct {
	dir     string
	apiBase *string
}

func (r contextCapturingRunner) RunSkill(_ context.Context, sj SkillJob, _ func(Event)) (SkillResult, error) {
	data, err := os.ReadFile(filepath.Join(sj.WorkRoot, "context.json"))
	if err != nil {
		return SkillResult{}, err
	}
	var ctx struct {
		Scrutineer struct {
			APIBase string `json:"api_base"`
		} `json:"scrutineer"`
	}
	if err := json.Unmarshal(data, &ctx); err != nil {
		return SkillResult{}, err
	}
	*r.apiBase = ctx.Scrutineer.APIBase
	return SkillResult{}, nil
}

func (r contextCapturingRunner) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, r.dir, name)
}

func (contextCapturingRunner) Backend() string { return "codex" }

func TestHostSplitRunner_routesByName(t *testing.T) {
	var hostBase, containerBase string
	r := HostSplitRunner{
		Container:  contextCapturingRunner{dir: "container", apiBase: &containerBase},
		Host:       contextCapturingRunner{dir: "host", apiBase: &hostBase},
		HostSkills: []string{"verify"},
	}
	if got := r.SkillDir("/w", "verify"); got != filepath.Join("/w", "host", "verify") {
		t.Errorf("host skill dir = %q", got)
	}
	if got := r.SkillDir("/w", "triage"); got != filepath.Join("/w", "container", "triage") {
		t.Errorf("container skill dir = %q", got)
	}
	if !r.runsOnHost("verify") || r.runsOnHost("triage") {
		t.Errorf("runsOnHost: verify=%v triage=%v", r.runsOnHost("verify"), r.runsOnHost("triage"))
	}
	if got := r.Backend(); got != "codex" {
		t.Errorf("Backend() = %q, want the container's", got)
	}
}

func TestRunnerImageName_unwrapsHostSplit(t *testing.T) {
	inner := ContainerRunner{Image: "runner:test", Runtime: ContainerRuntime{Bin: "podman"}}
	r := HostSplitRunner{Container: inner, Host: LocalClaude{}, HostSkills: []string{"verify"}}
	if got := RunnerImageName(r); got != "runner:test" {
		t.Errorf("RunnerImageName = %q, want runner:test", got)
	}
	if got := RuntimeOf(r).Bin; got != "podman" {
		t.Errorf("RuntimeOf.Bin = %q, want podman", got)
	}
}

// runHostSplitScan runs one posture-test scan through a split runner whose
// host list is hostSkills and returns the api_base each side saw.
func runHostSplitScan(t *testing.T, hostSkills []string) (hostBase, containerBase string) {
	t.Helper()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "posture-test", Description: "d", Body: "b", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID, Model: "fake"}
	gdb.Create(&scan)
	w := &Worker{
		DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		APIBase: "http://host.docker.internal:8080/api",
		Runner: HostSplitRunner{
			Container:   contextCapturingRunner{dir: "container", apiBase: &containerBase},
			Host:        contextCapturingRunner{dir: "host", apiBase: &hostBase},
			HostSkills:  hostSkills,
			HostAPIBase: "http://127.0.0.1:8080/api",
		},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Fatalf("scan status = %q, want done (%s)", got.Status, got.Error)
	}
	return hostBase, containerBase
}

func TestWorker_hostSkillGetsLoopbackAPIBase(t *testing.T) {
	hostBase, containerBase := runHostSplitScan(t, []string{"posture-test"})
	if containerBase != "" {
		t.Errorf("container side ran a host skill (api_base %q)", containerBase)
	}
	if hostBase != "http://127.0.0.1:8080/api" {
		t.Errorf("host api_base = %q, want the loopback base", hostBase)
	}
}

func TestWorker_containerSkillKeepsContainerAPIBase(t *testing.T) {
	hostBase, containerBase := runHostSplitScan(t, []string{"verify"})
	if hostBase != "" {
		t.Errorf("host side ran a container skill (api_base %q)", hostBase)
	}
	if containerBase != "http://host.docker.internal:8080/api" {
		t.Errorf("container api_base = %q, want the container host endpoint", containerBase)
	}
}
