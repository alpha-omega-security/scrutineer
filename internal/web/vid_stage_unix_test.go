//go:build !windows

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

const testVIDStageBudget = 64 << 20

func TestAPIStreamFindingVIDBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		sizes     []int64
		locations []string
		wantVID   string
	}{
		{name: "sparse overflow", sizes: []int64{testVIDStageBudget + 4096}, locations: []string{"a.c:1"}},
		{name: "aggregate overflow", sizes: []int64{testVIDStageBudget/2 + 1, testVIDStageBudget/2 + 1}, locations: []string{"a.c:1", "b.c:1"}},
		{name: "exact budget", sizes: []int64{testVIDStageBudget}, locations: []string{"a.c:1"}, wantVID: "VID-test"},
		{name: "repeated path", sizes: []int64{testVIDStageBudget}, locations: []string{"a.c:1", "a.c:2"}, wantVID: "VID-test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cleanup := newTestServer(t)
			defer cleanup()
			s.Worker.DataDir = t.TempDir()
			s.Worker.Log = s.Log
			repo, scan := seedRunningScan(t, s)
			src := filepath.Join(s.Worker.DataDir, fmt.Sprintf("scan-%d", scan.ID), "src")
			for i, size := range tc.sizes {
				writeVIDSparseSource(t, src, fmt.Sprintf("%c.c", 'a'+i), size)
			}
			control := t.TempDir()
			s.Worker.VIDCommand = writeVIDTestCommand(t, control, false)
			stageParent := t.TempDir()
			t.Setenv("TMPDIR", stageParent)
			postVIDFinding(t, s.Handler(), repo.ID, scan.APIToken, "budget finding", tc.locations)
			requirePersistedVID(t, s, "budget finding", tc.wantVID)
			cwdFile := filepath.Join(control, "cwd")
			if tc.wantVID == "" {
				if _, err := os.Stat(cwdFile); !os.IsNotExist(err) {
					t.Fatalf("over-budget finding invoked VID command: %v", err)
				}
				if left, _ := filepath.Glob(filepath.Join(stageParent, "scrutineer-vid-*")); len(left) != 0 {
					t.Fatalf("over-budget finding left staging directories: %v", left)
				}
			} else {
				requireVIDStageRemoved(t, cwdFile)
			}
			writeVIDSparseSource(t, src, "small.c", 8)
			postVIDFinding(t, s.Handler(), repo.ID, scan.APIToken, "next finding", []string{"small.c:1"})
			requirePersistedVID(t, s, "next finding", "VID-test")
			requireVIDStageRemoved(t, cwdFile)
		})
	}
}

func TestAPIStreamFindingVIDConcurrentStaging(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	s.Worker.DataDir = t.TempDir()
	repo, scan := seedRunningScan(t, s)
	src := filepath.Join(s.Worker.DataDir, fmt.Sprintf("scan-%d", scan.ID), "src")
	writeVIDSparseSource(t, src, "a.c", testVIDStageBudget)
	control := t.TempDir()
	s.Worker.VIDCommand = writeVIDTestCommand(t, control, true)
	release := filepath.Join(control, "release")
	defer func() { _ = os.WriteFile(release, nil, 0o600) }()
	stageParent := t.TempDir()
	t.Setenv("TMPDIR", stageParent)
	handler := s.Handler()
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- streamVIDFinding(handler, repo.ID, scan.APIToken, "first", []string{"a.c:1"}) }()
	cwdFile := filepath.Join(control, "cwd")
	stage := waitVIDStage(t, cwdFile)
	info, err := os.Stat(filepath.Join(stage, "a.c"))
	if err != nil || info.Size() != testVIDStageBudget {
		t.Fatalf("staged source = %v, err=%v", info, err)
	}
	other, cleanupOther := newTestServer(t)
	defer cleanupOther()
	other.Worker.DataDir = s.Worker.DataDir
	other.Worker.VIDCommand = s.Worker.VIDCommand
	otherRepo, otherScan := seedRunningScan(t, other)
	writeVIDSparseSource(t, filepath.Join(other.Worker.DataDir, fmt.Sprintf("scan-%d", otherScan.ID), "src"), "a.c", testVIDStageBudget)
	otherHandler := other.Handler()
	queued := make(chan *httptest.ResponseRecorder, 2)
	go func() { queued <- streamVIDFinding(handler, repo.ID, scan.APIToken, "concurrent", []string{"a.c:1"}) }()
	go func() {
		queued <- streamVIDFinding(otherHandler, otherRepo.ID, otherScan.APIToken, "other worker", []string{"a.c:1"})
	}()
	select {
	case response := <-queued:
		t.Fatalf("finding finished while another staging was active: %d %s", response.Code, response.Body)
	case <-time.After(200 * time.Millisecond):
	}
	if staged, _ := filepath.Glob(filepath.Join(stageParent, "scrutineer-vid-*")); len(staged) != 1 {
		t.Fatalf("staging directories while one VID run is active = %v, want only %s", staged, stage)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, pending := range []chan *httptest.ResponseRecorder{finished, queued, queued} {
		select {
		case response := <-pending:
			if response.Code != http.StatusCreated {
				t.Fatalf("POST: %d %s", response.Code, response.Body)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("finding did not finish after release")
		}
	}
	requirePersistedVID(t, s, "first", "VID-test")
	requirePersistedVID(t, s, "concurrent", "VID-test")
	requirePersistedVID(t, other, "other worker", "VID-test")
	requireVIDStageRemoved(t, cwdFile)
	postVIDFinding(t, handler, repo.ID, scan.APIToken, "after cleanup", []string{"a.c:1"})
	requirePersistedVID(t, s, "after cleanup", "VID-test")
	requireVIDStageRemoved(t, cwdFile)
}

func writeVIDSparseSource(t *testing.T, dir, name string, size int64) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
}

func writeVIDTestCommand(t *testing.T, control string, block bool) string {
	t.Helper()
	body := fmt.Sprintf("#!/bin/sh\npwd > %q\n", filepath.Join(control, "cwd"))
	if block {
		body += fmt.Sprintf("while [ ! -f %q ]; do sleep 0.01; done\n", filepath.Join(control, "release"))
	}
	body += "echo VID-test\n"
	path := filepath.Join(control, "vid")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func streamVIDFinding(handler http.Handler, repo uint, token, title string, locations []string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"title": title, "severity": "High", "location": locations[0], "locations": locations})
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/repositories/%d/findings", repo), strings.NewReader(string(body)))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func postVIDFinding(t *testing.T, handler http.Handler, repo uint, token, title string, locations []string) {
	t.Helper()
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- streamVIDFinding(handler, repo, token, title, locations) }()
	select {
	case w := <-finished:
		if w.Code != http.StatusCreated {
			t.Fatalf("POST: %d %s", w.Code, w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("finding POST did not finish")
	}
}

func requirePersistedVID(t *testing.T, s *Server, title, want string) {
	t.Helper()
	var finding db.Finding
	if err := s.DB.Where("title = ?", title).First(&finding).Error; err != nil {
		t.Fatal(err)
	}
	if finding.VID != want {
		t.Fatalf("%s VID = %q, want %q", title, finding.VID, want)
	}
}

func waitVIDStage(t *testing.T, cwdFile string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(cwdFile); err == nil && len(data) > 0 {
			return strings.TrimSpace(string(data))
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("VID command did not start")
	return ""
}

func requireVIDStageRemoved(t *testing.T, cwdFile string) {
	t.Helper()
	stage := waitVIDStage(t, cwdFile)
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("staging directory remains: %s: %v", stage, err)
	}
}
