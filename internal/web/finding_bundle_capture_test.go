package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/poc"
)

func TestStreamedCaptureFailureReturnsFindingAndEnqueuesTriage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	if err := s.DB.Model(&scan).Update("skill_name", "security-deep-dive").Error; err != nil {
		t.Fatal(err)
	}
	revalidate := db.Skill{Name: "revalidate", OutputKind: "revalidate", Active: true}
	if err := s.DB.Create(&revalidate).Error; err != nil {
		t.Fatal(err)
	}
	s.Worker.DataDir = t.TempDir()
	dir := filepath.Join(s.Worker.DataDir, fmt.Sprintf("scan-%d", scan.ID), "poc", "F1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var findingID uint
	for attempt, data := range [][]byte{make([]byte, poc.MaxFileBytes+1), []byte("echo repaired\n")} {
		if err := os.WriteFile(filepath.Join(dir, "run.sh"), data, 0o700); err != nil {
			t.Fatal(err)
		}
		body := `{"id":"F1","title":"capture retry","severity":"High","location":"parser.go:1"}`
		r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/repositories/%d/findings", repo.ID), strings.NewReader(body))
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+scan.APIToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var response struct {
			ID           uint   `json:"id"`
			CaptureError string `json:"poc_capture_error"`
		}
		if w.Code != http.StatusCreated {
			t.Fatalf("attempt %d: status=%d: %s", attempt, w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.ID == 0 || (attempt == 0) != strings.Contains(response.CaptureError, "capture PoC") {
			t.Fatalf("attempt %d: response=%+v", attempt, response)
		}
		if attempt > 0 && response.ID != findingID {
			t.Fatal("retry created another finding")
		}
		findingID = response.ID
		var count int64
		if err := s.DB.Model(&db.Scan{}).Where("finding_id = ? AND skill_id = ?", findingID, revalidate.ID).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("attempt %d: triage scans=%d, err=%v", attempt, count, err)
		}
	}
	row, err := db.LoadFindingPoC(s.DB, findingID)
	if err != nil || row == nil {
		t.Fatalf("retry did not capture files: %v", err)
	}
	files, err := poc.Decode(row.Files)
	if err != nil || len(files) != 1 || string(files[0].Data) != "echo repaired\n" {
		t.Fatalf("retry capture=%+v, err=%v", files, err)
	}
}

func TestStreamedPoCBundleUsesCapturedBytes(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	s.Worker.DataDir = t.TempDir()
	dir := filepath.Join(s.Worker.DataDir, fmt.Sprintf("scan-%d", scan.ID), "poc", "F1")
	if err := os.MkdirAll(filepath.Join(dir, "inputs"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte{0, 255, '\r', '\n'}
	if err := os.WriteFile(filepath.Join(dir, "inputs", "payload.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	run := []byte("#!/bin/sh\ncat inputs/payload.bin\n")
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), run, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"id":"F1","title":"captured bug","severity":"Low","location":"parser.go:1","validation":"prose has no reproduction"}`
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/repositories/%d/findings", repo.ID), strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("stream status=%d: %s", w.Code, w.Body.String())
	}
	var finding db.Finding
	if err := s.DB.Where("repository_id = ?", repo.ID).First(&finding).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.Worker.RemoveScanArtifacts(scan.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&finding).Update("validation", "```sh filename=../unsafe\nwrong bytes\n```\n").Error; err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/findings/%d/bundle.tar.gz", finding.ID), nil)
	r.Host = testHost
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("bundle status=%d: %s", w.Code, w.Body.String())
	}
	files := readArchive(t, w.Body.Bytes())
	if !bytes.Equal(files["poc/inputs/payload.bin"], payload) || !bytes.Equal(files["poc/run.sh"], run) {
		t.Fatalf("bundle lost captured bytes: %v", keys(files))
	}
	var manifest db.PoCManifest
	if err := json.Unmarshal(files["poc-manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ScanID != scan.ID || manifest.FindingID != finding.ID || len(manifest.Files) != 2 {
		t.Fatalf("capture manifest=%+v", manifest)
	}
	var summary bundleManifest
	if err := json.Unmarshal(files["manifest.json"], &summary); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.Contents["poc/"], "captured") || summary.Contents["poc-manifest.json"] == "" {
		t.Fatalf("bundle did not identify captured reproduction: %+v", summary.Contents)
	}
}

func TestFindingBundleRejectsCorruptCapture(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	finding := setUpBundleFinding(t, s, false)
	if err := s.DB.Create(&db.FindingPoC{FindingID: finding.ID, ScanID: finding.ScanID, Files: []byte(`[{"path":"../escape","data":"eA==","sha256":"bad"}]`)}).Error; err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/findings/%d/bundle.tar.gz", finding.ID), nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "captured PoC") {
		t.Fatalf("corrupt capture response=%d: %s", w.Code, w.Body.String())
	}
}
