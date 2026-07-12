package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/llm"
)

func TestCallAuxiliary_recordsUsageOnMalformedResponse(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "auxiliary.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/auxiliary", Name: "auxiliary"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanRunning, Model: "claude-sonnet-4-6"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Model != scan.Model {
			t.Errorf("model = %q, want %q", request.Model, scan.Model)
		}
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"not JSON"}],"usage":{"input_tokens":100,"output_tokens":10,"cache_read_input_tokens":20,"cache_creation_input_tokens":30}}`)
	}))
	defer server.Close()

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err = w.CallAuxiliary(context.Background(), &scan, "answer", json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string"}}}`), llm.Options{
		Endpoint: server.URL, APIKey: "key", MaxTokens: 32, HTTPClient: server.Client(),
	})
	if err == nil {
		t.Fatal("CallAuxiliary succeeded, want malformed-response error")
	}

	var got db.Scan
	if err := gdb.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.InputTokens != 100 || got.OutputTokens != 10 || got.CacheReadTokens != 20 || got.CacheWriteTokens != 30 {
		t.Errorf("usage = in:%d out:%d read:%d write:%d", got.InputTokens, got.OutputTokens, got.CacheReadTokens, got.CacheWriteTokens)
	}
	if want := 0.0005685; math.Abs(got.CostUSD-want) > 1e-12 {
		t.Errorf("cost = %.7f, want %.7f", got.CostUSD, want)
	}
	if scan.InputTokens != got.InputTokens || scan.CostUSD != got.CostUSD {
		t.Errorf("in-memory scan was not updated: %+v", scan)
	}
}

func TestCallAuxiliary_rejectsDifferentModel(t *testing.T) {
	w := &Worker{DB: &gorm.DB{}}
	_, err := w.CallAuxiliary(context.Background(), &db.Scan{ID: 1, Model: "claude-haiku-4-5"}, "answer", json.RawMessage(`{"type":"object"}`), llm.Options{
		Model: "claude-sonnet-4-6",
	})
	if err == nil || err.Error() != `auxiliary model "claude-sonnet-4-6" does not match scan model "claude-haiku-4-5"` {
		t.Fatalf("CallAuxiliary() error = %v", err)
	}
}

func TestRecordAuxiliaryUsage_rejectsMissingScan(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "missing-scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	err = recordAuxiliaryUsage(gdb, &db.Scan{ID: 999}, "claude-sonnet-4-6", llm.Usage{InputTokens: 1})
	if err == nil || err.Error() != "scan 999 no longer exists" {
		t.Fatalf("recordAuxiliaryUsage() error = %v", err)
	}
}
