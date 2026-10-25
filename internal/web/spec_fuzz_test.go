package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"scrutineer/internal/specfuzz"
)

func TestAPISpecFuzzClauses(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	s.apiListSpecFuzzClauses(rr, httptest.NewRequest("GET", "/api/specfuzz/clauses", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Source  string `json:"lean_rfcs"`
		Clauses []struct {
			ID       string `json:"id"`
			Protocol string `json:"protocol"`
		} `json:"clauses"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Source == "" {
		t.Error("lean_rfcs source empty")
	}
	found := false
	for _, c := range got.Clauses {
		if c.ID == "rfc9112-7.1" && c.Protocol == "http1" {
			found = true
		}
	}
	if !found {
		t.Errorf("rfc9112-7.1 not listed: %+v", got.Clauses)
	}
}

func TestAPISpecFuzzClause(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/specfuzz/clauses/rfc9112-7.1", nil)
	req.SetPathValue("id", "rfc9112-7.1")
	rr := httptest.NewRecorder()
	s.apiGetSpecFuzzClause(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Meta     specfuzz.ClauseMeta    `json:"meta"`
		Controls specfuzz.Controls      `json:"controls"`
		Corpus   []specfuzz.CorpusInput `json:"corpus"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Meta.ID != "rfc9112-7.1" {
		t.Errorf("meta.id = %q", got.Meta.ID)
	}
	if len(got.Corpus) == 0 {
		t.Error("corpus empty")
	}
	if len(got.Controls.MustAccept) == 0 || len(got.Controls.MustReject) == 0 {
		t.Error("controls incomplete")
	}
}

func TestAPISpecFuzzClauseNotFound(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/specfuzz/clauses/rfc0000-0.0", nil)
	req.SetPathValue("id", "rfc0000-0.0")
	rr := httptest.NewRecorder()
	s.apiGetSpecFuzzClause(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}
