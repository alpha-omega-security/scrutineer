package web

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestAPIStreamFinding_persistsAndIsVisibleToSiblings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, auth := seedRunningScan(t, s)
	s.DB.Model(&db.Scan{}).Where("id = ?", auth.ID).
		Updates(map[string]any{"scan_group": "grp-1", "skill_name": "security-deep-dive"})

	body := `{"id":"F1","title":"streamed bug","severity":"High","location":"main.go:10",
		"dup_check":"compared against F0; distinct sink"}`
	post := httptest.NewRequest("POST", fmt.Sprintf("/api/repositories/%d/findings", repo.ID), strings.NewReader(body))
	post.Host = testHost
	post.Header.Set("Authorization", "Bearer "+auth.APIToken)
	pw := httptest.NewRecorder()
	s.Handler().ServeHTTP(pw, post)
	if pw.Code != 201 {
		t.Fatalf("POST status %d: %s", pw.Code, pw.Body)
	}
	var created map[string]any
	_ = json.NewDecoder(pw.Body).Decode(&created)
	if created["title"] != "streamed bug" || created["dup_check"] != "compared against F0; distinct sink" {
		t.Errorf("POST returned %v", created)
	}

	get := httptest.NewRequest("GET", fmt.Sprintf("/api/repositories/%d/findings?scan_group=grp-1", repo.ID), nil)
	get.Host = testHost
	get.Header.Set("Authorization", "Bearer "+auth.APIToken)
	gw := httptest.NewRecorder()
	s.Handler().ServeHTTP(gw, get)
	if gw.Code != 200 {
		t.Fatalf("GET status %d: %s", gw.Code, gw.Body)
	}
	var rows []map[string]any
	_ = json.NewDecoder(gw.Body).Decode(&rows)
	if len(rows) != 1 || rows[0]["title"] != "streamed bug" {
		t.Fatalf("sibling read got %v, want the streamed finding", rows)
	}
}

func TestAPIStreamFinding_rejectsOtherRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, auth := seedRunningScan(t, s)
	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	s.DB.Create(&other)

	body := `{"title":"t","severity":"High","location":"a.go:1"}`
	r := httptest.NewRequest("POST", fmt.Sprintf("/api/repositories/%d/findings", other.ID), strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+auth.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-repo POST status %d, want 403", w.Code)
	}
	var n int64
	s.DB.Model(&db.Finding{}).Count(&n)
	if n != 0 {
		t.Errorf("cross-repo POST created %d findings, want 0", n)
	}
}

func TestAPIStreamFinding_rejectsInvalidBody(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, auth := seedRunningScan(t, s)

	for name, body := range map[string]string{
		"malformed JSON": `{not json`,
		"missing fields": `{"title":"t"}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", fmt.Sprintf("/api/repositories/%d/findings", repo.ID), strings.NewReader(body))
			r.Host = testHost
			r.Header.Set("Authorization", "Bearer "+auth.APIToken)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 400 {
				t.Errorf("status %d, want 400", w.Code)
			}
		})
	}
}
