package web

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"scrutineer/internal/db"
)

// TestAPIListSkills_activeFilter covers the ?active= query parameter: valid
// booleans filter, and a value that is not a boolean is rejected with 400
// rather than being treated as false (which silently returned the inactive
// skills for ?active=yes).
func TestAPIListSkills_activeFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, auth := seedRunningScan(t, s)

	s.DB.Create(&db.Skill{Name: "active-skill", Active: true})
	// Skill.Active is `not null;default:true`, so creating with Active:false
	// writes true — GORM omits Go zero values and the column default wins.
	// The retired skill has to be deactivated with an explicit update.
	retired := db.Skill{Name: "retired-skill"}
	s.DB.Create(&retired)
	s.DB.Model(&retired).Update("active", false)

	get := func(q string) (int, []map[string]any) {
		r := httptest.NewRequest("GET", "/api/skills"+q, nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+auth.APIToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var rows []map[string]any
		_ = json.NewDecoder(w.Body).Decode(&rows)
		return w.Code, rows
	}

	names := func(rows []map[string]any) map[string]bool {
		out := map[string]bool{}
		for _, r := range rows {
			out[r["name"].(string)] = true
		}
		return out
	}

	if code, rows := get("?active=true"); code != 200 {
		t.Errorf("?active=true: status %d, want 200", code)
	} else if n := names(rows); !n["active-skill"] || n["retired-skill"] {
		t.Errorf("?active=true returned %v", n)
	}

	if code, rows := get("?active=false"); code != 200 {
		t.Errorf("?active=false: status %d, want 200", code)
	} else if n := names(rows); !n["retired-skill"] || n["active-skill"] {
		t.Errorf("?active=false returned %v", n)
	}

	// The regression: these used to parse as false and return the inactive
	// skills instead of reporting the bad input.
	for _, bad := range []string{"yes", "typo", "2"} {
		code, rows := get("?active=" + bad)
		if code != 400 {
			t.Errorf("?active=%s: status %d, want 400 (rows=%v)", bad, code, rows)
		}
	}

	// An empty value keeps its existing meaning: no filter at all.
	if code, rows := get("?active="); code != 200 {
		t.Errorf("?active= (empty): status %d, want 200", code)
	} else if n := names(rows); !n["active-skill"] || !n["retired-skill"] {
		t.Errorf("?active= (empty) should not filter, got %v", n)
	}
}
