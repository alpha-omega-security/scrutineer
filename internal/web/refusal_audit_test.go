package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestRepoShow_refusalAuditWarning(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/refusal-audit", Name: "refusal-audit"}
	s.DB.Create(&repo)
	scan := db.Scan{
		RepositoryID:        repo.ID,
		Kind:                "skill",
		Status:              db.ScanDone,
		SkillName:           deepDiveSkillName,
		RefusalAudit:        `{"refused":false,"reason":null,"skipped":[{"path":"blob.bin","reason":"opaque"}]}`,
		RefusalAuditWarning: true,
	}
	s.DB.Create(&scan)

	body := getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, "analysis incomplete") {
		t.Errorf("repo Scans tab missing refusal warning: %s", body)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/scans/%d", scan.ID)))
	if w.Code != 200 {
		t.Fatalf("scan page status %d: %s", w.Code, w.Body)
	}
	for _, want := range []string{"analysis incomplete", "Refusal audit", "blob.bin"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("scan page missing %q: %s", want, w.Body)
		}
	}
}
