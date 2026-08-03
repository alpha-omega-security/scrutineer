package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestBuildPackageAlternativeValidatesInput(t *testing.T) {
	tests := []struct {
		name string
		purl string
		kind string
		want string
	}{
		{name: "missing purl", kind: "fork", want: "purl is required"},
		{name: "invalid purl", purl: "not-a-purl", kind: "fork", want: "purl is invalid"},
		{name: "invalid kind", purl: "pkg:npm/example", kind: "replacement", want: "kind must be fork, successor, or equivalent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildPackageAlternative(1, tt.purl, tt.kind, "")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRepoPackageAlternativesCRUDAndRender(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/zombie", Name: "zombie", Health: db.RepositoryHealthZombie}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	body := getRepoPage(t, s, repo.ID)
	for _, want := range []string{"Alternatives", "Add alternative", "No alternatives recorded yet"} {
		if !strings.Contains(body, want) {
			t.Fatalf("initial alternatives tab missing %q: %s", want, body)
		}
	}

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/alternatives", repo.ID), url.Values{
		"purl": {"pkg:npm/successor"},
		"kind": {"successor"},
		"note": {"Maintained replacement"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create status %d: %s", w.Code, w.Body)
	}

	var alt db.PackageAlternative
	if err := s.DB.Where("repository_id = ?", repo.ID).First(&alt).Error; err != nil {
		t.Fatal(err)
	}
	if alt.PURL != "pkg:npm/successor" || alt.Kind != db.PackageAlternativeSuccessor || alt.Note != "Maintained replacement" {
		t.Fatalf("alternative = %+v", alt)
	}

	body = getRepoPage(t, s, repo.ID)
	for _, want := range []string{"pkg:npm/successor", "successor", "Maintained replacement"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered alternatives missing %q: %s", want, body)
		}
	}

	w = postForm(t, s, fmt.Sprintf("/repositories/%d/alternatives/%d/delete", repo.ID, alt.ID), url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete status %d: %s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.PackageAlternative{}).Where("repository_id = ?", repo.ID).Count(&count)
	if count != 0 {
		t.Fatalf("alternatives count = %d, want 0", count)
	}
}

func TestAPIListPackageAlternatives(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	if err := s.DB.Create(&db.PackageAlternative{
		RepositoryID: repo.ID,
		PURL:         "pkg:gem/split-ng",
		Kind:         db.PackageAlternativeFork,
		Note:         "Maintained fork",
	}).Error; err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/repositories/%d/alternatives", repo.ID), nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0]["purl"] != "pkg:gem/split-ng" || got[0]["kind"] != "fork" {
		t.Fatalf("alternatives response = %+v", got)
	}
}
