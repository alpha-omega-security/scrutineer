package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestMaintainerUpdateCorrectsReportedDetails(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	m := db.Maintainer{Login: "person", Name: "Wrong name", Email: "wrong@example.org", Status: db.MaintainerActive, Notes: "wrong note", DoNotContact: true}
	if err := s.DB.Create(&m).Error; err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/maintainers/%d", m.ID)
	w := postForm(t, s, path, url.Values{
		"name": {" Correct name "}, "email": {" correct@example.org "}, "status": {"inactive"}, "notes": {" Corrected by operator "},
		"login": {"changed"}, "do_not_contact": {"false"},
	})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != path {
		t.Fatalf("save details: status=%d location=%s body=%s", w.Code, w.Header().Get("Location"), w.Body)
	}
	var got db.Maintainer
	if err := s.DB.First(&got, m.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Name != "Correct name" || got.Email != "correct@example.org" || got.Status != db.MaintainerInactive || got.Notes != "Corrected by operator" || got.Login != m.Login || !got.DoNotContact {
		t.Fatalf("saved maintainer = %+v", got)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, path))
	if w.Code != http.StatusOK {
		t.Fatalf("show details: status=%d body=%s", w.Code, w.Body)
	}
	for _, want := range []string{`action="` + path + `"`, `value="Correct name"`, `value="correct@example.org"`, `value="inactive" selected`, `>Corrected by operator</textarea>`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("maintainer page missing %q", want)
		}
	}
}

func TestRepositoryMaintainerViewsUseScopedActivity(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	pushed := time.Now().AddDate(-3, 0, 0)
	if err := s.DB.Model(&repo).Updates(map[string]any{"pushed_at": pushed, "fetched_at": time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	m := db.Maintainer{Login: "person", Name: "Person", Email: "person@example.org", Status: db.MaintainerActive}
	if err := s.DB.Create(&m).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&repo).Association("Maintainers").Append(&m); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordMaintainerActivity(s.DB, repo.ID, m.ID, "inactive"); err != nil {
		t.Fatal(err)
	}
	seedHealthScans(t, s, repo.ID)
	s.repositoryHealthTick(time.Now())
	for _, tc := range []struct {
		path string
		want string
	}{
		{fmt.Sprintf("/api/repositories/%d/maintainers", repo.ID), `"status":"inactive"`},
		{fmt.Sprintf("/repositories/%d", repo.ID), "abandoned health"},
		{fmt.Sprintf("/repositories/%d/report.md", repo.ID), "| Person | person | person@example.org | inactive |"},
	} {
		w := httptest.NewRecorder()
		if strings.HasPrefix(tc.path, "/api/") {
			w = apiReq(t, s, http.MethodGet, tc.path, scan.APIToken, "")
		} else {
			s.Handler().ServeHTTP(w, localReq(http.MethodGet, tc.path))
		}
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("GET %s: status=%d, response missing %q", tc.path, w.Code, tc.want)
		}
	}
}

func TestMaintainerUpdateRejectsInvalidStatusWithoutChangingDetails(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	m := db.Maintainer{Login: "person", Name: "Original", Status: db.MaintainerActive}
	if err := s.DB.Create(&m).Error; err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/maintainers/%d", m.ID)
	w := postForm(t, s, path, url.Values{"name": {"Changed"}, "status": {"invalid"}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid status: status=%d body=%s", w.Code, w.Body)
	}
	var got db.Maintainer
	if err := s.DB.First(&got, m.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Name != m.Name || got.Status != m.Status {
		t.Fatalf("invalid request changed details: %+v", got)
	}
}

func TestMaintainerUpdateRequiresOperatorSession(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, scan := seedRunningScan(t, s)
	m := db.Maintainer{Login: "person", Name: "Original"}
	if err := s.DB.Create(&m).Error; err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://host.docker.internal/maintainers/%d", m.ID), strings.NewReader("name=Changed"))
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("scan-token edit: status=%d body=%s", w.Code, w.Body)
	}
	var got db.Maintainer
	if err := s.DB.First(&got, m.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Name != m.Name {
		t.Fatalf("scan-token edit changed details: %+v", got)
	}
}
