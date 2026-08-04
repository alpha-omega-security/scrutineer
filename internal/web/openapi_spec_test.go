package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"scrutineer/internal/db"
)

// runningScanToken seeds a running scan and returns its API token, the
// credential a skill inside the runner container holds while it works.
func runningScanToken(t *testing.T, s *Server) string {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/spec", Name: "spec"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, APIToken: NewAPIToken()}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	return scan.APIToken
}

// GET /api/openapi.yaml serves the spec so a skill or external tool can read
// the API surface from a running server without a checkout (#731).
func TestOpenAPISpecServedOverHTTP(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/api/openapi.yaml"))

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/openapi.yaml status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("Content-Type"); got != "application/yaml" {
		t.Errorf("Content-Type = %q, want %q", got, "application/yaml")
	}

	var doc struct {
		Info struct {
			Title string `yaml:"title"`
		} `yaml:"info"`
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("served spec does not parse as YAML: %v", err)
	}
	if doc.Info.Title == "" {
		t.Error("served spec has no info.title")
	}
	if _, ok := doc.Paths["/openapi.yaml"]; !ok {
		t.Error("served spec does not document its own /openapi.yaml path")
	}
}

// The embedded copy must stay byte-identical to the file the repo ships, so a
// stale binary cannot serve a spec that disagrees with openapi.yaml.
func TestOpenAPISpecMatchesRepoFile(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	onDisk, err := os.ReadFile("../../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/api/openapi.yaml"))

	if got := w.Body.Bytes(); !bytes.Equal(got, onDisk) {
		t.Errorf("served spec differs from openapi.yaml (%d served bytes, %d on disk)", len(got), len(onDisk))
	}
}

// A skill in the runner container reaches the loopback-bound server through the
// egress proxy, which rewrites the dial target but forwards the Host that
// context.json advertises -- host.docker.internal under docker/podman, the
// default gateway IP under Apple's container. Neither is local, so the spec has
// to be reachable with the per-scan bearer token those callers already hold;
// otherwise the endpoint 403s exactly where #731 wants it to work.
func TestOpenAPISpecServedToContainerWithScanToken(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	token := runningScanToken(t, s)

	onDisk, err := os.ReadFile("../../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}

	for _, apiHost := range []string{"host.docker.internal:8080", "192.168.64.1:8080"} {
		r := httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil)
		r.Host = apiHost
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("Host %s with a running scan token: status = %d, want %d; body=%s",
				apiHost, w.Code, http.StatusOK, w.Body)
			continue
		}
		if !bytes.Equal(w.Body.Bytes(), onDisk) {
			t.Errorf("Host %s served %d bytes, want the %d-byte spec", apiHost, w.Body.Len(), len(onDisk))
		}
	}
}

// Bearer access must not become a way around the host boundary for callers with
// no scan: a non-local Host still gets nothing without a valid running-scan
// token, so a DNS-rebound browser cannot read the document.
func TestOpenAPISpecNonLocalHostNeedsValidToken(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	// A scan that is not running, so its token must not open the endpoint.
	repo := db.Repository{URL: "https://example.com/done", Name: "done"}
	s.DB.Create(&repo)
	finished := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, APIToken: NewAPIToken()}
	s.DB.Create(&finished)

	cases := map[string]string{
		"no token":             "",
		"garbage token":        "not-a-real-token",
		"token of a done scan": finished.APIToken,
	}
	for name, token := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil)
		r.Host = "evil.example.com"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s from a non-local host: status = %d, want %d", name, w.Code, http.StatusUnauthorized)
		}
		if bytes.Contains(w.Body.Bytes(), []byte("openapi:")) {
			t.Errorf("%s from a non-local host: response leaked the spec", name)
		}
	}
}

// Reading the spec from the host must not require a scan bearer token: an
// external tool discovering the API has no running scan to borrow one from.
func TestOpenAPISpecNeedsNoBearerToken(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := localReq(http.MethodGet, "/api/openapi.yaml")
	r.Header.Del("Authorization")
	s.Handler().ServeHTTP(w, r)

	if w.Code == http.StatusUnauthorized {
		t.Fatal("GET /api/openapi.yaml required a bearer token; the spec must be readable without a running scan")
	}
}
