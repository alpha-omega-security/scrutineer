package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

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

	if got := w.Body.Bytes(); string(got) != string(onDisk) {
		t.Errorf("served spec differs from openapi.yaml (%d served bytes, %d on disk)", len(got), len(onDisk))
	}
}

// The spec is unauthenticated but keeps the host-only boundary the rest of the
// browser surface relies on; see threatmodel.md.
func TestOpenAPISpecRejectsNonLocalHost(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil)
	r.Host = "evil.example.com"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("non-local host status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// Reading the spec must not require a scan bearer token: an external tool
// discovering the API has no running scan to borrow one from.
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
