package web

import (
	"net/http"

	"scrutineer"
)

// openAPISpec serves the embedded openapi.yaml.
//
// It is registered on the root mux rather than inside apiHandler because
// apiAuth only accepts a bearer token belonging to a RUNNING scan: a tool
// discovering the API has no scan to borrow a token from, so serving the spec
// from behind that middleware would defeat the point of serving it at all.
// Reading it is unauthenticated but still host-only via securityHeaders, the
// same boundary the /api/v1 export surface relies on (see threatmodel.md).
// The document is already public in the repository, so this discloses nothing
// a reader could not fetch from GitHub.
func (s *Server) openAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	if _, err := w.Write(scrutineer.OpenAPISpec); err != nil {
		s.Log.Error("serve openapi spec", "err", err)
	}
}
