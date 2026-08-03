package web

import (
	"net/http"

	"scrutineer"
)

// openAPISpecHandler serves the embedded openapi.yaml under two access rules,
// because the two callers the document exists for reach the server very
// differently.
//
// A caller on the host -- the browser UI, curl, a tool discovering the API --
// gets it unauthenticated. It has no running scan to borrow a bearer token
// from, so requiring one would defeat the point of serving the spec at all;
// the Host check is what keeps a DNS-rebound browser out, the same boundary
// the /api/v1 export surface relies on (see threatmodel.md).
//
// A skill inside the runner container cannot satisfy that check. context.json
// advertises the runtime's host endpoint (host.docker.internal for
// docker/podman, the default gateway IP under Apple's container), and the
// egress proxy rewrites the dial target to loopback but forwards the original
// Host, so the request arrives with a non-local Host and would 403. Those
// callers instead present the per-scan bearer token they already hold for the
// rest of /api. That is not a weaker boundary: a rebound browser cannot mint a
// running scan's token, and it cannot attach an Authorization header
// cross-origin without a preflight this server never answers.
//
// The document is already public in the repository either way, so neither path
// discloses anything a reader could not fetch from GitHub.
func (s *Server) openAPISpecHandler() http.Handler {
	spec := http.HandlerFunc(s.openAPISpec)
	fromHost := securityHeaders(spec)
	fromContainer := s.apiAuth(spec)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if localHost(r.Host) {
			fromHost.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", cspPolicy)
		fromContainer.ServeHTTP(w, r)
	})
}

// openAPISpec writes the embedded copy of the repository's openapi.yaml.
// openAPISpecHandler owns the access rules; this only serves bytes.
func (s *Server) openAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	if _, err := w.Write(scrutineer.OpenAPISpec); err != nil {
		s.Log.Error("serve openapi spec", "err", err)
	}
}
