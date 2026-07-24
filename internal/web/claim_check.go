package web

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
)

var claimCheckHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// claimCheckMaxBody bounds the request body; a claim-check payload is a
// single hash, so anything past a few KB is garbage.
const claimCheckMaxBody = 4096

// claimCheck answers a federation peer asking whether this instance
// holds a finding with the posted salted hash (see
// interchange.FindingHash), so the peer can coordinate before reporting
// the same finding upstream. Neither side reveals the finding: the
// request is a salted hash and a match discloses only the operator
// contact. Without federation_salt the route answers 404, so a
// non-federated instance is indistinguishable from one without the
// endpoint. Like the rest of the UI it sits behind the loopback Host
// check; exposing it to peers is a reverse-proxy decision documented in
// docs/interchange.md.
func (s *Server) claimCheck(w http.ResponseWriter, r *http.Request) {
	if s.FederationSalt == "" {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Hash string `json:"hash"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, claimCheckMaxBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	hash := strings.ToLower(strings.TrimSpace(req.Hash))
	if !claimCheckHashRe.MatchString(hash) {
		http.Error(w, "hash must be 64 hex characters", http.StatusBadRequest)
		return
	}

	// Rejected findings are ones this instance decided are not real, and
	// a duplicate is covered by its canonical sibling; neither is ours to
	// claim.
	type row struct {
		SubPath  string
		Location string
		CWE      string
		URL      string
	}
	var rows []row
	if err := s.DB.Model(&db.Finding{}).
		Select("findings.sub_path, findings.location, findings.cwe, repositories.url").
		Joins("JOIN repositories ON repositories.id = findings.repository_id").
		Where("findings.status NOT IN ?", []db.FindingLifecycle{db.FindingRejected, db.FindingDuplicate}).
		Find(&rows).Error; err != nil {
		s.Log.Error("claim-check findings", "err", err)
		http.Error(w, "failed to load findings", http.StatusInternalServerError)
		return
	}
	for _, f := range rows {
		if interchange.FindingHash(s.FederationSalt, f.URL, f.SubPath, f.Location, f.CWE) == hash {
			writeJSON(w, http.StatusOK, map[string]any{"match": true, "contact": s.FederationContact})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"match": false})
}
