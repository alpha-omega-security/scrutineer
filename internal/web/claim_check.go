package web

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
)

var claimCheckHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// claimCheckMaxBody bounds the request body; a claim-check payload is a
// single hash, so anything past a few KB is garbage.
const claimCheckMaxBody = 4096

// claimCheckTTL bounds how often the salted hash set is rebuilt from the
// findings table. A flood of requests therefore costs map lookups, not a
// table scan plus a hash per finding each time; the price is that a
// match lags finding writes by up to the TTL, which is immaterial for
// cross-instance coordination.
const claimCheckTTL = time.Minute

// claimCheckIndex caches the salted finding hashes claim-check consults.
// The map is published complete and never mutated afterwards, so readers
// may use it after the lock is released; rebuilds swap the pointer.
type claimCheckIndex struct {
	mu      sync.Mutex
	hashes  map[string]struct{}
	expires time.Time
}

// claimCheck answers a federation peer asking whether this instance
// holds a finding with the posted salted hash (see
// interchange.FindingHash), so the peer can coordinate before reporting
// the same finding upstream. Neither side reveals the finding: the
// request is a salted hash and a match discloses only the operator
// contact. Non-POST requests and instances without federation_salt
// answer a plain 404, so a non-federated instance is indistinguishable
// from one without the endpoint. Like the rest of the UI it sits behind
// the loopback Host check; exposing it to peers is a reverse-proxy
// decision documented in docs/interchange.md.
func (s *Server) claimCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || s.FederationSalt == "" {
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
	hashes, err := s.claimHashSet()
	if err != nil {
		s.Log.Error("claim-check findings", "err", err)
		http.Error(w, "failed to load findings", http.StatusInternalServerError)
		return
	}
	if _, ok := hashes[hash]; ok {
		writeJSON(w, http.StatusOK, map[string]any{"match": true, "contact": s.FederationContact})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"match": false})
}

// claimHashSet returns the salted hash of every claimable finding,
// rebuilding the cached set at most once per claimCheckTTL. Rejected
// findings are ones this instance decided are not real, and a duplicate
// is covered by its canonical sibling; neither is ours to claim.
func (s *Server) claimHashSet() (map[string]struct{}, error) {
	s.claimIndex.mu.Lock()
	defer s.claimIndex.mu.Unlock()
	if s.claimIndex.hashes != nil && time.Now().Before(s.claimIndex.expires) {
		return s.claimIndex.hashes, nil
	}
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
		return nil, err
	}
	hashes := make(map[string]struct{}, len(rows))
	for _, f := range rows {
		hashes[interchange.FindingHash(s.FederationSalt, f.URL, f.SubPath, f.Location, f.CWE)] = struct{}{}
	}
	s.claimIndex.hashes = hashes
	s.claimIndex.expires = time.Now().Add(claimCheckTTL)
	return hashes, nil
}
