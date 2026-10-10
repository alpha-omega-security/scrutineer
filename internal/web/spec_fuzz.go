package web

import (
	"net/http"

	"scrutineer/internal/specfuzz"
)

// apiListSpecFuzzClauses returns the vendored clause ids and metadata
// so a skill can decide which clauses apply to the target.
func (s *Server) apiListSpecFuzzClauses(w http.ResponseWriter, _ *http.Request) {
	ids, err := specfuzz.Clauses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type clauseInfo struct {
		ID       string `json:"id"`
		Citation string `json:"citation"`
		Protocol string `json:"protocol"`
	}
	out := struct {
		Source  string       `json:"lean_rfcs"`
		Clauses []clauseInfo `json:"clauses"`
	}{Source: specfuzz.Source}
	for _, id := range ids {
		c, err := specfuzz.LoadClause(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out.Clauses = append(out.Clauses, clauseInfo{
			ID: c.Meta.ID, Citation: c.Meta.Citation, Protocol: c.Meta.Protocol,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// apiGetSpecFuzzClause returns one clause's controls and corpus so the
// skill can run its adapter against them and report verdicts.
func (s *Server) apiGetSpecFuzzClause(w http.ResponseWriter, r *http.Request) {
	c, err := specfuzz.LoadClause(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Meta     specfuzz.ClauseMeta    `json:"meta"`
		Controls specfuzz.Controls      `json:"controls"`
		Corpus   []specfuzz.CorpusInput `json:"corpus"`
	}{c.Meta, c.Controls, c.Corpus})
}
