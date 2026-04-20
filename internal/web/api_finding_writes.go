package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"scrutineer/internal/db"
)

// The handlers below let skills (and the browser UI) mutate a finding:
// edit scoring fields, append notes, log communications, add references,
// set labels, and read the full change history. Auth scoping holds: the
// authenticated scan's repository must own the finding.

func (s *Server) apiPatchFinding(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	repoID, ok := s.findingRepoID(uint(id))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "finding not found")
		return
	}
	if !s.scanOwnsRepo(r, repoID) {
		writeAPIError(w, http.StatusForbidden, "scan may only edit findings on its own repository")
		return
	}
	var body struct {
		Fields map[string]string `json:"fields"`
		By     string            `json:"by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "body must be JSON with a fields map")
		return
	}
	source := sourceFromRequest(r)
	for field, value := range body.Fields {
		if err := db.WriteFindingField(s.DB, uint(id), field, value, source, body.By); err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiAddFindingNote(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var body struct {
		Body string `json:"body"`
		By   string `json:"by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "body must be JSON")
		return
	}
	n, err := db.AddFindingNote(s.DB, id, body.Body, body.By)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) apiListFindingNotes(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var rows []db.FindingNote
	s.DB.Where("finding_id = ?", id).Order("created_at desc").Find(&rows)
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) apiAddFindingCommunication(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var body struct {
		Channel     string    `json:"channel"`
		Direction   string    `json:"direction"`
		Actor       string    `json:"actor"`
		Body        string    `json:"body"`
		OfferedHelp string    `json:"offered_help"`
		At          time.Time `json:"at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "body must be JSON")
		return
	}
	c, err := db.AddFindingCommunication(s.DB, id, body.Channel, body.Direction, body.Actor, body.Body, body.OfferedHelp, body.At)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) apiListFindingCommunications(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var rows []db.FindingCommunication
	s.DB.Where("finding_id = ?", id).Order("at desc").Find(&rows)
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) apiAddFindingReference(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var body struct {
		URL     string `json:"url"`
		Tags    string `json:"tags"`
		Summary string `json:"summary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "body must be JSON")
		return
	}
	ref, err := db.AddFindingReference(s.DB, id, body.URL, body.Tags, body.Summary)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ref)
}

func (s *Server) apiListFindingReferences(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var rows []db.FindingReference
	s.DB.Where("finding_id = ?", id).Order("id desc").Find(&rows)
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) apiSetFindingLabels(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var body struct {
		Labels []string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "body must be JSON with a labels array")
		return
	}
	if err := db.SetFindingLabels(s.DB, id, body.Labels); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiListFindingHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var rows []db.FindingHistory
	s.DB.Where("finding_id = ?", id).Order("created_at desc").Find(&rows)
	writeJSON(w, http.StatusOK, rows)
}

// findingScoped parses the path id, resolves its repository, and enforces
// the scan-owns-repo auth rule. Returns false when the response has
// already been written with the appropriate error.
func (s *Server) findingScoped(w http.ResponseWriter, r *http.Request) (uint, bool) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	repoID, ok := s.findingRepoID(uint(id))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "finding not found")
		return 0, false
	}
	if !s.scanOwnsRepo(r, repoID) {
		writeAPIError(w, http.StatusForbidden, "scan may only act on findings on its own repository")
		return 0, false
	}
	return uint(id), true
}

// sourceFromRequest picks model_suggested when the authenticated scan has
// a skill context (skills write as themselves) and analyst otherwise. The
// browser UI currently also uses bearer tokens, so analyst edits come
// through with the finding-scoped scan's token; we treat those as
// model_suggested here. Bypass path for purely UI edits lives in the
// server's non-API handlers (findingStatus, findingNotes) which write
// with source=analyst directly.
func sourceFromRequest(r *http.Request) db.FindingSource {
	sc := scanFromRequest(r)
	if sc != nil && sc.SkillID != nil {
		return db.SourceModel
	}
	return db.SourceAnalyst
}
