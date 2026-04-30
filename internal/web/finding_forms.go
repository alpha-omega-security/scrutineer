package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"scrutineer/internal/db"
)

// The browser-form handlers write finding mutations with
// source=analyst. Skills hit the /api counterparts, which pick
// source=model_suggested automatically.

// analystFields is the set of fields the finding edit form exposes. Any
// field not in this list is silently dropped; WriteFindingField would
// reject it anyway.
var analystFields = []string{
	"title", "severity", "cwe", "location", "affected",
	"cve_id", "cvss_vector", "fix_version", "fix_commit",
	"resolution", "disclosure_draft", "assignee",
}

func (s *Server) findingFields(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, field := range analystFields {
		value, ok := r.Form[field]
		if !ok {
			continue
		}
		if err := db.WriteFindingField(s.DB, f.ID, field, strings.TrimSpace(value[0]), db.SourceAnalyst, ""); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

func (s *Server) findingCommunications(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	at, _ := time.Parse("2006-01-02", r.FormValue("at"))
	if _, err := db.AddFindingCommunication(s.DB, f.ID,
		r.FormValue("channel"),
		r.FormValue("direction"),
		r.FormValue("actor"),
		r.FormValue("body"),
		r.FormValue("offered_help"),
		at,
	); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

func (s *Server) findingReferences(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tags := r.FormValue("tags")
	if _, err := db.AddFindingReference(s.DB, f.ID, r.FormValue("url"), tags, r.FormValue("summary")); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

func (s *Server) findingLabels(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Labels arrive either as multiple labels= form fields (from checkboxes)
	// or as one comma-joined free-text value.
	raw := r.Form["labels"]
	if len(raw) == 1 && strings.Contains(raw[0], ",") {
		raw = strings.Split(raw[0], ",")
	}
	names := make([]string, 0, len(raw))
	for _, n := range raw {
		n = strings.TrimSpace(n)
		if n != "" {
			names = append(names, n)
		}
	}
	if err := db.SetFindingLabels(s.DB, f.ID, names); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}
