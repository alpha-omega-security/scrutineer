package web

import (
	"net/http"
	"strconv"
	"strings"

	"scrutineer/internal/db"
)

func (s *Server) skillsList(w http.ResponseWriter, r *http.Request) {
	var skills []db.Skill
	s.DB.Order("active desc, name asc").Find(&skills)
	s.render(w, "skills.html", map[string]any{"Skills": skills})
}

func (s *Server) skillShow(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var skill db.Skill
	if err := s.DB.First(&skill, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "skill_show.html", map[string]any{"S": skill})
}

func (s *Server) skillNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, "skill_form.html", map[string]any{
		"S":      db.Skill{Active: true, Source: "ui"},
		"Action": "/skills",
		"Verb":   "Create",
	})
}

func (s *Server) skillEdit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var skill db.Skill
	if err := s.DB.First(&skill, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "skill_form.html", map[string]any{
		"S":      skill,
		"Action": "/skills/" + strconv.Itoa(int(skill.ID)),
		"Verb":   "Save",
	})
}

func (s *Server) skillCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	skill := db.Skill{
		Name:        strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")),
		Body:        r.FormValue("body"),
		OutputFile:  strings.TrimSpace(r.FormValue("output_file")),
		OutputKind:  strings.TrimSpace(r.FormValue("output_kind")),
		SchemaJSON:  r.FormValue("schema_json"),
		Source:      "ui",
		Active:      true,
		Version:     1,
	}
	if skill.Name == "" || skill.Description == "" {
		http.Error(w, "name and description are required", http.StatusBadRequest)
		return
	}
	if err := s.DB.Create(&skill).Error; err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/skills/"+strconv.Itoa(int(skill.ID)), http.StatusSeeOther)
}

func (s *Server) skillUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var skill db.Skill
	if err := s.DB.First(&skill, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	skill.Name = strings.TrimSpace(r.FormValue("name"))
	skill.Description = strings.TrimSpace(r.FormValue("description"))
	skill.Body = r.FormValue("body")
	skill.OutputFile = strings.TrimSpace(r.FormValue("output_file"))
	skill.OutputKind = strings.TrimSpace(r.FormValue("output_kind"))
	skill.SchemaJSON = r.FormValue("schema_json")
	skill.Active = r.FormValue("active") == "on"
	skill.Version++
	if err := s.DB.Save(&skill).Error; err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/skills/"+strconv.Itoa(int(skill.ID)), http.StatusSeeOther)
}

// skillRun enqueues a skill-backed scan for a repo. Accepts skill_id and
// optional model as form fields; posted from the repo page's skill picker.
func (s *Server) skillRun(w http.ResponseWriter, r *http.Request) {
	repoID, _ := strconv.Atoi(r.PathValue("id"))
	skillID, _ := strconv.Atoi(r.FormValue("skill_id"))
	if repoID == 0 || skillID == 0 {
		http.Error(w, "repo id and skill id required", http.StatusBadRequest)
		return
	}
	var skill db.Skill
	if err := s.DB.First(&skill, skillID).Error; err != nil || !skill.Active {
		http.Error(w, "skill not found or inactive", http.StatusNotFound)
		return
	}
	scanID, err := s.enqueueSkill(r.Context(), uint(repoID), uint(skillID), r.FormValue("model"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/scans/"+strconv.FormatUint(uint64(scanID), 10), http.StatusSeeOther)
}
