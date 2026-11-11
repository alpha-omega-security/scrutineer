package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func (s *Server) findingDependentCampaignUpdate(w http.ResponseWriter, r *http.Request) {
	finding, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	dependentID, err := strconv.Atoi(r.PathValue("dependent_id"))
	if err != nil || dependentID <= 0 {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err = db.SetFindingDependentCampaign(
		s.DB,
		finding.ID,
		uint(dependentID),
		db.DependentCampaignStatus(r.FormValue("status")),
		r.FormValue("note"),
	)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	setFlash(w, Flash{Category: successKey, Title: "Dependent campaign updated"})
	s.redirect(w, r, fmt.Sprintf("/findings/%d#migration-guide", finding.ID))
}
