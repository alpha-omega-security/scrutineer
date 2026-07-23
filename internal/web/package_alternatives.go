package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/git-pkgs/purl"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

type packageAlternativeResponse struct {
	ID           uint   `json:"id"`
	RepositoryID uint   `json:"repository_id"`
	PURL         string `json:"purl"`
	Kind         string `json:"kind"`
	Note         string `json:"note,omitempty"`
}

func (s *Server) apiListPackageAlternatives(w http.ResponseWriter, r *http.Request) {
	repoID, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	rows, err := loadPackageAlternatives(s.DB, repoID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, packageAlternativeResponses(rows))
}

func (s *Server) repoPackageAlternativeCreate(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	row, err := buildPackageAlternative(repo.ID, r.FormValue("purl"), r.FormValue("kind"), r.FormValue("note"))
	if err != nil {
		setFlash(w, Flash{Category: errorKey, Title: err.Error()})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt15", repo.ID))
		return
	}
	if err := s.DB.Create(&row).Error; err != nil {
		setFlash(w, Flash{Category: errorKey, Title: "Alternative not saved", Description: err.Error()})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt15", repo.ID))
		return
	}
	setFlash(w, Flash{Category: successKey, Title: "Alternative saved"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt15", repo.ID))
}

func (s *Server) repoPackageAlternativeDelete(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	altID, err := strconv.Atoi(r.PathValue("alternative_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	res := s.DB.Where("repository_id = ? AND id = ?", repo.ID, altID).Delete(&db.PackageAlternative{})
	if res.Error != nil {
		setFlash(w, Flash{Category: errorKey, Title: "Alternative not deleted", Description: res.Error.Error()})
	} else if res.RowsAffected > 0 {
		setFlash(w, Flash{Category: successKey, Title: "Alternative deleted"})
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt15", repo.ID))
}

func buildPackageAlternative(repoID uint, purlValue, kindValue, note string) (db.PackageAlternative, error) {
	purlValue = strings.TrimSpace(purlValue)
	if purlValue == "" {
		return db.PackageAlternative{}, fmt.Errorf("purl is required")
	}
	if _, err := purl.Parse(purlValue); err != nil {
		return db.PackageAlternative{}, fmt.Errorf("purl is invalid")
	}
	kind, err := packageAlternativeKind(kindValue)
	if err != nil {
		return db.PackageAlternative{}, err
	}
	return db.PackageAlternative{
		RepositoryID: repoID,
		PURL:         purlValue,
		Kind:         kind,
		Note:         strings.TrimSpace(note),
	}, nil
}

func packageAlternativeKind(value string) (db.PackageAlternativeKind, error) {
	switch db.PackageAlternativeKind(strings.TrimSpace(value)) {
	case db.PackageAlternativeFork:
		return db.PackageAlternativeFork, nil
	case db.PackageAlternativeSuccessor:
		return db.PackageAlternativeSuccessor, nil
	case db.PackageAlternativeEquivalent:
		return db.PackageAlternativeEquivalent, nil
	default:
		return "", fmt.Errorf("kind must be fork, successor, or equivalent")
	}
}

func loadPackageAlternatives(gdb *gorm.DB, repoID uint) ([]db.PackageAlternative, error) {
	var rows []db.PackageAlternative
	if err := gdb.Where("repository_id = ?", repoID).Order("kind, p_url").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func showPackageAlternatives(repo db.Repository, rows []db.PackageAlternative) bool {
	return len(rows) > 0 || repo.Health == db.RepositoryHealthAbandoned || repo.Health == db.RepositoryHealthZombie
}

func packageAlternativeResponses(rows []db.PackageAlternative) []packageAlternativeResponse {
	out := make([]packageAlternativeResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, packageAlternativeResponse{
			ID:           row.ID,
			RepositoryID: row.RepositoryID,
			PURL:         row.PURL,
			Kind:         string(row.Kind),
			Note:         row.Note,
		})
	}
	return out
}
