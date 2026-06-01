package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func (s *Server) jobs(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Scan{})
	skillName := r.URL.Query().Get("skill")
	if skillName != "" {
		q = q.Where("skill_name = ?", skillName)
	}
	status := r.URL.Query().Get("status")
	if status != "" {
		q = q.Where("status = ?", status)
	}

	sort := r.URL.Query().Get("sort")
	switch sort {
	case "skill":
		q = q.Order("skill_name, id desc")
	case "status":
		q = q.Order("status, id desc")
	case sortRepository:
		q = q.Joins("Repository").Order("`Repository`.name, scans.id desc")
	default:
		sort = defaultSort
		q = q.Order("status_priority, scans.id desc")
	}

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var scans []db.Scan
	q.Preload("Repository").
		Limit(perPage).Offset((page.N - 1) * perPage).Find(&scans)

	skillNames := s.scanSkillNames()

	anySubPath := false
	for _, sc := range scans {
		if sc.SubPath != "" {
			anySubPath = true
			break
		}
	}
	s.render(w, r, "jobs.html", map[string]any{
		"Scans": scans, "Page": page,
		"Skill": skillName, "Status": status, "Sort": sort, "Skills": skillNames,
		"AnySubPath": anySubPath,
	})
}

const skillNamesCacheTTL = 30 * time.Second

func (s *Server) scanSkillNames() []string {
	s.skillNamesMu.Lock()
	defer s.skillNamesMu.Unlock()
	if time.Now().Before(s.skillNamesTTL) {
		return s.skillNamesCache
	}
	var names []string
	s.DB.Model(&db.Scan{}).Where("skill_name != ''").Distinct("skill_name").
		Order("skill_name").Pluck("skill_name", &names)
	s.skillNamesCache = names
	s.skillNamesTTL = time.Now().Add(skillNamesCacheTTL)
	return names
}

func (s *Server) scanShow(w http.ResponseWriter, r *http.Request) {
	var scan db.Scan
	if err := s.DB.Preload("Repository").Preload("Findings").First(&scan, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "scan_show.html", map[string]any{"Scan": scan})
}

func (s *Server) scanRetry(w http.ResponseWriter, r *http.Request) {
	scan, ok := loadByID[db.Scan](s, w, r)
	if !ok {
		return
	}
	if scan.Kind != worker.JobSkill || scan.SkillID == nil {
		http.Error(w, "scan cannot be retried: no skill reference", http.StatusBadRequest)
		return
	}
	sessionID, resumeOf := resumeOpts(scan)
	newID, err := s.enqueueSkillWith(r.Context(), scan.RepositoryID, *scan.SkillID, ScanOpts{
		Model:             scan.Model,
		FindingID:         scan.FindingID,
		SubPath:           scan.SubPath,
		Ref:               scan.Ref,
		Profile:           scan.Profile,
		SessionID:         sessionID,
		ResumedFromScanID: resumeOf,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", newID))
}

// resumeOpts decides whether a retry of scan should resume its claude
// session. Only a failed scan that captured a session is resumable; a done
// or cancelled scan, or one that never reached the model, retries fresh.
// ResumedFromScanID is pinned to the lineage root so a chain of retries all
// reuse one workspace and session rather than forking a new one each time.
func resumeOpts(scan db.Scan) (sessionID string, resumeOf *uint) {
	if scan.Status != db.ScanFailed || scan.SessionID == "" {
		return "", nil
	}
	root := scan.ID
	if scan.ResumedFromScanID != nil && *scan.ResumedFromScanID != 0 {
		root = *scan.ResumedFromScanID
	}
	return scan.SessionID, &root
}

func (s *Server) scansRetryFailed(w http.ResponseWriter, r *http.Request) {
	skillName := r.URL.Query().Get("skill")
	repoID, _ := strconv.Atoi(r.URL.Query().Get("repository"))
	q := s.DB.Model(&db.Scan{}).
		Where("status = ? AND kind = ? AND skill_id IS NOT NULL", db.ScanFailed, worker.JobSkill)
	if skillName != "" {
		q = q.Where("skill_name = ?", skillName)
	}
	if repoID > 0 {
		q = q.Where("repository_id = ?", repoID)
	}

	var totalFailed int64
	q.Count(&totalFailed)

	// Skip any failed scan that has a later scan with the same
	// (repository, skill, sub_path, ref, finding_id) tuple already in
	// queued/running/done.
	var scans []db.Scan
	err := q.Select("id, repository_id, skill_id, model, finding_id, sub_path, ref, profile, status, session_id, resumed_from_scan_id").
		Where(`NOT EXISTS (
			SELECT 1 FROM scans n
			WHERE n.id > scans.id
			  AND n.repository_id = scans.repository_id
			  AND COALESCE(n.skill_id, 0) = COALESCE(scans.skill_id, 0)
			  AND COALESCE(n.sub_path, '') = COALESCE(scans.sub_path, '')
			  AND COALESCE(n.ref, '') = COALESCE(scans.ref, '')
			  AND COALESCE(n.finding_id, 0) = COALESCE(scans.finding_id, 0)
			  AND n.status IN ?
		)`, []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanDone}).
		Find(&scans).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var retried, errored int
	for _, sc := range scans {
		sessionID, resumeOf := resumeOpts(sc)
		if _, err := s.enqueueSkillWith(r.Context(), sc.RepositoryID, *sc.SkillID, ScanOpts{
			Model:             sc.Model,
			FindingID:         sc.FindingID,
			SubPath:           sc.SubPath,
			Ref:               sc.Ref,
			Profile:           sc.Profile,
			SessionID:         sessionID,
			ResumedFromScanID: resumeOf,
		}); err != nil {
			errored++
			continue
		}
		retried++
	}
	skipped := int(totalFailed) - retried - errored

	setFlash(w, retryFailedToast(retried, skipped, errored))
	// Repo-scoped retries return to that repo's Scans tab so the operator
	// stays in context; otherwise we send them to the global jobs list
	// filtered to failed.
	target := "/scans?status=failed"
	if repoID > 0 {
		target = fmt.Sprintf("/repositories/%d#rt3", repoID)
	} else if skillName != "" {
		target += "&skill=" + url.QueryEscape(skillName)
	}
	s.redirect(w, r, target)
}

func retryFailedToast(retried, skipped, errored int) Flash {
	if retried == 0 && skipped == 0 && errored == 0 {
		return Flash{Category: "success", Title: "No failed scans to retry"}
	}
	parts := []string{fmt.Sprintf("%d retried", retried)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", skipped))
	}
	if errored > 0 {
		parts = append(parts, fmt.Sprintf("%d errored", errored))
	}
	cat := "success"
	switch {
	case errored > 0:
		cat = "error"
	case retried == 0:
		cat = "warning"
	}
	return Flash{Category: cat, Title: strings.Join(parts, ", ")}
}

func (s *Server) scanCancel(w http.ResponseWriter, r *http.Request) {
	scan, ok := loadByID[db.Scan](s, w, r)
	if !ok {
		return
	}
	if scan.Status.Terminal() {
		http.Error(w, "scan already finished", http.StatusBadRequest)
		return
	}
	if !s.Worker.Cancel(scan.ID) {
		// Not in flight: mark the row so the queue handler drops it on pickup.
		s.DB.Model(&scan).Updates(map[string]any{
			"status":      db.ScanCancelled,
			"error":       "cancelled by user",
			"finished_at": new(time.Now()),
		})
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", scan.ID))
}

// scanLog returns just the <pre> log block. The scan page polls this with
// hx-trigger while the scan is running so the operator can watch claude work.
func (s *Server) scanLog(w http.ResponseWriter, r *http.Request) {
	scan, ok := loadByID[db.Scan](s, w, r)
	if !ok {
		return
	}
	if scan.Status != db.ScanQueued && scan.Status != db.ScanRunning {
		// Tell htmx to do a full refresh so the report renders.
		w.Header().Set("HX-Refresh", "true")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "scan_log.html", scan); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
