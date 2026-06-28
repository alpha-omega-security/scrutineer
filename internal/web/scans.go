package web

import (
	"context"
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
	status := r.URL.Query().Get(statusKey)
	if status != "" {
		q = q.Where("status = ?", status)
	}

	sort := r.URL.Query().Get("sort")
	switch sort {
	case "skill":
		q = q.Order("skill_name, id desc")
	case statusKey:
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
	stats := s.scanListStats()

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
		"AnySubPath": anySubPath, "QueuedCount": stats.QueuedCount, "PausedCount": stats.PausedCount,
		"AccountPausedCount": stats.AccountPausedCount,
	})
}

type scanListStats struct {
	QueuedCount        int64
	PausedCount        int64
	AccountPausedCount int64
}

func (s *Server) scanListStats() scanListStats {
	var stats scanListStats
	s.DB.Model(&db.Scan{}).
		Select(
			"COUNT(CASE WHEN status = ? THEN 1 END) AS queued_count, "+
				"COUNT(CASE WHEN status = ? THEN 1 END) AS paused_count, "+
				"COUNT(CASE WHEN status = ? AND error LIKE ? THEN 1 END) AS account_paused_count",
			db.ScanQueued,
			db.ScanPaused,
			db.ScanPaused,
			worker.ClaudeAccountPausePrefix+"%",
		).
		Scan(&stats)
	return stats
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
		Effort:            scan.Effort,
		FindingID:         scan.FindingID,
		SubPath:           scan.SubPath,
		Ref:               scan.Ref,
		Profile:           scan.Profile,
		SessionID:         sessionID,
		ResumedFromScanID: resumeOf,
		// An ingest scan's input is the uploaded payload, not ./src;
		// without it the retry stages no import/report and the model
		// runs against a missing file.
		ImportPayload: scan.ImportPayload,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", newID))
}

// resumeOpts decides whether a retry of scan should resume its claude
// session. Failed scans and soft-success scans that hit max turns are
// resumable when they captured a session; ordinary done/cancelled scans, or
// scans that never reached the model, retry fresh. ResumedFromScanID is pinned
// to the lineage root so a chain of retries all reuse one workspace and
// session rather than forking a new one each time.
func resumeOpts(scan db.Scan) (sessionID string, resumeOf *uint) {
	resumableStatus := scan.Status == db.ScanFailed || (scan.Status == db.ScanDone && scan.MaxTurnsHit)
	if !resumableStatus || scan.SessionID == "" {
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
	err := q.Select("id, repository_id, skill_id, model, effort, finding_id, sub_path, ref, profile, status, session_id, resumed_from_scan_id, import_payload").
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
			Effort:            sc.Effort,
			FindingID:         sc.FindingID,
			SubPath:           sc.SubPath,
			Ref:               sc.Ref,
			Profile:           sc.Profile,
			SessionID:         sessionID,
			ResumedFromScanID: resumeOf,
			ImportPayload:     sc.ImportPayload,
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

func (s *Server) scansPauseQueued(w http.ResponseWriter, r *http.Request) {
	var scans []db.Scan
	if err := s.DB.Where("status = ?", db.ScanQueued).Find(&scans).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	for _, sc := range scans {
		s.DB.Model(&db.Scan{}).Where("id = ? AND status = ?", sc.ID, db.ScanQueued).Updates(map[string]any{
			statusKey:         db.ScanPaused,
			"status_priority": db.StatusPriorityFor(db.ScanPaused),
			errorKey:          "paused by user",
			"finished_at":     &now,
		})
	}
	setFlash(w, Flash{Category: successKey, Title: fmt.Sprintf("%d queued scans paused", len(scans))})
	s.redirect(w, r, "/scans?status=paused")
}

func (s *Server) scansResumePaused(w http.ResponseWriter, r *http.Request) {
	repoID, _ := strconv.Atoi(r.URL.Query().Get("repository"))
	q := s.DB.Where("status = ?", db.ScanPaused)
	if repoID > 0 {
		q = q.Where("repository_id = ?", repoID)
	}
	var scans []db.Scan
	if err := q.Find(&scans).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var resumed, errored int
	for _, sc := range scans {
		if err := s.resumeScan(r.Context(), &sc); err != nil {
			errored++
			continue
		}
		resumed++
	}
	cat := successKey
	if errored > 0 {
		cat = errorKey
	}
	setFlash(w, Flash{Category: cat, Title: fmt.Sprintf("%d paused scans resumed", resumed)})
	// Repo-scoped resumes return to that repo's Scans tab so the operator stays
	// in context; otherwise we send them to the global queued list.
	if repoID > 0 {
		s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt3", repoID))
		return
	}
	s.redirect(w, r, "/scans?status=queued")
}

func (s *Server) scanResume(w http.ResponseWriter, r *http.Request) {
	scan, ok := loadByID[db.Scan](s, w, r)
	if !ok {
		return
	}
	if scan.Status != db.ScanPaused {
		http.Error(w, "scan is not paused", http.StatusBadRequest)
		return
	}
	if err := s.resumeScan(r.Context(), &scan); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", scan.ID))
}

func (s *Server) resumeScan(ctx context.Context, scan *db.Scan) error {
	priority := worker.PrioScan
	if scan.FindingID != nil {
		priority = worker.PrioFinding
	}
	if err := s.Queue.Enqueue(ctx, scan.Kind, scan.ID, priority); err != nil {
		return err
	}
	return s.DB.Model(&db.Scan{}).Where("id = ? AND status = ?", scan.ID, db.ScanPaused).Updates(map[string]any{
		statusKey:         db.ScanQueued,
		"status_priority": db.StatusPriorityFor(db.ScanQueued),
		errorKey:          "",
		"finished_at":     nil,
	}).Error
}

func retryFailedToast(retried, skipped, errored int) Flash {
	if retried == 0 && skipped == 0 && errored == 0 {
		return Flash{Category: successKey, Title: "No failed scans to retry"}
	}
	parts := []string{fmt.Sprintf("%d retried", retried)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", skipped))
	}
	if errored > 0 {
		parts = append(parts, fmt.Sprintf("%d errored", errored))
	}
	cat := successKey
	switch {
	case errored > 0:
		cat = errorKey
	case retried == 0:
		cat = warningKey
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
	if scan.Status == db.ScanPaused {
		http.Error(w, "scan is paused", http.StatusBadRequest)
		return
	}
	if s.cancelScan(&scan) {
		// A queued scan isn't in flight, so the worker never publishes a
		// scan-status event for it; push one ourselves so the repo Scans tab
		// and the scan page reflect the cancellation live.
		s.Broker.Publish(Event{Name: "scan-status", ScanID: scan.ID, RepoID: scan.RepositoryID})
	}
	// Deliberately no redirect: cancelling from a list (repo Scans tab, jobs)
	// should leave the operator on that list so they can cancel the next one,
	// rather than bouncing to the scan page on every click. htmx clients get a
	// live row update over SSE; the plain-form fallback reloads the referrer.
	if isHX(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ref := sameOriginReferer(r); ref != "" {
		http.Redirect(w, r, ref, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/scans/%d", scan.ID), http.StatusSeeOther)
}

// sameOriginReferer returns the Referer header value only if it points back at
// this server (same host, or a host-less path). Anything else is dropped so a
// "redirect back where you came from" handler can't be turned into an open
// redirect by a forged Referer. Opaque URIs (javascript:, data:, the
// http:evil.com form) parse with an empty Host and are rejected explicitly.
func sameOriginReferer(r *http.Request) string {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	switch {
	case err != nil,
		u.Opaque != "",
		u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https",
		u.Host != "" && u.Host != r.Host:
		return ""
	}
	return ref
}

// cancelScan aborts one non-terminal scan. A running scan is signalled through
// the worker, which flips its row and publishes scan-status as it unwinds; a
// queued scan isn't in flight, so we flip the row here (the queue handler drops
// a cancelled row on pickup) and return true so the caller can publish a
// scan-status event itself. Returns false when there was nothing to do.
func (s *Server) cancelScan(scan *db.Scan) (flippedQueued bool) {
	if s.Worker.Cancel(scan.ID) {
		return false
	}
	now := time.Now()
	// Gate on the live status so a scan the worker picks up between the caller's
	// read and this write doesn't get a "cancelled" row while it keeps running.
	res := s.DB.Model(&db.Scan{}).
		Where("id = ? AND status IN ?", scan.ID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
		Updates(map[string]any{
			statusKey:         db.ScanCancelled,
			"status_priority": db.StatusPriorityFor(db.ScanCancelled),
			errorKey:          "cancelled by user",
			"finished_at":     &now,
		})
	return res.RowsAffected > 0
}

// scansCancelAll cancels every queued or running scan on a repository — the
// bulk companion to the per-row Cancel button, so an operator who fired off a
// batch can stop them all in one click instead of cancelling each in turn.
func (s *Server) scansCancelAll(w http.ResponseWriter, r *http.Request) {
	repoID, _ := strconv.Atoi(r.URL.Query().Get("repository"))
	if repoID <= 0 {
		http.Error(w, "missing repository", http.StatusBadRequest)
		return
	}
	var scans []db.Scan
	if err := s.DB.Where("repository_id = ? AND status IN ?",
		repoID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).Find(&scans).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var cancelled int
	for i := range scans {
		s.cancelScan(&scans[i])
		cancelled++
	}
	setFlash(w, Flash{Category: successKey, Title: fmt.Sprintf("%d scan(s) cancelled", cancelled)})
	// Back to the Scans tab: the redirect re-renders the table with fresh DB
	// state, so every flipped row shows "cancelled" without per-scan SSE pushes.
	s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt3", repoID))
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
