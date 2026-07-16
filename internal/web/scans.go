package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

	sortCol, dir := splitSort(r.URL.Query().Get("sort"))
	switch sortCol {
	case "id":
		q = q.Order(orderByExpr("scans.id", dir, true))
	case "skill":
		q = q.Order(orderByExpr("skill_name", dir, false)).Order("scans.id desc")
	case statusKey:
		q = q.Order(orderByExpr("status", dir, false)).Order("scans.id desc")
	case sortRepository:
		q = q.Joins("Repository").Order(orderByExpr("`Repository`.name", dir, false)).Order("scans.id desc")
	case "findings":
		// findings_count is a denormalised column on the scan row.
		q = q.Order(orderByExpr("findings_count", dir, true)).Order("scans.id desc")
	default:
		sortCol, dir = defaultSort, ""
		q = q.Order("status_priority, scans.id desc")
	}
	sort := joinSort(sortCol, dir)

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
		"NextAccountResume":  stats.NextAccountResume,
		"ModelDowngraded":    s.Worker.ShouldDowngradeModel(),
	})
}

type scanListStats struct {
	QueuedCount        int64
	PausedCount        int64
	AccountPausedCount int64
	NextAccountResume  *time.Time
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
			worker.AccountPausePrefix+"%",
		).
		Scan(&stats)
	var next db.Scan
	s.DB.Select("id", "paused_until").
		Where("status = ? AND error LIKE ? AND paused_until IS NOT NULL", db.ScanPaused, worker.AccountPausePrefix+"%").
		Order("paused_until ASC").
		Limit(1).
		Find(&next)
	stats.NextAccountResume = next.PausedUntil
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
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.Preload("Repository").Preload("Findings").First(&scan, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "scan_show.html", map[string]any{
		"Scan": scan,
		"Diff": parseScanDiffView(scan),
	})
}

// scanDiffView is the parsed diff-rescan metadata for the scan page,
// merged from the two JSON blobs the worker writes: Coverage (requested vs
// actual mode plus a fallback reason) and DiffStats (changed-file list and
// patch size). Nil when the scan carried neither.
type scanDiffView struct {
	RequestedMode  string
	ActualMode     string
	FallbackReason string
	ChangedFiles   int
	PatchBytes     int64
	Files          []scanDiffFile
}

type scanDiffFile struct {
	Status string `json:"status"`
	Path   string `json:"path"`
	Old    string `json:"old"`
}

// StatusName expands the git --name-status letter to a word so the
// changed-files table reads without a legend. Rename/copy carry a
// similarity score suffix (R100, C075) which is dropped here; the
// old→new path already conveys the rename.
func (f scanDiffFile) StatusName() string {
	if f.Status == "" {
		return ""
	}
	switch f.Status[0] {
	case 'A':
		return "added"
	case 'M':
		return "modified"
	case 'D':
		return "deleted"
	case 'R':
		return "renamed"
	case 'C':
		return "copied"
	case 'T':
		return "type change"
	}
	return f.Status
}

// Linkable reports whether the file exists at the head commit and so can
// be linked through the in-app blob route. Deleted files only existed at
// the base commit.
func (f scanDiffFile) Linkable() bool {
	return f.Status != "" && f.Status[0] != 'D'
}

func parseScanDiffView(scan db.Scan) *scanDiffView {
	if scan.Coverage == "" && scan.DiffStats == "" {
		return nil
	}
	var v scanDiffView
	if scan.Coverage != "" {
		var cov struct {
			RequestedMode  string `json:"requested_mode"`
			ActualMode     string `json:"actual_mode"`
			FallbackReason string `json:"fallback_reason"`
		}
		if json.Unmarshal([]byte(scan.Coverage), &cov) == nil {
			v.RequestedMode = cov.RequestedMode
			v.ActualMode = cov.ActualMode
			v.FallbackReason = cov.FallbackReason
		}
	}
	if scan.DiffStats != "" {
		var stats struct {
			ChangedFiles int            `json:"changed_files"`
			PatchBytes   int64          `json:"patch_bytes"`
			Files        []scanDiffFile `json:"files"`
		}
		if json.Unmarshal([]byte(scan.DiffStats), &stats) == nil {
			v.ChangedFiles = stats.ChangedFiles
			v.PatchBytes = stats.PatchBytes
			v.Files = stats.Files
		}
	}
	return &v
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
	sessionID, resumeOf := s.resumeOpts(scan)
	newID, err := s.enqueueSkillWith(r.Context(), scan.RepositoryID, *scan.SkillID, ScanOpts{
		Model:             scan.Model,
		Effort:            scan.Effort,
		FindingID:         scan.FindingID,
		SubPath:           scan.SubPath,
		Ref:               scan.Ref,
		Profile:           scan.Profile,
		RescanMode:        scan.RescanMode,
		DiffBaseScanID:    scan.DiffBaseScanID,
		ScanGroup:         scan.ScanGroup,
		FocusArea:         scan.FocusArea,
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

// resumeOpts decides whether a retry of scan should resume its harness
// session. Failed scans and soft-success scans that hit max turns are
// resumable when they captured a session; ordinary done/cancelled scans, or
// scans that never reached the model, retry fresh. ResumedFromScanID is pinned
// to the lineage root so a chain of retries all reuse one workspace and
// session rather than forking a new one each time.
//
// A scan whose recorded Backend differs from the running server's -backend
// also retries fresh: the session id belongs to a different agent CLI
// (e.g. a codex thread id passed to claude --resume would fail), so drop it
// rather than wedge the retry lineage. An empty scan.Backend (rows predating
// the column, or the local runner which sets none) is treated as claude,
// since claude was the only backend before the column existed and the local
// runner is claude-only.
func (s *Server) resumeOpts(scan db.Scan) (sessionID string, resumeOf *uint) {
	resumableStatus := scan.Status == db.ScanFailed || (scan.Status == db.ScanDone && scan.MaxTurnsHit)
	if !resumableStatus || scan.SessionID == "" {
		return "", nil
	}
	scanBackend := scan.Backend
	if scanBackend == "" {
		// Rows predating the column, and LocalClaude runs, are claude sessions.
		scanBackend = "claude"
	}
	if s.Backend != "" && scanBackend != s.Backend {
		s.Log.Info("retry: backend changed since scan ran; starting fresh instead of resuming",
			"scan", scan.ID, "scan_backend", scanBackend, "server_backend", s.Backend)
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
	// queued/running/done, or superseded by a newer failed/paused attempt,
	// so repeated failures retry only the newest row per tuple. Cancelled is
	// deliberately absent: a user-cancelled newer run shouldn't block
	// retrying an older genuine failure.
	var scans []db.Scan
	err := q.Select("id, repository_id, skill_id, model, effort, finding_id, sub_path, ref, profile, rescan_mode, diff_base_scan_id, scan_group, backend, status, session_id, resumed_from_scan_id, import_payload").
		Where(`NOT EXISTS (
			SELECT 1 FROM scans n
			WHERE n.id > scans.id
			  AND n.repository_id = scans.repository_id
			  AND COALESCE(n.skill_id, 0) = COALESCE(scans.skill_id, 0)
			  AND COALESCE(n.sub_path, '') = COALESCE(scans.sub_path, '')
			  AND COALESCE(n.ref, '') = COALESCE(scans.ref, '')
			  AND COALESCE(n.finding_id, 0) = COALESCE(scans.finding_id, 0)
			  AND n.status IN ?
		)`, []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanDone, db.ScanFailed, db.ScanPaused}).
		Find(&scans).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var retried, errored int
	for _, sc := range scans {
		sessionID, resumeOf := s.resumeOpts(sc)
		if _, err := s.enqueueSkillWith(r.Context(), sc.RepositoryID, *sc.SkillID, ScanOpts{
			Model:             sc.Model,
			Effort:            sc.Effort,
			FindingID:         sc.FindingID,
			SubPath:           sc.SubPath,
			Ref:               sc.Ref,
			Profile:           sc.Profile,
			RescanMode:        sc.RescanMode,
			DiffBaseScanID:    sc.DiffBaseScanID,
			ScanGroup:         sc.ScanGroup,
			FocusArea:         sc.FocusArea,
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
	now := time.Now()
	res := s.DB.Model(&db.Scan{}).Where("status = ?", db.ScanQueued).Updates(scanStatusUpdates(
		db.ScanPaused,
		"paused by user",
		&now,
		nil,
	))
	if res.Error != nil {
		http.Error(w, res.Error.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: successKey, Title: fmt.Sprintf("%d queued scans paused", res.RowsAffected)})
	s.redirect(w, r, "/scans?status=paused")
}

func scanStatusUpdates(status db.ScanStatus, msg string, finishedAt *time.Time, pausedUntil *time.Time) map[string]any {
	return map[string]any{
		statusKey:         status,
		"status_priority": db.StatusPriorityFor(status),
		errorKey:          msg,
		"finished_at":     finishedAt,
		"paused_until":    pausedUntil,
	}
}

func (s *Server) bulkResumePaused(base *gorm.DB) ([]db.Scan, error) {
	var scans []db.Scan
	res := base.Model(&scans).Clauses(clause.Returning{
		Columns: []clause.Column{
			{Name: "id"},
			{Name: "kind"},
			{Name: "finding_id"},
			{Name: "error"},
			{Name: "paused_until"},
		},
	}).Where("status = ?", db.ScanPaused).Updates(scanStatusUpdates(
		db.ScanQueued,
		"",
		nil,
		nil,
	))
	if res.Error != nil {
		return nil, res.Error
	}
	return scans, nil
}

func (s *Server) restorePausedAfterResumeEnqueueFailure(scan db.Scan, err error) error {
	now := time.Now()
	return s.DB.Model(&db.Scan{}).Where("id = ? AND status = ?", scan.ID, db.ScanQueued).Updates(scanStatusUpdates(
		db.ScanPaused,
		"resume failed: "+err.Error(),
		&now,
		scan.PausedUntil,
	)).Error
}

func (s *Server) enqueueResumedScan(ctx context.Context, scan db.Scan) error {
	priority := worker.PrioScan
	if scan.FindingID != nil {
		priority = worker.PrioFinding
	}
	if err := s.Queue.Enqueue(ctx, scan.Kind, scan.ID, priority); err != nil {
		return errors.Join(err, s.restorePausedAfterResumeEnqueueFailure(scan, err))
	}
	return nil
}

func (s *Server) scansResumePaused(w http.ResponseWriter, r *http.Request) {
	repoID, _ := strconv.Atoi(r.URL.Query().Get("repository"))
	q := s.DB
	if repoID > 0 {
		q = q.Where("repository_id = ?", repoID)
	}
	scans, err := s.bulkResumePaused(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var resumed, errored int
	for _, sc := range scans {
		if err := s.enqueueResumedScan(r.Context(), sc); err != nil {
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
		"paused_until":    nil,
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
	now := time.Now()
	queued := s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND status = ?", repoID, db.ScanQueued).
		Updates(scanStatusUpdates(db.ScanCancelled, "cancelled by user", &now, nil))
	if queued.Error != nil {
		http.Error(w, queued.Error.Error(), http.StatusInternalServerError)
		return
	}
	var scans []db.Scan
	if err := s.DB.Where("repository_id = ? AND status IN ?",
		repoID, []db.ScanStatus{db.ScanRunning}).Find(&scans).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cancelled := int(queued.RowsAffected)
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
