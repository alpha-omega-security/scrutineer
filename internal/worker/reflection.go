package worker

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/reflection"
)

// prepareReflection runs before claiming a worker slot or spending model turns.
// ImportPayload is a persisted, host-authored snapshot, staged as import/report.
func (w *Worker) prepareReflection(scan *db.Scan) (bool, error) {
	if scan.TriageScanID == nil || scan.SubPath != "" || scan.Ref != "" || scan.FindingID != nil {
		return false, fmt.Errorf("reflect requires a root default-branch triage invocation")
	}
	// A retry replays the recorded input, not the current state of the source
	// scans. Those may have been retried, paused, or removed by retention.
	if len(scan.ImportPayload) != 0 {
		var input reflection.Input
		if err := json.Unmarshal(scan.ImportPayload, &input); err != nil {
			return false, fmt.Errorf("read reflection snapshot: %w", err)
		}
		if input.TriageScanID != *scan.TriageScanID {
			return false, fmt.Errorf("reflection snapshot belongs to another triage")
		}
		if err := reflection.ValidateInput(input); err != nil {
			return false, err
		}
		return false, w.validateReflectionModel(scan.RepositoryID)
	}
	var triage db.Scan
	if err := w.DB.Select("id, repository_id, skill_name, status, sub_path, ref").First(&triage, *scan.TriageScanID).Error; err != nil {
		return false, fmt.Errorf("load reflection triage: %w", err)
	}
	if triage.RepositoryID != scan.RepositoryID || triage.SkillName != "triage" || triage.SubPath != "" || triage.Ref != "" {
		return false, fmt.Errorf("reflection triage scope does not match")
	}
	if !triage.Status.Terminal() || w.reflectionFinalizing(triage.ID) {
		return true, nil
	}
	sources, err := w.reflectionSources(scan)
	if err != nil {
		return false, err
	}
	if len(sources) > reflection.MaxScans {
		return false, fmt.Errorf("reflection cohort exceeds %d scans", reflection.MaxScans)
	}
	if len(sources) == 0 {
		return false, fmt.Errorf("reflection triage has no compatible child scans")
	}
	for _, source := range sources {
		if !source.Status.Terminal() || w.reflectionFinalizing(source.ID) {
			return true, nil
		}
	}
	// A finalizer may have enqueued descendants between the first query and
	// our running-map check. Re-read after every observed finalizer exited.
	latest, err := w.reflectionSources(scan)
	if err != nil {
		return false, err
	}
	if !sameReflectionSources(sources, latest) {
		return true, nil
	}
	if err := w.validateReflectionModel(scan.RepositoryID); err != nil {
		return false, err
	}
	input := reflection.Input{TriageScanID: triage.ID, Sources: make([]reflection.Source, 0, len(sources))}
	for _, source := range sources {
		excerpt, err := w.reflectionSource(source)
		if err != nil {
			return false, err
		}
		input.Sources = append(input.Sources, excerpt)
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return false, err
	}
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("import_payload", raw).Error; err != nil {
		return false, err
	}
	scan.ImportPayload = raw
	return false, nil
}

func (w *Worker) validateReflectionModel(repoID uint) error {
	var repo db.Repository
	if err := w.DB.Select("id, threat_model").First(&repo, repoID).Error; err != nil {
		return err
	}
	var model map[string]json.RawMessage
	if err := json.Unmarshal([]byte(repo.ThreatModel), &model); err != nil || model == nil {
		return fmt.Errorf("reflect requires an existing threat-model object; run threat-model first")
	}
	return nil
}

func (w *Worker) reflectionSources(scan *db.Scan) ([]db.Scan, error) {
	var sources []db.Scan
	err := w.DB.Select("id, skill_name, status, `commit`").
		Where("repository_id = ? AND triage_scan_id = ? AND skill_name <> ? AND sub_path = '' AND ref = ''", scan.RepositoryID, *scan.TriageScanID, "reflect").
		Order("id").Limit(reflection.MaxScans + 1).Find(&sources).Error
	return sources, err
}

func sameReflectionSources(before, after []db.Scan) bool {
	if len(before) != len(after) {
		return false
	}
	for i := range before {
		if before[i].ID != after[i].ID || before[i].Status != after[i].Status {
			return false
		}
	}
	return true
}

// A terminal row can still be running its finalization hooks, including the
// threat-model deep-dive fan-out. Do not snapshot that cohort until they return.
func (w *Worker) reflectionFinalizing(id uint) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.running[id]
	return ok
}

func (w *Worker) reflectionSource(scan db.Scan) (reflection.Source, error) {
	var windows struct {
		Prefix, Tail string
		Size         int
	}
	result := w.DB.Model(&db.Scan{}).Select("substr(log, 1, ?) AS prefix, substr(log, -?) AS tail, length(log) AS size", reflection.Window, reflection.Window).
		Where("id = ?", scan.ID).Scan(&windows)
	if result.Error != nil {
		return reflection.Source{}, fmt.Errorf("read reflection transcript %d: %w", scan.ID, result.Error)
	}
	missing := result.RowsAffected == 0 || windows.Size == 0
	return reflection.Source{ScanID: scan.ID, Stage: scan.SkillName, Commit: scan.Commit, Status: string(scan.Status), Missing: missing,
		Truncated: windows.Size > reflection.MaxExcerpt/2 || len(windows.Tail) > reflection.MaxExcerpt/2, Excerpt: reflection.Excerpt(windows.Prefix, windows.Tail)}, nil
}

func (w *Worker) parseReflectionOutput(scan *db.Scan, report string) error {
	var input reflection.Input
	if err := json.Unmarshal(scan.ImportPayload, &input); err != nil {
		return fmt.Errorf("read reflection snapshot: %w", err)
	}
	if scan.TriageScanID == nil || input.TriageScanID != *scan.TriageScanID || scan.SubPath != "" || scan.Ref != "" {
		return fmt.Errorf("invalid reflection provenance")
	}
	var output reflection.Report
	decoder := json.NewDecoder(strings.NewReader(report))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return fmt.Errorf("parse reflection: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("reflection report must contain exactly one JSON object")
	}
	return db.UpdateThreatModel(w.DB, scan.RepositoryID, func(model string) (string, error) {
		return reflection.Merge(model, input, output, scan.ID)
	})
}
