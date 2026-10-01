package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	"gorm.io/gorm/clause"

	"scrutineer/internal/db"
	"scrutineer/internal/poc"
)

var pocFindingID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

const pocExecutablePerm = 0o700

// PoCCaptureError reports a failed capture after the finding was saved.
type PoCCaptureError struct{ error }

func (e *PoCCaptureError) Unwrap() error { return e.error }

func (w *Worker) captureFindingPoC(scan *db.Scan, finding *db.Finding) error {
	if w.DataDir == "" || !pocFindingID.MatchString(finding.FindingID) {
		return nil
	}
	existing, err := db.LoadFindingPoC(w.DB, finding.ID)
	if err != nil || existing != nil {
		return err
	}
	files, err := capturePoCFiles(w.scanWorkRoot(scan), finding.FindingID)
	if err == nil && files == nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("capture PoC for finding %d: %w", finding.ID, err)
	}
	data, err := json.Marshal(files)
	if err != nil {
		return err
	}
	row := db.FindingPoC{FindingID: finding.ID, ScanID: scan.ID, Commit: scan.Commit, Files: data}
	return w.DB.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "finding_id"}}, DoNothing: true}).Create(&row).Error
}

func capturePoCFiles(workRoot, findingID string) ([]poc.File, error) {
	root, err := os.OpenRoot(workRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	pocRoot, err := poc.OpenDir(root, "poc")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = pocRoot.Close() }()
	findingRoot, err := poc.OpenDir(pocRoot, findingID)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = findingRoot.Close() }()
	return poc.Capture(findingRoot)
}

func (w *Worker) stageFindingPoC(workRoot string, scan *db.Scan, skill *db.Skill) error {
	if scan.FindingID == nil || skill.Name != verifySkillName {
		return nil
	}
	var finding db.Finding
	if err := w.DB.First(&finding, *scan.FindingID).Error; err != nil {
		return err
	}
	if finding.RepositoryID != scan.RepositoryID {
		return fmt.Errorf("PoC finding belongs to another repository")
	}
	row, err := db.LoadFindingPoC(w.DB, finding.ID)
	if err != nil || row == nil {
		return err
	}
	files, err := poc.Decode(row.Files)
	if err != nil {
		return fmt.Errorf("load captured PoC: %w", err)
	}
	root, err := os.OpenRoot(workRoot)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, file := range files {
		path := "poc/" + file.Path
		if err := replaceWorkspaceFile(workRoot, path, file.Data); err != nil {
			return err
		}
		if file.Executable {
			if err := root.Chmod(path, pocExecutablePerm); err != nil {
				return err
			}
		}
	}
	data, err := json.MarshalIndent(row.Manifest(files), "", "  ")
	if err != nil {
		return err
	}
	return replaceWorkspaceFile(workRoot, "poc-manifest.json", data)
}
