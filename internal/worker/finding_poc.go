package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gorm.io/gorm/clause"

	"scrutineer/internal/db"
	"scrutineer/internal/poc"
)

var pocFindingID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

const pocExecutablePerm = 0o700

// PoCCaptureError reports a failed capture after the finding was saved.
type PoCCaptureError struct{ error }

func (e *PoCCaptureError) Unwrap() error { return e.error }

func (w *Worker) captureFindingPoC(scan *db.Scan, finding *db.Finding) (err error) {
	defer func() {
		if err != nil && scan.APIToken != "" && strings.Contains(err.Error(), scan.APIToken) {
			err = errors.New(strings.ReplaceAll(err.Error(), scan.APIToken, "[redacted]"))
		}
	}()
	if w.DataDir == "" || !pocFindingID.MatchString(finding.FindingID) {
		return nil
	}
	root, err := openFindingPoC(w.scanWorkRoot(scan), finding.FindingID)
	if err != nil {
		return fmt.Errorf("capture PoC for finding %d: %w", finding.ID, err)
	}
	if root == nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	existing, err := db.LoadFindingPoC(w.DB, finding.ID)
	if err != nil || existing != nil {
		return err
	}
	files, err := poc.Capture(root)
	if err != nil {
		return fmt.Errorf("capture PoC for finding %d: %w", finding.ID, err)
	}
	if scan.APIToken != "" {
		for _, file := range files {
			if strings.Contains(file.Path, scan.APIToken) || bytes.Contains(file.Data, []byte(scan.APIToken)) {
				return fmt.Errorf("capture PoC for finding %d: files contain the scan API token", finding.ID)
			}
		}
	}
	data, err := json.Marshal(files)
	if err != nil {
		return err
	}
	row := db.FindingPoC{FindingID: finding.ID, ScanID: scan.ID, Commit: scan.Commit, Files: data}
	return w.DB.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "finding_id"}}, DoNothing: true}).Create(&row).Error
}

func capturePoCFiles(workRoot, findingID string) ([]poc.File, error) {
	root, err := openFindingPoC(workRoot, findingID)
	if err != nil || root == nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return poc.Capture(root)
}

func openFindingPoC(workRoot, findingID string) (*os.Root, error) {
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
	return findingRoot, nil
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
	if err := writePoCFiles(workRoot, "poc/", files); err != nil {
		return err
	}
	data, err := json.MarshalIndent(row.Manifest(files), "", "  ")
	if err != nil {
		return err
	}
	return replaceWorkspaceFile(workRoot, "poc-manifest.json", data)
}

func writePoCFiles(workRoot, prefix string, files []poc.File) error {
	root, err := os.OpenRoot(workRoot)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, file := range files {
		path := prefix + file.Path
		if err := replaceWorkspaceFile(workRoot, path, file.Data); err != nil {
			return err
		}
		if file.Executable {
			if err := root.Chmod(path, pocExecutablePerm); err != nil {
				return err
			}
		}
	}
	return nil
}
