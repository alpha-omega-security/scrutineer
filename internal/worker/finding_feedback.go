package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
)

func (w *Worker) findingFeedback(ctx context.Context, workRoot string, scan *db.Scan, skill *db.Skill) ([]db.FindingFeedback, error) {
	if scan.ExplorationMode != "" {
		return nil, nil
	}
	var paths []string
	switch {
	case skill.Name == "revalidate" && scan.FindingID != nil:
		var finding db.Finding
		if err := w.DB.WithContext(ctx).Where("repository_id = ?", scan.RepositoryID).First(&finding, *scan.FindingID).Error; err != nil {
			return nil, fmt.Errorf("load finding for analyst feedback: %w", err)
		}
		if path := findingnorm.FindingPath(finding.SubPath, finding.Location); path != "" {
			paths = append(paths, path)
		}
	case skill.Name == "security-deep-dive" && scan.RescanMode == db.ScanRescanModeDiff:
		data, err := os.ReadFile(filepath.Join(workRoot, changedFilesFile))
		if err != nil {
			return nil, fmt.Errorf("load changed paths for analyst feedback: %w", err)
		}
		var changed []changedFile
		if err := json.Unmarshal(data, &changed); err != nil {
			return nil, fmt.Errorf("decode changed paths for analyst feedback: %w", err)
		}
		for _, file := range changed {
			paths = append(paths, file.Path)
			if file.Old != "" {
				paths = append(paths, file.Old)
			}
		}
	default:
		return nil, nil
	}
	rows, err := db.FindingFeedbackForPaths(w.DB.WithContext(ctx), scan.RepositoryID, paths)
	if err != nil {
		return nil, fmt.Errorf("load analyst feedback: %w", err)
	}
	return rows, nil
}
