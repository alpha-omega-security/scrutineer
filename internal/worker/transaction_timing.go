package worker

import (
	"log/slog"

	"scrutineer/internal/db"
)

func (w *Worker) scanTransactionLog(scan *db.Scan, operation string) *slog.Logger {
	log := w.Log
	if log == nil {
		log = slog.Default()
	}
	return log.With("operation", operation, "scan", scan.ID, "repo", scan.RepositoryID, "skill", scan.SkillName)
}
