// Package worker holds the job handlers that the queue dispatches to.
// Each job receives a Scan ID, looks up the row, does its work, and writes
// status/log/report back to the same row as it goes so the web UI can poll.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

const (
	JobClaude   = "claude"
	JobSkill    = "skill"
	JobMetadata = "metadata"
	JobPackages = "packages"
	JobBrief    = "brief"
	JobGitPkgs  = "git-pkgs"
	JobSemgrep  = "semgrep"
	JobZizmor   = "zizmor"
	JobSBOM       = "sbom"
	JobDependents  = "dependents"
	JobAdvisories  = "advisories"
	JobMaintainers = "maintainers"
	JobCommits     = "commits"

	PrioScan     = 0
	PrioTool     = 5
	PrioFastTool = 8
	PrioMetadata = 10
)

type Worker struct {
	DB      *gorm.DB
	Log     *slog.Logger
	DataDir string // workspace root for clones
	Spec    string // audit spec text passed to claude
	Runner  ClaudeRunner
	OnEvent func(scanID, repoID uint, name, data string) // optional SSE bridge
}

func (w *Worker) publish(scanID, repoID uint, name, data string) {
	if w.OnEvent != nil {
		w.OnEvent(scanID, repoID, name, data)
	}
}

func (w *Worker) Register(q *queue.Queue) {
	q.Register(JobClaude, w.wrap(w.doClaude))
	q.Register(JobSkill, w.wrap(w.doSkill))
	q.Register(JobMetadata, w.wrap(w.doMetadata))
	q.Register(JobPackages, w.wrap(w.doPackages))
	q.Register(JobBrief, w.wrap(w.doBrief))
	q.Register(JobGitPkgs, w.wrap(w.doGitPkgs))
	q.Register(JobSemgrep, w.wrap(w.doSemgrep))
	q.Register(JobZizmor, w.wrap(w.doZizmor))
	q.Register(JobSBOM, w.wrap(w.doSBOM))
	q.Register(JobDependents, w.wrap(w.doDependents))
	q.Register(JobAdvisories, w.wrap(w.doAdvisories))
	q.Register(JobMaintainers, w.wrap(w.doMaintainerAnalysis))
	q.Register(JobCommits, w.wrap(w.doCommits))
}

// handler does the actual work for one job kind. It receives the loaded scan
// (with Repository preloaded) and an emit callback that appends to Scan.Log.
// The returned report string lands in Scan.Report.
type handler func(ctx context.Context, scan *db.Scan, emit func(Event)) (report string, err error)

// wrap turns a handler into a goqite jobs.Func: decode payload, load the
// scan row, run the handler, persist status/log/report. Errors from the
// handler mark the scan failed but return nil to goqite so it does not
// auto-retry expensive work; the user re-queues from the UI.
func (w *Worker) wrap(h handler) func(context.Context, []byte) error {
	return func(ctx context.Context, body []byte) error {
		var p queue.Payload
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("decode payload: %w", err)
		}
		var scan db.Scan
		if err := w.DB.Preload("Repository").First(&scan, p.ScanID).Error; err != nil {
			return fmt.Errorf("load scan %d: %w", p.ScanID, err)
		}
		if scan.Status.Terminal() {
			w.Log.Info("dropping stale job", "scan", scan.ID, "status", scan.Status)
			return nil
		}

		now := time.Now()
		scan.Status = db.ScanRunning
		scan.StartedAt = &now
		scan.Log = ""
		scan.Error = ""
		if err := w.DB.Save(&scan).Error; err != nil {
			return err
		}

		emit := func(e Event) {
			line := FormatEvent(e)
			scan.Log += line + "\n"
			w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("log", scan.Log)
			if e.Kind == KindResult {
				scan.CostUSD = e.CostUSD
				scan.Turns = e.Turns
			}
			w.publish(scan.ID, scan.RepositoryID, "scan-log", line+"\n")
		}

		report, err := h(ctx, &scan, emit)

		fin := time.Now()
		scan.FinishedAt = &fin
		if err != nil {
			scan.Status = db.ScanFailed
			scan.Error = err.Error()
			emit(Event{Kind: KindError, Text: err.Error()})
		} else {
			scan.Status = db.ScanDone
			scan.Report = report
		}
		if saveErr := w.DB.Save(&scan).Error; saveErr != nil {
			return saveErr
		}
		w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
		w.Log.Info("job finished", "scan", scan.ID, "kind", scan.Kind, "status", scan.Status)
		return nil
	}
}

func (w *Worker) doClaude(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	scan.Prompt = w.Runner.Prompt(scan.Repository, w.Spec)
	w.DB.Model(scan).Update("prompt", scan.Prompt)

	job := Job{Repo: scan.Repository, DataDir: w.DataDir, Model: scan.Model, Prompt: scan.Prompt}
	res, err := w.Runner.Run(ctx, job, emit)
	scan.Commit = res.Commit
	if err != nil {
		return res.Report, err
	}

	rep, perr := parseReport([]byte(res.Report))
	if perr != nil {
		// Keep the raw output so the operator can see what came back, but
		// flag the scan failed: a non-conforming report is a bug to chase.
		return res.Report, perr
	}
	findings := rep.toFindings(scan.ID)
	scan.FindingsCount = len(findings)
	if len(findings) > 0 {
		if err := w.DB.Create(&findings).Error; err != nil {
			return res.Report, fmt.Errorf("save findings: %w", err)
		}
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("parsed %d finding(s)", len(findings))})
	return res.Report, nil
}

func (w *Worker) doMetadata(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	er, raw, err := fetchEcosystems(ctx, scan.Repository.URL, emit)
	if err != nil {
		return string(raw), err
	}
	w.applyMetadata(&scan.Repository, er, raw)
	var pretty map[string]any
	_ = json.Unmarshal(raw, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	return string(out), nil
}
