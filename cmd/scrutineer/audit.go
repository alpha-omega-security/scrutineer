package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/git-pkgs/sarif"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// auditIncompleteExitCode is the exit status of an audit that wrote its
// outputs but did not finish every scan, so callers can tell it apart from a
// setup failure (1).
const auditIncompleteExitCode = 3

const (
	auditExportTimeout = 2 * time.Minute
	auditFilePerm      = 0o644
	auditDirPerm       = 0o755
	auditGitTimeout    = 10 * time.Second

	auditComplete    = "complete"
	auditIncomplete  = "incomplete"
	auditInterrupted = "interrupted"

	auditReportDir     = "scrutineer-audit"
	auditCandidatesDir = "bug-candidates"
	auditSarifName     = "scrutineer.sarif"
)

// Package vars so tests can shrink the waits.
var (
	// auditPollInterval is how often the DB is checked for outstanding scans.
	auditPollInterval = 2 * time.Second
	// auditSettlePolls is how many consecutive empty polls count as idle. Hooks
	// enqueue follow-up scans right after a terminal save, so one empty poll
	// can fall between a scan finishing and its follow-up appearing.
	auditSettlePolls = 3
	// auditDrainTimeout bounds the wait for running scans to finalize once the
	// queue is told to stop.
	auditDrainTimeout = 30 * time.Second
	// auditAppHook is called with the wired app before anything runs. Tests
	// use it to reach the database; it is nil in production.
	auditAppHook func(*app)
)

// auditIncompleteError reports an audit that finished writing outputs but did
// not complete every scan. main maps it to exit status 3.
type auditIncompleteError struct {
	Status string
	Reason string
}

func (e *auditIncompleteError) Error() string {
	return fmt.Sprintf("audit %s: %s", e.Status, e.Reason)
}

func (e *auditIncompleteError) ExitCode() int { return auditIncompleteExitCode }

// auditOptions are the audit-only flags.
type auditOptions struct {
	source  string
	out     string
	timeout time.Duration
	model   string
}

type auditScan struct {
	ID     uint   `json:"id"`
	Skill  string `json:"skill"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type auditManifest struct {
	Tool          string      `json:"tool"`
	Version       string      `json:"version"`
	Status        string      `json:"status"`
	Reason        string      `json:"reason,omitempty"`
	Source        string      `json:"source"`
	Revision      string      `json:"revision"`
	RepositoryID  uint        `json:"repository_id"`
	StartedAt     string      `json:"started_at"`
	FinishedAt    string      `json:"finished_at"`
	Scans         []auditScan `json:"scans"`
	Findings      int         `json:"findings"`
	BugCandidates int         `json:"bug_candidates"`
}

// runAudit implements `scrutineer audit`: it scans one local source tree with
// the default triage pipeline in a throwaway instance, then writes SARIF and a
// manifest under -out. It never touches an operator's database.
func runAudit(args []string, out io.Writer) error {
	return runAuditWith(args, out, setupRunner)
}

func runAuditWith(args []string, out io.Writer, setup runnerSetup) error {
	f, opts, err := parseAuditFlags(args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cleanup, err := prepareAuditData(f, log)
	if err != nil {
		return err
	}
	defer cleanup()

	// Bind first so setupRunner's hostAPIBase points skills at the real port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = ln.Close() }()
	f.addr = ln.Addr().String()
	f.set["addr"] = true

	f, cfg, err := loadConfigFor(f, log)
	if err != nil {
		return err
	}
	isolateAuditConfig(f, opts, log)

	a, err := newApp(f, cfg, log, setup)
	if err != nil {
		return err
	}
	defer closeAuditDB(a.db)
	a.server.DisableEcosystems()
	if auditAppHook != nil {
		auditAppHook(a)
	}

	return runAuditApp(a, ln, opts, out)
}

// parseAuditFlags parses the audit FlagSet: every server flag plus the
// audit-only ones. Unlike parseFlags it returns errors instead of exiting.
func parseAuditFlags(args []string) (*flags, *auditOptions, error) {
	f := &flags{}
	opts := &auditOptions{}
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	registerFlags(fs, f)
	fs.StringVar(&opts.source, "source", "", "directory to audit (required)")
	fs.StringVar(&opts.out, "out", "", "directory to write results to (required)")
	fs.DurationVar(&opts.timeout, "audit-timeout", 0, "wall-clock limit for the whole audit (0 = no limit)")
	fs.StringVar(&opts.model, "model", "", "default model for the audit's scans")
	fs.StringVar(&f.trustedModelHost, "trusted-model-host", "",
		"hostname of a model proxy on a private container network that may be reached over plain http, such as OSS-CRS's LiteLLM")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if fs.NArg() > 0 {
		return nil, nil, fmt.Errorf("unexpected argument %q (booleans take the -flag=false form)", fs.Arg(0))
	}
	f.set = make(map[string]bool)
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })

	if err := resolveAuditPaths(opts); err != nil {
		return nil, nil, err
	}
	return f, opts, nil
}

// resolveAuditPaths validates -source and -out and creates -out.
func resolveAuditPaths(opts *auditOptions) error {
	if opts.source == "" {
		return errors.New("-source is required")
	}
	if opts.out == "" {
		return errors.New("-out is required")
	}
	src, err := filepath.Abs(opts.source)
	if err != nil {
		return fmt.Errorf("resolve -source: %w", err)
	}
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("-source: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("-source %s is not a directory", src)
	}
	outDir, err := filepath.Abs(opts.out)
	if err != nil {
		return fmt.Errorf("resolve -out: %w", err)
	}
	if err := os.MkdirAll(outDir, auditDirPerm); err != nil {
		return fmt.Errorf("create -out: %w", err)
	}
	opts.source, opts.out = src, outDir
	return nil
}

// prepareAuditData picks the data directory and pins it so the config file
// cannot redirect the audit into an operator's database. Without an explicit
// -data it uses a fresh temp dir that the returned cleanup removes.
func prepareAuditData(f *flags, log *slog.Logger) (func(), error) {
	cleanup := func() {}
	if f.set["data"] {
		if _, err := os.Stat(filepath.Join(f.dataDir, dbFileName)); err == nil {
			return nil, fmt.Errorf("-data %s already contains %s; use an empty directory so stale results never mix in", f.dataDir, dbFileName)
		}
	} else {
		dir, err := os.MkdirTemp("", "scrutineer-audit-")
		if err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
		f.dataDir = dir
		cleanup = func() {
			if err := os.RemoveAll(dir); err != nil {
				log.Warn("remove audit data dir", "dir", dir, "err", err)
			}
		}
	}
	f.set["data"] = true
	return cleanup, nil
}

// isolateAuditConfig applies the settings that must win over the config file:
// sqlite in the audit's own data dir, no ecosystems lookups plus the -model
// override.
func isolateAuditConfig(f *flags, opts *auditOptions, log *slog.Logger) {
	if f.dbDriver != "" || f.dbDSN != "" {
		log.Info("audit ignores the configured database and uses sqlite in its data dir", "driver", f.dbDriver)
	}
	f.dbDriver = ""
	f.dbDSN = ""
	f.ecosystemsEnrichment = false
	if opts.model != "" {
		f.defaultModel = opts.model
	}
}

// closeAuditDB closes the sqlite file so a temp data dir can be removed on
// platforms that cannot delete an open file.
func closeAuditDB(gdb *gorm.DB) {
	if sqldb, err := gdb.DB(); err == nil {
		_ = sqldb.Close()
	}
}

// auditOutcome is how the wait ended.
type auditOutcome struct {
	interrupted bool
	reason      string
}

func runAuditApp(a *app, ln net.Listener, opts *auditOptions, out io.Writer) error {
	started := time.Now().UTC()
	httpSrv := &http.Server{Handler: a.server.Handler(), ReadHeaderTimeout: shutdownTimeout}
	go func() { _ = httpSrv.Serve(ln) }()
	defer shutdownAuditServer(httpSrv)

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	auditCtx, cancelAudit := signalCtx, context.CancelFunc(func() {})
	if opts.timeout > 0 {
		auditCtx, cancelAudit = context.WithTimeout(signalCtx, opts.timeout)
	}
	defer cancelAudit()

	qctx, stopQueue := context.WithCancel(context.Background())
	queueDone := make(chan struct{})
	go func() {
		a.queue.Start(qctx)
		close(queueDone)
	}()
	// Safety net for early returns; the normal path stops the queue below.
	defer func() { stopQueue(); drainQueue(queueDone) }()

	repo, isNew, err := a.server.AddRepository(auditCtx, opts.source)
	if err != nil {
		return fmt.Errorf("add repository: %w", err)
	}
	if !isNew {
		return errors.New("repository already exists in the audit database")
	}

	outcome := waitForAudit(auditCtx, a.db, repo.ID)
	stopQueue()
	drainQueue(queueDone)

	return finishAudit(a, outcome, repo, started, opts, out, ln.Addr().String())
}

func shutdownAuditServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// drainQueue waits for the queue to finish its in-flight jobs, giving up after
// auditDrainTimeout.
func drainQueue(done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(auditDrainTimeout):
	}
}

// waitForAudit polls until the repository has no queued or running scans for
// auditSettlePolls polls in a row or ctx ends.
func waitForAudit(ctx context.Context, gdb *gorm.DB, repoID uint) auditOutcome {
	ticker := time.NewTicker(auditPollInterval)
	defer ticker.Stop()
	settled := 0
	for {
		select {
		case <-ctx.Done():
			return interruptedOutcome(ctx)
		case <-ticker.C:
		}
		var active int64
		err := gdb.Model(&db.Scan{}).
			Where("repository_id = ? AND status IN ?", repoID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
			Count(&active).Error
		if err != nil {
			return auditOutcome{interrupted: true, reason: fmt.Sprintf("poll scans: %v", err)}
		}
		if active > 0 {
			settled = 0
			continue
		}
		settled++
		if settled >= auditSettlePolls {
			return auditOutcome{}
		}
	}
}

func interruptedOutcome(ctx context.Context) auditOutcome {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return auditOutcome{interrupted: true, reason: "audit timeout reached"}
	}
	return auditOutcome{interrupted: true, reason: "interrupted by signal"}
}

// finishAudit exports the results, writes the outputs and turns the outcome
// into the command's return value.
func finishAudit(a *app, outcome auditOutcome, repo db.Repository, started time.Time, opts *auditOptions, out io.Writer, addr string) error {
	var scans []db.Scan
	if err := a.db.Where("repository_id = ?", repo.ID).Order("id").Find(&scans).Error; err != nil {
		return fmt.Errorf("read scans: %w", err)
	}
	status, reason := auditStatus(outcome, scans)

	exp, err := fetchAuditExports(addr, a.server.OperatorToken, repo.ID)
	if err != nil {
		return err
	}
	candidates, kept, total, err := bugCandidates(exp.sarif)
	if err != nil {
		return fmt.Errorf("filter bug candidates: %w", err)
	}
	manifest := auditManifest{
		Tool:          "scrutineer",
		Version:       version,
		Status:        status,
		Reason:        reason,
		Source:        opts.source,
		Revision:      gitRevision(opts.source),
		RepositoryID:  repo.ID,
		StartedAt:     started.Format(time.RFC3339),
		FinishedAt:    time.Now().UTC().Format(time.RFC3339),
		Scans:         manifestScans(scans),
		Findings:      total,
		BugCandidates: kept,
	}
	if err := writeAuditOutputs(opts.out, manifest, exp, candidates); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "audit %s: %d findings, %d bug candidates, results in %s\n", status, total, kept, opts.out)
	if status == auditComplete {
		return nil
	}
	return &auditIncompleteError{Status: status, Reason: reason}
}

func manifestScans(scans []db.Scan) []auditScan {
	out := make([]auditScan, 0, len(scans))
	for _, s := range scans {
		out = append(out, auditScan{ID: s.ID, Skill: s.SkillName, Status: string(s.Status), Error: s.Error})
	}
	return out
}

// auditStatus classifies the run. Done and skipped scans are fine; anything
// else (or no scans at all) means the audit did not cover everything.
func auditStatus(outcome auditOutcome, scans []db.Scan) (status, reason string) {
	if outcome.interrupted {
		return auditInterrupted, outcome.reason
	}
	if len(scans) == 0 {
		return auditIncomplete, "no scans ran"
	}
	counts := map[db.ScanStatus]int{}
	for _, s := range scans {
		if s.Status != db.ScanDone && s.Status != db.ScanSkipped {
			counts[s.Status]++
		}
	}
	var parts []string
	for _, st := range []db.ScanStatus{db.ScanFailed, db.ScanCancelled, db.ScanPaused, db.ScanQueued, db.ScanRunning} {
		if n := counts[st]; n > 0 {
			noun := "scans"
			if n == 1 {
				noun = "scan"
			}
			parts = append(parts, fmt.Sprintf("%d %s %s", n, noun, st))
		}
	}
	if len(parts) == 0 {
		return auditComplete, ""
	}
	return auditIncomplete, strings.Join(parts, ", ")
}

func gitRevision(source string) string {
	ctx, cancel := context.WithTimeout(context.Background(), auditGitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-c", "safe.directory="+source, "-C", source, "rev-parse", "HEAD")
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// auditExports are the raw operator API payloads.
type auditExports struct {
	sarif    []byte
	findings []byte
	scans    []byte
}

// fetchAuditExports reads the results through the operator API the way an
// external client would. It uses its own context because the audit context
// may already be cancelled.
func fetchAuditExports(addr, token string, repoID uint) (auditExports, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditExportTimeout)
	defer cancel()
	base := "http://" + addr + "/api/v1"
	var exp auditExports
	for _, item := range []struct {
		dst  *[]byte
		path string
	}{
		{&exp.sarif, fmt.Sprintf("/repositories/%d/findings?format=sarif", repoID)},
		{&exp.findings, fmt.Sprintf("/repositories/%d/findings", repoID)},
		{&exp.scans, fmt.Sprintf("/scans?repository_id=%d", repoID)},
	} {
		body, err := auditGet(ctx, base+item.path, token)
		if err != nil {
			return auditExports{}, err
		}
		*item.dst = body
	}
	return exp, nil
}

func auditGet(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("export %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("export %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("export %s: status %d", url, resp.StatusCode)
	}
	return body, nil
}

// bugCandidates drops every suppressed result (rejected or duplicate
// findings) from the SARIF export. It returns the filtered document, how many
// results were kept and how many the export held.
func bugCandidates(raw []byte) (data []byte, kept, total int, err error) {
	log, err := sarif.Parse(raw)
	if err != nil {
		return nil, 0, 0, err
	}
	for i := range log.Runs {
		run := &log.Runs[i]
		total += len(run.Results)
		filtered := run.Results[:0:0]
		for _, r := range run.Results {
			if len(r.Suppressions) == 0 {
				filtered = append(filtered, r)
			}
		}
		run.Results = filtered
		kept += len(filtered)
	}
	if kept == 0 {
		return nil, 0, total, nil
	}
	if err := sarif.Validate(log); err != nil {
		return nil, 0, 0, err
	}
	data, err = sarif.Marshal(log, false)
	return data, kept, total, err
}

// writeAuditOutputs lays out the report directory and the bug-candidate file.
// The candidate file is removed first so an earlier run never leaves a stale
// one behind.
func writeAuditOutputs(outDir string, m auditManifest, exp auditExports, candidates []byte) error {
	report := filepath.Join(outDir, auditReportDir)
	candDir := filepath.Join(outDir, auditCandidatesDir)
	candFile := filepath.Join(candDir, auditSarifName)
	if err := os.Remove(candFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale bug candidates: %w", err)
	}
	if err := os.MkdirAll(report, auditDirPerm); err != nil {
		return err
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
	}{
		{filepath.Join(report, "audit.json"), append(manifest, '\n')},
		{filepath.Join(report, auditSarifName), exp.sarif},
		{filepath.Join(report, "findings.jsonl"), exp.findings},
		{filepath.Join(report, "scans.jsonl"), exp.scans},
	}
	if len(candidates) > 0 {
		if err := os.MkdirAll(candDir, auditDirPerm); err != nil {
			return err
		}
		files = append(files, struct {
			path string
			data []byte
		}{candFile, candidates})
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, f.data, auditFilePerm); err != nil {
			return fmt.Errorf("write %s: %w", f.path, err)
		}
	}
	return nil
}
