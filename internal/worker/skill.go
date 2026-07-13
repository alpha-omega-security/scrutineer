package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
	"scrutineer/internal/skills"
)

const (
	filePerm                  = 0o644
	defaultSkillOutputFile    = "report.json"
	skillSchemaFile           = "schema.json"
	schemaRepairMaxTurns      = 4
	schemaRepairReportMaxSize = 4000
	refusalAuditSkillName     = "security-deep-dive"
	refusalAuditOutputFile    = "refusal_audit.json"
	refusalAuditMaxTurns      = 3
)

// skillContext is the JSON document scrutineer writes to ./context.json in
// every skill workspace before invoking claude. Skills that need to know who
// they are scanning (or need to call back into scrutineer) read this file.
type skillContext struct {
	Repository skillContextRepo  `json:"repository"`
	Commit     string            `json:"commit,omitempty"`
	Packages   []skillContextPkg `json:"packages,omitempty"`
	// Scrutineer lets a skill call back into the host app: list prior scans,
	// enqueue further skills, read reports. The schema is openapi.yaml at
	// the repo root.
	Scrutineer skillContextScrutineer `json:"scrutineer"`
}

type skillContextScrutineer struct {
	APIBase     string `json:"api_base"`               // e.g. http://127.0.0.1:8080/api
	ScanID      uint   `json:"scan_id"`                // the scan that owns this run
	Token       string `json:"token"`                  // bearer for api_base
	RepoID      uint   `json:"repository_id"`          // convenience for URL building
	SkillID     uint   `json:"skill_id,omitempty"`     // the running skill
	FindingID   uint   `json:"finding_id,omitempty"`   // set for finding-scoped scans
	DependentID uint   `json:"dependent_id,omitempty"` // set on exposure scans
	// ScanRef is the git ref (branch/tag) the clone was checked out to.
	// Empty means the repository's default branch.
	ScanRef string `json:"scan_ref,omitempty"`
	// ScanSubPath scopes code analysis to a sub-folder of ./src (monorepo
	// support). Empty means the repo root. Skills that walk files honour
	// this; skills that query external APIs ignore it.
	ScanSubPath string `json:"scan_subpath,omitempty"`
	// ScanGroup identifies the parallel batch this scan belongs to. An audit
	// skill passes it to /repositories/{id}/findings?scan_group=... to read
	// what its siblings have already filed before reporting its own.
	// Empty when the scan was not launched as part of a batch.
	ScanGroup string `json:"scan_group,omitempty"`
	// ForkOrg is the GitHub organisation the fork skill stages scanned
	// repositories into. Absent when fork_org is unconfigured.
	ForkOrg string `json:"fork_org,omitempty"`
	// MetadataDir is the path inside a staging repo where scrutineer
	// metadata lives (`.scrutineer/` by default). Always written so
	// skills can build paths without re-applying the default.
	MetadataDir string `json:"metadata_dir"`
	// Rescan is present for diff-based rescans. It names the baseline and
	// staged files a diff-aware skill should read.
	Rescan *skillContextRescan `json:"rescan,omitempty"`
	// ScanConfig is the operator-authored repository guidance. It is omitted
	// entirely for repositories without a saved configuration.
	ScanConfig *repoconfig.Config `json:"scan_config,omitempty"`
}

type skillContextRescan struct {
	Mode                string `json:"mode"`
	BaseScanID          uint   `json:"base_scan_id,omitempty"`
	BaseCommit          string `json:"base_commit,omitempty"`
	HeadCommit          string `json:"head_commit,omitempty"`
	ThreatModelScanID   uint   `json:"threat_model_scan_id,omitempty"`
	DiffFile            string `json:"diff_file,omitempty"`
	ChangedFilesFile    string `json:"changed_files_file,omitempty"`
	OldThreatModelFile  string `json:"old_threat_model_file,omitempty"`
	CoverageMetadataKey string `json:"coverage_metadata_key,omitempty"`
}

// DefaultMetadataDir is the value used when scrutineer.yaml does not
// configure `metadata_dir`. Keep it scrutineer-flavoured; an operator
// who wants a consortium-flavoured directory (e.g. `.ossprey/`) sets
// metadata_dir explicitly.
const DefaultMetadataDir = ".scrutineer/"

type skillContextRepo struct {
	URL           string `json:"url"`
	HTMLURL       string `json:"html_url,omitempty"`
	Name          string `json:"name,omitempty"`
	FullName      string `json:"full_name,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

type skillContextPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// doSkill stages the referenced skill under the scan's workspace and invokes
// claude-code, which discovers project-level skills at ./.claude/skills and
// follows the body of the selected SKILL.md. If the skill declares an output
// file in its frontmatter metadata, the contents land in Scan.Report and,
// when output_kind is "findings", parse into Finding rows.
func (w *Worker) doSkill(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	if scan.SkillID == nil {
		return "", fmt.Errorf("scan %d has no skill id", scan.ID)
	}
	var skill db.Skill
	if err := w.DB.First(&skill, *scan.SkillID).Error; err != nil {
		return "", fmt.Errorf("load skill %d: %w", *scan.SkillID, err)
	}
	scan.SkillName = skill.Name
	scan.SkillVersion = skill.Version
	w.DB.Model(scan).Updates(map[string]any{
		"skill_name":    skill.Name,
		"skill_version": skill.Version,
	})

	// Per-scan workspace keeps concurrent skills on the same repo from
	// clobbering each other's src/ and report.json. wrap() removes it on
	// successful completion; failed/cancelled dirs are left so the
	// operator can inspect what the skill saw. The clone itself lives in
	// the persistent repo-cache and is copied in by prepareRepoSrc.
	workRoot := w.scanWorkRoot(scan)
	if err := validateSkillPaths(skill.Name, skill.OutputFile); err != nil {
		return "", err
	}
	if scan.Repository.IsLocal() && skill.RequiresRemote {
		return "", fmt.Errorf("skill %q requires a remote repository; cannot run on local directory", skill.Name)
	}
	if err := os.MkdirAll(workRoot, dirPerm); err != nil {
		return "", fmt.Errorf("mkdir work: %w", err)
	}
	if scan.Repository.IsLocal() {
		if err := prepareLocalSrc(scan.Repository.LocalPath(), workRoot, emit); err != nil {
			return "", fmt.Errorf("copy local source: %w", err)
		}
		scan.Commit = gitHead(filepath.Join(workRoot, "src"))
	} else {
		prepare := w.PrepareRepoSrc
		if prepare == nil {
			prepare = w.prepareRepoSrc
		}
		cacheCommit, err := prepare(ctx, scan.Repository.URL, scan.Ref, workRoot, emit)
		if err != nil {
			if report, ok := w.handleCloneError(scan, err, emit); ok {
				return report, nil
			}
			return "", err
		}
		scan.Commit = cacheCommit
		w.clearCloneError(scan)
	}
	if err := w.prepareDiffRescan(ctx, scan, workRoot, emit); err != nil {
		return "", err
	}
	if err := applyRepositoryPathFilters(workRoot, &skill, scan.Repository.ScanConfig, emit); err != nil {
		return "", fmt.Errorf("apply path filters: %w", err)
	}

	skillDir := w.Runner.SkillDir(workRoot, skill.Name)
	if err := w.stageWorkspace(workRoot, skillDir, scan, &skill); err != nil {
		return "", err
	}

	prompt := buildLoggedPrompt(&skill)
	scan.Prompt = prompt
	w.DB.Model(scan).Update("prompt", prompt)

	sj := SkillJob{
		Repo:            scan.Repository,
		ScanID:          scan.ID,
		WorkRoot:        workRoot,
		SubPath:         scan.SubPath,
		Model:           scan.Model,
		Effort:          scan.Effort,
		Name:            skill.Name,
		SkillDir:        skillDir,
		OutputFile:      skill.OutputFile,
		Ref:             scan.Ref,
		MaxTurns:        w.resolveMaxTurns(skill.MaxTurns),
		AllowedTools:    skill.AllowedTools,
		SrcReady:        true,
		Profile:         scan.Profile,
		RequiresProfile: skill.RequiresProfile,
	}
	w.applyResume(scan, &sj, emit)
	res, err := w.Runner.RunSkill(ctx, sj, emit)
	w.applySkillResult(scan, res)
	if err != nil {
		if _, ok := errors.AsType[*MaxTurnsReachedError](err); ok && res.Report != "" {
			w.parsePartialSkillReport(&skill, scan, res.Report, emit)
		}
		return res.Report, err
	}

	report := res.Report
	if report != "" {
		var err error
		report, err = w.repairAndParseSkillOutput(ctx, &skill, scan, sj, report, emit)
		if err != nil {
			return report, err
		}
		w.auditSkillRefusals(ctx, &skill, scan, sj, emit)
	}
	return report, nil
}

// applySkillResult writes back the fields RunSkill reports about the run
// itself (as opposed to the skill's report) onto the scan row: session id
// and commit onto the in-memory struct (persisted by wrap()'s closing Save),
// and Profile/Backend to the DB immediately so a retry sees them even if the
// scan later fails hard. Called from every RunSkill call site so the four
// fields stay in one place.
func (w *Worker) applySkillResult(scan *db.Scan, res SkillResult) {
	if res.SessionID != "" && res.SessionID != scan.SessionID {
		scan.SessionID = res.SessionID
	}
	if res.Commit != "" {
		scan.Commit = res.Commit
	}
	if res.Profile != "" && res.Profile != scan.Profile {
		scan.Profile = res.Profile
		w.DB.Model(scan).Update("profile", res.Profile)
	}
	if res.Backend != "" && res.Backend != scan.Backend {
		scan.Backend = res.Backend
		w.DB.Model(scan).Update("backend", res.Backend)
	}
}

// parsePartialSkillReport runs parseSkillOutput against a max-turns
// partial and logs on failure. The scan is already returning a
// MaxTurnsReachedError so the parse error has nowhere useful to
// propagate; logging keeps a silently-malformed partial from vanishing.
func (w *Worker) parsePartialSkillReport(skill *db.Skill, scan *db.Scan, report string, emit func(Event)) {
	if err := w.parseSkillOutput(skill, scan, report, emit); err != nil {
		w.Log.Warn("parse partial skill output after max turns", "scan", scan.ID, "skill", skill.Name, "err", err)
	}
}

func (w *Worker) repairAndParseSkillOutput(ctx context.Context, skill *db.Skill, scan *db.Scan, sj SkillJob, report string, emit func(Event)) (string, error) {
	if skill.SchemaJSON != "" {
		if detail := ValidateReportSchema(skill.SchemaJSON, report); detail != "" {
			if repairedReport, ok := w.repairSchemaReport(ctx, skill, scan, sj, report, detail, emit); ok {
				report = repairedReport
			}
		}
	}
	if err := w.parseSkillOutput(skill, scan, report, emit); err != nil {
		return report, err
	}
	return report, nil
}

func (w *Worker) repairSchemaReport(ctx context.Context, skill *db.Skill, scan *db.Scan, sj SkillJob, report, detail string, emit func(Event)) (string, bool) {
	outputFile := skillOutputFile(skill)
	if scan.SessionID == "" {
		return "", false
	}

	emit(Event{Kind: KindText, Text: fmt.Sprintf("schema: %s failed validation; asking the agent to repair it", outputFile)})
	repairJob := sj
	repairJob.ResumeSessionID = scan.SessionID
	repairJob.ResumePrompt = buildSchemaRepairPrompt(skill, detail, report)
	repairJob.MaxTurns = schemaRepairMaxTurns
	res, err := w.Runner.RunSkill(ctx, repairJob, emit)
	w.applySkillResult(scan, res)
	if err != nil {
		emit(Event{Kind: KindError, Text: fmt.Sprintf("schema: repair attempt for %s failed: %v; parsing original output", outputFile, err)})
		return "", false
	}
	if res.Report == "" {
		emit(Event{Kind: KindError, Text: fmt.Sprintf("schema: repair attempt did not produce %s; parsing original output", outputFile)})
		return "", false
	}
	if detail = ValidateReportSchema(skill.SchemaJSON, res.Report); detail == "" {
		emit(Event{Kind: KindText, Text: fmt.Sprintf("schema: repaired %s validates", outputFile)})
		return res.Report, true
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("schema: repaired %s still does not validate; parsing original output", outputFile)})
	return "", false
}

func buildSchemaRepairPrompt(skill *db.Skill, detail, report string) string {
	outputFile := skillOutputFile(skill)
	return fmt.Sprintf(`Your previous %q skill run wrote ./%s, but it failed validation against ./%s.

Validation errors:
%s

Rewrite only ./%s with JSON that validates against ./%s. Preserve the facts from the previous run, do not restart the analysis, and do not write prose outside the JSON file.

Previous invalid ./%s:
%s`, skill.Name, outputFile, skillSchemaFile, detail, outputFile, skillSchemaFile, outputFile, truncateSchemaRepairReport(report))
}

func skillOutputFile(skill *db.Skill) string {
	if skill.OutputFile != "" {
		return skill.OutputFile
	}
	return defaultSkillOutputFile
}

func schemaValidationEvent(skill *db.Skill, detail string) Event {
	return Event{Kind: KindError, Text: fmt.Sprintf("schema: %s does not validate against %s:\n%s", skillOutputFile(skill), skillSchemaFile, detail)}
}

func truncateSchemaRepairReport(report string) string {
	report = strings.TrimSpace(report)
	if len(report) <= schemaRepairReportMaxSize {
		return report
	}
	return report[:schemaRepairReportMaxSize] + "\n... truncated ..."
}

func (w *Worker) parseSkillOutput(skill *db.Skill, scan *db.Scan, report string, emit func(Event)) error {
	if skill.SchemaJSON != "" {
		if detail := ValidateReportSchema(skill.SchemaJSON, report); detail != "" {
			emit(schemaValidationEvent(skill, detail))
			if w.SchemaStrict {
				return &SchemaValidationError{Skill: skill.Name, Detail: detail}
			}
		}
	}
	switch skill.OutputKind {
	case "findings":
		return w.parseFindingsOutput(skill, scan, report, emit)
	case "maintainers":
		return w.parseMaintainersOutput(scan, report, emit)
	case "repo_metadata":
		return w.parseRepoMetadataOutput(scan, report, emit)
	case "packages":
		return w.parsePackagesOutput(scan, report, emit)
	case "advisories":
		return w.parseAdvisoriesOutput(scan, report, emit)
	case "dependencies":
		return w.parseDependenciesOutput(scan, report, emit)
	case "finding_dedup":
		return w.parseFindingDedupOutput(scan, report, emit)
	case "verify":
		return w.parseVerifyOutput(scan, report, emit)
	case "revalidate":
		return w.parseRevalidateOutput(scan, report, emit)
	case "breaking_change":
		return w.parseBreakingChangeOutput(scan, report, emit)
	case "mitigation":
		return w.parseMitigationOutput(scan, report, emit)
	case "disclose":
		return w.parseDiscloseOutput(scan, report, emit)
	case "release_watch":
		return w.parseReleaseWatchOutput(scan, report, emit)
	case "subprojects":
		return w.parseSubprojectsOutput(scan, report, emit)
	case "repo_overview":
		return w.parseRepoOverviewOutput(scan, report, emit)
	case "posture":
		return w.parsePostureOutput(scan, report, emit)
	case "patch":
		return w.parsePatchOutput(scan, report, emit)
	}
	return nil
}

func (w *Worker) handleCloneError(scan *db.Scan, err error, emit func(Event)) (string, bool) {
	var ure *RepoUnreachableError
	if !errors.As(err, &ure) {
		return "", false
	}
	w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).
		Update("clone_error", ure.Error())
	emit(Event{Kind: KindText, Text: "repository unreachable, flagging"})
	report := fmt.Sprintf(`{"error":"repository unreachable","detail":%q}`, ure.Error())
	return report, true
}

func (w *Worker) clearCloneError(scan *db.Scan) {
	if scan.Repository.CloneError != "" {
		w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).
			Update("clone_error", "")
	}
}

// parseFindingsOutput feeds the existing spec-deep parser so skill-driven
// audits surface in the Findings tab alongside the legacy claude job.
// Findings are deduped against prior scans of the same repository by
// fingerprint: a match bumps last-seen on the existing row instead of
// creating a duplicate, so analyst triage state survives a rescan (#75).
func (w *Worker) parseFindingsOutput(skill *db.Skill, scan *db.Scan, report string, emit func(Event)) error {
	rep, err := parseReport([]byte(report))
	if err != nil {
		return err
	}
	findings := rep.toFindings(scan.ID, scan.RepositoryID, scan.Commit, scan.SubPath)
	findings = groupByFingerprint(findings, scan.SkillName)

	if skill.MinConfidence != "" {
		kept := findings[:0]
		for _, f := range findings {
			if db.ConfidenceAtLeast(f.Confidence, skill.MinConfidence) {
				kept = append(kept, f)
			}
		}
		if dropped := len(findings) - len(kept); dropped > 0 {
			emit(Event{Kind: KindText, Text: fmt.Sprintf("dropped %d finding(s) below min_confidence=%s", dropped, skill.MinConfidence)})
		}
		findings = kept
	}
	scan.FindingsCount = len(findings)

	// VIDs hash the code at each sink and snippets excerpt it around the
	// primary location, so both can only be captured while the scanned
	// checkout is still on disk at workRoot/src.
	srcDir := filepath.Join(w.scanWorkRoot(scan), "src")
	for i := range findings {
		findings[i].VID = w.computeVID(srcDir, findings[i].Locations)
		findings[i].Snippet = readSnippet(srcDir, findings[i].Location)
	}

	worst := ""
	created, observed := 0, 0
	seenThisScan := map[string]bool{}
	for i := range findings {
		f := &findings[i]
		if db.SeverityAtLeast(f.Severity, worst) || worst == "" {
			worst = f.Severity
		}
		seenThisScan[f.Fingerprint] = true

		wasCreated, perr := w.persistFinding(scan, f)
		if perr != nil {
			return perr
		}
		if wasCreated {
			created++
		} else {
			observed++
		}
	}

	missed := 0
	if scan.RescanMode != db.ScanRescanModeDiff {
		missed = w.markNotObserved(scan, seenThisScan)
	}
	retracted := w.markRetracted(scan, seenThisScan)

	emit(Event{Kind: KindText, Text: fmt.Sprintf("parsed %d finding(s): %d new, %d re-observed, %d not-observed, %d retracted",
		len(findings), created, observed, missed, retracted)})

	if db.SeverityAtLeast(worst, skill.FailOn) {
		return &FailOnThresholdError{Worst: worst, Threshold: skill.FailOn}
	}
	return nil
}

// persistFinding writes one finding into the repository's finding set using
// fingerprint dedup: a match re-observes the existing row, otherwise a new row
// is created and OnFindingCreated fires. Shared by the end-of-scan report
// ingestion and the streamed concurrent-finding log. On the dedup
// branch f.ID is set to the existing row so callers can report the live id.
func (w *Worker) persistFinding(scan *db.Scan, f *db.Finding) (created bool, err error) {
	f.LastSeenScanID = scan.ID
	f.LastSeenCommit = scan.Commit
	f.SeenCount = 1

	var existing db.Finding
	lookup := w.DB.Where("repository_id = ? AND fingerprint = ?", scan.RepositoryID, f.Fingerprint).
		Order("id").Limit(1).Find(&existing)
	if lookup.Error != nil {
		return false, fmt.Errorf("lookup existing finding: %w", lookup.Error)
	}
	if lookup.RowsAffected > 0 {
		if uerr := w.reobserveFinding(&existing, f, scan); uerr != nil {
			return false, uerr
		}
		f.ID = existing.ID
		return false, nil
	}
	if cerr := w.DB.Create(f).Error; cerr != nil {
		return false, fmt.Errorf("save finding: %w", cerr)
	}
	if w.OnFindingCreated != nil {
		w.OnFindingCreated(scan, f)
	}
	return true, nil
}

// reobserveFinding handles the dedup branch in parseFindingsOutput:
// bump the seen-count, refresh fields that may drift between scans
// (location, VID, references), and write an `observed` history row.
// Reference and history failures are logged but not fatal; the finding
// row write itself does propagate so a real DB error stops the scan.
func (w *Worker) reobserveFinding(existing, f *db.Finding, scan *db.Scan) error {
	// A finding already last-seen in this same scan was streamed into the
	// concurrent-finding log earlier in this run. Reconciling it from
	// the final report must be idempotent: do not bump seen_count or write
	// another observed-history row, or a streamed finding would count as
	// seen twice by one scan.
	sameScan := existing.LastSeenScanID == scan.ID

	seenCount := existing.SeenCount + 1
	if sameScan {
		seenCount = existing.SeenCount
	}
	updates := map[string]any{
		"last_seen_scan_id":   scan.ID,
		"last_seen_commit":    scan.Commit,
		"seen_count":          seenCount,
		"missed_count":        0,
		"last_missed_scan_id": 0,
		"location":            f.Location,
		"locations":           f.Locations,
	}
	if sameScan {
		// The existing row is this run's own streamed preview, which may
		// carry only the minimal fields the POST endpoint requires. The
		// final report is the authoritative full version of the same
		// finding, so parser-owned content is refreshed wholesale.
		// Cross-scan re-observation deliberately keeps existing content
		// (TestParseFindingsOutput_dedupesAcrossScans locks that in).
		maps.Copy(updates, map[string]any{
			"finding_id":   f.FindingID,
			"sinks":        f.Sinks,
			"title":        f.Title,
			"severity":     f.Severity,
			"confidence":   f.Confidence,
			"cwe":          f.CWE,
			"affected":     f.Affected,
			"reachability": f.Reachability,
			"quality_tier": f.QualityTier,
			"trace":        f.Trace,
			"boundary":     f.Boundary,
			"validation":   f.Validation,
			"prior_art":    f.PriorArt,
			"reach":        f.Reach,
			"rating":       f.Rating,
			"dup_check":    f.DupCheck,
		})
	}

	var statusRestore string
	if existing.Status == db.FindingRejected {
		var lastStatus db.FindingHistory
		lastStatusLookup := w.DB.Where("finding_id = ? AND field = ?", existing.ID, "status").
			Order("id desc").Limit(1).Find(&lastStatus)
		if lastStatusLookup.Error != nil {
			w.Log.Warn("lookup finding status history", "finding", existing.ID, "scan", scan.ID, "err", lastStatusLookup.Error)
		} else if lastStatusLookup.RowsAffected > 0 {
			if lastStatus.Source == db.SourceSystem {
				statusRestore = lastStatus.OldValue
				updates["status"] = statusRestore
			}
		}
	}

	// Refresh the VID and snippet so they track the code as it drifts,
	// but never wipe a stored one just because this run could not capture
	// it (vid binary missing, location gone, checkout evicted).
	if f.VID != "" {
		updates["vid"] = f.VID
	}
	if f.Snippet != "" {
		updates["snippet"] = f.Snippet
	}
	if err := w.DB.Model(&db.Finding{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update finding %d: %w", existing.ID, err)
	}
	if err := w.upsertFindingReferences(existing.ID, f.References); err != nil {
		w.Log.Warn("upsert finding references", "finding", existing.ID, "scan", scan.ID, "err", err)
	}
	if sameScan {
		return nil
	}
	if err := w.DB.Create(&db.FindingHistory{
		FindingID: existing.ID,
		Field:     "observed",
		NewValue:  fmt.Sprintf("scan %d @ %s", scan.ID, scan.Commit),
		Source:    db.SourceTool,
		By:        scan.SkillName,
	}).Error; err != nil {
		w.Log.Warn("record observed-again finding history", "finding", existing.ID, "scan", scan.ID, "err", err)
	}

	if statusRestore != "" {
		if err := w.DB.Create(&db.FindingHistory{
			FindingID: existing.ID,
			Field:     "status",
			OldValue:  string(db.FindingRejected),
			NewValue:  statusRestore,
			Source:    db.SourceSystem,
			By:        "re-observed in scan",
		}).Error; err != nil {
			w.Log.Warn("record finding status reopen history", "finding", existing.ID, "scan", scan.ID, "err", err)
		}
	}

	return nil
}

// upsertFindingReferences inserts any reference URLs not already on the
// finding. Used in the dedup branch so a re-observed finding picks up new
// or migration-added references without duplicating ones already present.
func (w *Worker) upsertFindingReferences(findingID uint, refs []db.FindingReference) error {
	if len(refs) == 0 {
		return nil
	}
	var existingURLs []string
	if err := w.DB.Model(&db.FindingReference{}).
		Where("finding_id = ?", findingID).
		Pluck("url", &existingURLs).Error; err != nil {
		return err
	}
	have := make(map[string]bool, len(existingURLs))
	for _, u := range existingURLs {
		have[u] = true
	}
	for _, r := range refs {
		if have[r.URL] {
			continue
		}
		if _, err := db.AddFindingReference(w.DB, findingID, r.URL, r.Tags, r.Summary); err != nil {
			return err
		}
	}
	return nil
}

// groupByFingerprint computes each finding's fingerprint and collapses
// entries that share one into a single finding whose Locations column
// carries every match position from the group (#191). Skills that
// emit one finding per match (semgrep, zizmor) hit this path when the
// same rule fires repeatedly in one file; pre-grouping skills emit
// distinct fingerprints and pass through unchanged.
func groupByFingerprint(in []db.Finding, skillName string) []db.Finding {
	out := make([]db.Finding, 0, len(in))
	idx := map[string]int{}
	for _, f := range in {
		f.Fingerprint = db.FingerprintFinding(skillName, f.SubPath, f.CWE, f.Location, f.Title)
		if i, ok := idx[f.Fingerprint]; ok {
			out[i].Locations = mergeLocations(out[i].Locations, f.Location, f.Locations)
			continue
		}
		f.Locations = mergeLocations(f.Locations, f.Location, "")
		idx[f.Fingerprint] = len(out)
		out = append(out, f)
	}
	return out
}

// mergeLocations folds extra file:line entries into a newline-joined
// set, dropping blanks and duplicates while preserving first-seen
// order so the primary entry stays at the head.
func mergeLocations(base string, more ...string) string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		for e := range strings.SplitSeq(s, "\n") {
			e = strings.TrimSpace(e)
			if e == "" || seen[e] {
				continue
			}
			seen[e] = true
			out = append(out, e)
		}
	}
	add(base)
	for _, m := range more {
		add(m)
	}
	return strings.Join(out, "\n")
}

// FailOnThresholdError is returned when a scan's findings include at
// least one at or above the skill's fail_on severity. wrap() treats it
// as a completed run (the report is saved) that is marked failed so
// the repo list shows red.
type FailOnThresholdError struct {
	Worst     string
	Threshold string
}

func (e *FailOnThresholdError) Error() string {
	return fmt.Sprintf("%s-severity finding meets fail_on=%s", e.Worst, e.Threshold)
}

// markNotObserved bumps MissedCount on open findings that this scan was
// in scope to re-observe (same repo, same skill, same subpath) but whose
// fingerprint did not appear in the scan output. Closed findings (fixed,
// published, rejected, duplicate) are left alone. Returns the number of
// rows touched so the scan log can report it.
func (w *Worker) markNotObserved(scan *db.Scan, seen map[string]bool) int {
	sameSkill := w.DB.Model(&db.Scan{}).Select("id").
		Where("repository_id = ? AND skill_name = ?", scan.RepositoryID, scan.SkillName)
	var prior []db.Finding
	w.DB.Where("repository_id = ? AND sub_path = ?", scan.RepositoryID, scan.SubPath).
		Where("scan_id IN (?)", sameSkill).
		Where("scan_id <> ?", scan.ID).
		Where("status NOT IN ?", db.ClosedFindingLifecycles).
		Find(&prior)

	missed := 0
	for _, f := range prior {
		if seen[f.Fingerprint] {
			continue
		}

		missedCount := f.MissedCount + 1
		updates := map[string]any{
			"missed_count":        missedCount,
			"last_missed_scan_id": scan.ID,
		}

		autoReject := false
		if w.AutoRejectMissedCount > 0 && missedCount >= w.AutoRejectMissedCount {
			if f.Status == db.FindingNew || f.Status == db.FindingEnriched || f.Status == db.FindingTriaged || f.Status == db.FindingReady {
				if !w.hasEverBeenReportedOrAcknowledged(f.ID) {
					autoReject = true
					updates["status"] = db.FindingRejected
				}
			}
		}

		if uerr := w.DB.Model(&db.Finding{}).Where("id = ?", f.ID).Updates(updates).Error; uerr != nil {
			w.Log.Error("mark finding not-observed", "finding", f.ID, "err", uerr)
			continue
		}
		_ = w.DB.Create(&db.FindingHistory{
			FindingID: f.ID,
			Field:     "not_observed",
			NewValue:  fmt.Sprintf("scan %d @ %s", scan.ID, scan.Commit),
			Source:    db.SourceTool,
			By:        scan.SkillName,
		}).Error

		if autoReject {
			_ = w.DB.Create(&db.FindingHistory{
				FindingID: f.ID,
				Field:     "status",
				OldValue:  string(f.Status),
				NewValue:  string(db.FindingRejected),
				Source:    db.SourceSystem,
				By:        fmt.Sprintf("not observed in %d consecutive rescans", missedCount),
			}).Error
		}

		missed++
	}
	return missed
}

// hasEverBeenReportedOrAcknowledged checks if the finding ever reached reported or acknowledged status.
func (w *Worker) hasEverBeenReportedOrAcknowledged(findingID uint) bool {
	var count int64
	w.DB.Model(&db.FindingHistory{}).
		Where("finding_id = ? AND field = ? AND (new_value = ? OR new_value = ?)",
			findingID, "status", string(db.FindingReported), string(db.FindingAcknowledged)).
		Count(&count)
	return count > 0
}

// markRetracted flags findings this scan streamed into the concurrent-finding
// log but then left out of its final report.json. The row is kept — a sibling
// may have stood down citing it, so deleting would lose the bug from both scans
// — but a `retracted` history row records that the scan did not confirm it in
// the end, so it is no longer indistinguishable from a confirmed finding. Only
// rows this scan both created and last saw are considered; a finding a sibling
// re-observed since stays live under that sibling.
func (w *Worker) markRetracted(scan *db.Scan, seen map[string]bool) int {
	var streamed []db.Finding
	w.DB.Where("scan_id = ? AND last_seen_scan_id = ?", scan.ID, scan.ID).Find(&streamed)

	retracted := 0
	for _, f := range streamed {
		if seen[f.Fingerprint] {
			continue
		}
		if err := w.DB.Create(&db.FindingHistory{
			FindingID: f.ID,
			Field:     "retracted",
			NewValue:  fmt.Sprintf("scan %d @ %s", scan.ID, scan.Commit),
			Source:    db.SourceTool,
			By:        scan.SkillName,
		}).Error; err != nil {
			w.Log.Error("mark finding retracted", "finding", f.ID, "err", err)
			continue
		}
		retracted++
	}
	return retracted
}

// parseMaintainersOutput upserts Maintainer rows and links them to the
// scanned repo. Mirrors the legacy doMaintainerAnalysis logic so the
// maintainers skill and the old Go handler stay interchangeable.
func (w *Worker) parseMaintainersOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Maintainers []struct {
			Login    string `json:"login"`
			Name     string `json:"name"`
			Email    string `json:"email"`
			Role     string `json:"role"`
			Status   string `json:"status"`
			Evidence string `json:"evidence"`
		} `json:"maintainers"`
		DisclosureChannel string `json:"disclosure_channel"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse maintainers report: %w", err)
	}
	var repo db.Repository
	if err := w.DB.First(&repo, scan.RepositoryID).Error; err != nil {
		return err
	}
	if strings.TrimSpace(result.DisclosureChannel) != "" {
		if err := w.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
			Update("disclosure_channel", result.DisclosureChannel).Error; err != nil {
			return fmt.Errorf("update disclosure channel: %w", err)
		}
	}
	var linked []db.Maintainer
	for _, rm := range result.Maintainers {
		if rm.Login == "" {
			continue
		}
		var m db.Maintainer
		w.DB.Where(db.Maintainer{Login: rm.Login}).FirstOrCreate(&m)
		if rm.Name != "" {
			m.Name = rm.Name
		}
		if validEmail(rm.Email) {
			m.Email = rm.Email
		}
		switch rm.Status {
		case "active":
			m.Status = db.MaintainerActive
		case "inactive":
			m.Status = db.MaintainerInactive
		}
		if rm.Evidence != "" {
			m.Notes = rm.Role + ": " + rm.Evidence
		}
		w.DB.Save(&m)
		linked = append(linked, m)
	}
	if len(linked) > 0 {
		_ = w.DB.Model(&repo).Association("Maintainers").Replace(linked)
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("identified %d maintainer(s)", len(result.Maintainers))})
	return nil
}

// applyPathFilters prunes workRoot/src down to the files visible to the
// skill given its scrutineer.paths / scrutineer.ignore_paths. This is a
// scoping mechanism for performance and noise reduction, not an
// isolation boundary: symlinks within the workspace are preserved by
// the upstream copyTree, so a skill that follows one can still read
// outside the filtered tree. The builtin skip list applies whenever the
// skill has not declared scrutineer.paths; ignore_paths layers on top.
// Whole subtrees blanket-excluded by deny patterns are removed in one
// shot rather than walked file-by-file. .git is always preserved.
// Emits a one-line scan-log entry with the count when at least one file
// is removed.
func applyPathFilters(workRoot string, skill *db.Skill, emit func(Event)) error {
	return applyPathFiltersWithSkips(workRoot, skill, nil, emit)
}

// applyRepositoryPathFilters layers the repository's configured skip patterns
// on top of the skill's filters. A repository cannot use this setting to bring
// files back that a skill or the builtin skip list has excluded.
func applyRepositoryPathFilters(workRoot string, skill *db.Skill, rawConfig string, emit func(Event)) error {
	cfg, err := repoconfig.Parse(rawConfig)
	if err != nil {
		return fmt.Errorf("parse repository scan config: %w", err)
	}
	return applyPathFiltersWithSkips(workRoot, skill, cfg.Skip, emit)
}

func applyPathFiltersWithSkips(workRoot string, skill *db.Skill, repositorySkips []string, emit func(Event)) error {
	paths := skills.SplitPatterns(skill.Paths)
	ignorePaths := skills.SplitPatterns(skill.IgnorePaths)
	ignorePaths = append(ignorePaths, repositorySkips...)
	src := filepath.Join(workRoot, "src")
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// Unconditional strip of agent-instruction files (CLAUDE.md, AGENTS.md,
	// .claude/, .cursor/, ...) so a hostile repo cannot inject standing
	// instructions into the auditing agent. Runs before the paths filter
	// because scrutineer.paths bypasses BuiltinSkipPaths and must not be
	// able to opt these back in. See threatmodel.md T5.
	stripped, err := stripAgentDirectives(src)
	if err != nil {
		return fmt.Errorf("strip agent directives: %w", err)
	}
	if stripped > 0 {
		emit(Event{Kind: KindText, Text: fmt.Sprintf("%d agent-directive item(s) stripped from ./src", stripped)})
	}
	excluded := 0
	err = filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == src {
			return nil
		}
		rel, relErr := filepath.Rel(src, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ".git" {
				return filepath.SkipDir
			}
			if skills.DirAllExcluded(rel, paths, ignorePaths) {
				n, rmErr := removeSubtree(p)
				if rmErr != nil {
					return rmErr
				}
				excluded += n
				return filepath.SkipDir
			}
			return nil
		}
		if !skills.PathIncluded(rel, paths, ignorePaths) {
			if rmErr := os.Remove(p); rmErr != nil {
				return rmErr
			}
			excluded++
		}
		return nil
	})
	if err != nil {
		return err
	}
	if excluded > 0 {
		emit(Event{Kind: KindText, Text: fmt.Sprintf("%d file(s) excluded by path filters", excluded)})
	}
	return nil
}

func removeSubtree(root string) (int, error) {
	n := 0
	walkErr := filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	if walkErr != nil {
		return 0, walkErr
	}
	if err := os.RemoveAll(root); err != nil {
		return 0, err
	}
	return n, nil
}

func validateSkillPaths(name, outputFile string) error {
	if !filepath.IsLocal(name) || strings.Contains(name, "/") {
		return fmt.Errorf("skill name %q contains path separators", name)
	}
	if outputFile != "" && (outputFile != filepath.Base(outputFile) || !filepath.IsLocal(outputFile)) {
		return fmt.Errorf("skill output_file %q contains path separators", outputFile)
	}
	return nil
}

// ValidateSkillPaths exposes the same path checks production scans apply before
// staging a skill. Eval harnesses call this before invoking StageWorkspace.
func ValidateSkillPaths(name, outputFile string) error {
	return validateSkillPaths(name, outputFile)
}

// stageSkill writes the skill's files into dst so claude-code discovers them
// at ./.claude/skills/{name}. SKILL.md and schema.json are reconstructed from
// the DB; supplementary files (scripts/, references/, assets/) are copied
// from SourcePath when the skill was loaded from disk.
//
// schema.json is also written to workRoot so the `./schema.json` path every
// SKILL.md references resolves without the model having to glob for it (#221).
// context.json is mirrored from workRoot into dst so `./context.json` resolves
// from the skill directory as well as the workspace root; that read means
// stageSkill must run after stageContext, which is what produces the file.
func stageSkill(skill *db.Skill, workRoot, dst string) error {
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, dirPerm); err != nil {
		return err
	}
	skillMD := renderSkillMD(skill)
	if err := os.WriteFile(filepath.Join(dst, "SKILL.md"), []byte(skillMD), filePerm); err != nil {
		return err
	}
	if skill.SchemaJSON != "" {
		if err := os.WriteFile(filepath.Join(dst, "schema.json"), []byte(skill.SchemaJSON), filePerm); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(workRoot, "schema.json"), []byte(skill.SchemaJSON), filePerm); err != nil {
			return err
		}
	}
	switch data, err := os.ReadFile(filepath.Join(workRoot, "context.json")); {
	case errors.Is(err, os.ErrNotExist):
		// stageContext hasn't run (or this caller doesn't use one); no mirror.
	case err != nil:
		return fmt.Errorf("read context.json: %w", err)
	default:
		if werr := os.WriteFile(filepath.Join(dst, "context.json"), data, filePerm); werr != nil {
			return werr
		}
	}
	if skill.SourcePath != "" && skill.Source != "ui" {
		if err := copyAux(skill.SourcePath, dst); err != nil {
			return fmt.Errorf("copy aux files: %w", err)
		}
		if err := mirrorScripts(skill.SourcePath, workRoot); err != nil {
			return fmt.Errorf("mirror scripts: %w", err)
		}
	}
	return nil
}

// mirrorScripts copies the skill's scripts/ directory (if any) to
// workRoot/scripts/ so the `bash scripts/foo.sh` / `python3 scripts/foo.py`
// instructions every SKILL.md uses resolve from the workspace root on the
// first try, without the model having to glob for them. Same pattern as
// schema.json (#221). The destination is cleared first so a retry after a
// skill edit doesn't run a mix of old and new scripts.
func mirrorScripts(src, workRoot string) error {
	srcScripts := filepath.Join(src, "scripts")
	info, err := os.Stat(srcScripts)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	dst := filepath.Join(workRoot, "scripts")
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	return CopyTree(srcScripts, dst)
}

// renderSkillMD rebuilds a SKILL.md from the stored fields. The frontmatter
// is re-serialised rather than preserved verbatim so UI edits round-trip
// cleanly; order is not preserved but the spec doesn't require it.
func renderSkillMD(skill *db.Skill) string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "name: %s\n", skill.Name)
	fmt.Fprintf(&b, "description: %s\n", oneLine(skill.Description))
	if skill.License != "" {
		fmt.Fprintf(&b, "license: %s\n", oneLine(skill.License))
	}
	if skill.Compatibility != "" {
		fmt.Fprintf(&b, "compatibility: %s\n", oneLine(skill.Compatibility))
	}
	if skill.AllowedTools != "" {
		fmt.Fprintf(&b, "allowed-tools: %s\n", skill.AllowedTools)
	}
	if skill.Metadata != "" {
		fmt.Fprintf(&b, "metadata_json: %s\n", oneLine(skill.Metadata))
	}
	b.WriteString("---\n\n")
	b.WriteString(skill.Body)
	if !strings.HasSuffix(skill.Body, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// stageImportPayload writes the raw report bytes from an import-fallback
// run into the workspace at import/report, where the ingest skill expects
// to find them. Every scan without a payload (everything except the
// import fallback) stages nothing.
func stageImportPayload(workRoot string, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	dir := filepath.Join(workRoot, "import")
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report"), payload, filePerm)
}

// stageContext writes the workspace-level context.json that every skill can
// rely on. Kept small and boring on purpose: skills that need more detail
// can read it from the clone. The scrutineer block gives skills enough to
// call back into the host API (list scans, trigger more skills).
// metadataDir returns the per-staging-repo metadata directory the
// worker should hand to skills. Empty config falls back to the default
// so callers never have to repeat the constant.
func (w *Worker) metadataDir() string {
	if w.MetadataDir == "" {
		return DefaultMetadataDir
	}
	return w.MetadataDir
}

func stageContext(workRoot, apiBase, forkOrg, metadataDir string, scan *db.Scan, repo *db.Repository) error {
	if err := os.MkdirAll(workRoot, dirPerm); err != nil {
		return err
	}
	ctx := skillContext{
		Repository: skillContextRepo{
			URL:           repo.URL,
			HTMLURL:       repo.HTMLURL,
			Name:          repo.Name,
			FullName:      repo.FullName,
			DefaultBranch: repo.DefaultBranch,
		},
		Scrutineer: skillContextScrutineer{
			APIBase:     apiBase,
			ScanID:      scan.ID,
			Token:       scan.APIToken,
			RepoID:      scan.RepositoryID,
			ForkOrg:     forkOrg,
			MetadataDir: metadataDir,
		},
	}
	config, err := repoconfig.Parse(repo.ScanConfig)
	if err != nil {
		return fmt.Errorf("parse repository scan config: %w", err)
	}
	if !config.Empty() {
		ctx.Scrutineer.ScanConfig = &config
	}
	if scan.SkillID != nil {
		ctx.Scrutineer.SkillID = *scan.SkillID
	}
	if scan.FindingID != nil {
		ctx.Scrutineer.FindingID = *scan.FindingID
	}
	if scan.DependentID != nil {
		ctx.Scrutineer.DependentID = *scan.DependentID
	}
	if scan.Ref != "" {
		ctx.Scrutineer.ScanRef = scan.Ref
	}
	if scan.SubPath != "" {
		ctx.Scrutineer.ScanSubPath = scan.SubPath
	}
	if scan.ScanGroup != "" {
		ctx.Scrutineer.ScanGroup = scan.ScanGroup
	}
	if scan.RescanMode == db.ScanRescanModeDiff {
		rc := &skillContextRescan{
			Mode:                db.ScanRescanModeDiff,
			BaseCommit:          scan.DiffBaseCommit,
			HeadCommit:          scan.Commit,
			DiffFile:            "diff.patch",
			ChangedFilesFile:    "changed_files.json",
			CoverageMetadataKey: "coverage",
		}
		if scan.DiffBaseScanID != nil {
			rc.BaseScanID = *scan.DiffBaseScanID
		}
		if scan.DiffThreatModelScanID != nil {
			rc.ThreatModelScanID = *scan.DiffThreatModelScanID
			rc.OldThreatModelFile = "old_threat_model.json"
		}
		ctx.Scrutineer.Rescan = rc
	}
	b, err := json.MarshalIndent(ctx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workRoot, "context.json"), b, filePerm)
}

// stageWorkspace writes everything other than ./src into the scan
// workspace: context.json, the operator's threat-model override, the
// skill bundle under .claude/skills/{name}/, and any import payload.
// Pulled out of doSkill to keep that function under the gocognit
// threshold; the error wrapping stays here so failures still name the
// staging step.
func (w *Worker) stageWorkspace(workRoot, skillDir string, scan *db.Scan, skill *db.Skill) error {
	return StageWorkspace(workRoot, skillDir, w.APIBase, w.ForkOrg, w.metadataDir(), scan, skill)
}

// StageWorkspace writes the same workspace side files as a production skill
// scan: context.json, an optional threat-model override, the rendered skill
// bundle, and optional import payloads.
func StageWorkspace(workRoot, skillDir, apiBase, forkOrg, metadataDir string, scan *db.Scan, skill *db.Skill) error {
	if err := stageContext(workRoot, apiBase, forkOrg, metadataDir, scan, &scan.Repository); err != nil {
		return fmt.Errorf("stage context: %w", err)
	}
	if err := stageThreatModel(workRoot, scan.SubPath, scan.Repository.ThreatModel); err != nil {
		return fmt.Errorf("stage threat model: %w", err)
	}
	if err := stageSkill(skill, workRoot, skillDir); err != nil {
		return fmt.Errorf("stage skill: %w", err)
	}
	if err := stageImportPayload(workRoot, scan.ImportPayload); err != nil {
		return fmt.Errorf("stage import payload: %w", err)
	}
	return nil
}

// stageThreatModel writes the repository's operator-edited threat model to
// ./threat_model.json so skills that consume one (security-deep-dive) can
// load it in preference to fetching the latest threat-model scan from the
// API. No-op when the repository has no override set, and for
// subpath-scoped scans: the override is authored against the repository
// root, and the staged file would take precedence over anything the
// skill derives from the subproject itself.
func stageThreatModel(workRoot, subPath, model string) error {
	if model == "" || subPath != "" {
		return nil
	}
	return os.WriteFile(filepath.Join(workRoot, "threat_model.json"), []byte(model), filePerm)
}

// copyAux copies every top-level entry in src other than SKILL.md and
// schema.json (which are staged from the DB row) into dst, recursively.
// Delegates to copyTree so symlink and permission handling lives in one
// place; this preserves scripts/ and references/ for skills that bundle
// them.
func copyAux(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if name == "SKILL.md" || name == "schema.json" {
			continue
		}
		if err := CopyTree(filepath.Join(src, name), filepath.Join(dst, name)); err != nil {
			return err
		}
	}
	return nil
}
