package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

const filePerm = 0o644

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
	// ForkOrg is the GitHub organisation the fork skill stages scanned
	// repositories into. Absent when fork_org is unconfigured.
	ForkOrg string `json:"fork_org,omitempty"`
	// MetadataDir is the path inside a staging repo where scrutineer
	// metadata lives (`.scrutineer/` by default). Always written so
	// skills can build paths without re-applying the default.
	MetadataDir string `json:"metadata_dir"`
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
	if err := applyPathFilters(workRoot, &skill, emit); err != nil {
		return "", fmt.Errorf("apply path filters: %w", err)
	}

	skillDir := filepath.Join(workRoot, ".claude", "skills", skill.Name)
	if err := stageContext(workRoot, w.APIBase, w.ForkOrg, w.metadataDir(), scan, &scan.Repository); err != nil {
		return "", fmt.Errorf("stage context: %w", err)
	}
	if err := stageSkill(&skill, workRoot, skillDir); err != nil {
		return "", fmt.Errorf("stage skill: %w", err)
	}
	if err := stageImportPayload(workRoot, scan.ImportPayload); err != nil {
		return "", fmt.Errorf("stage import payload: %w", err)
	}

	prompt := buildLoggedPrompt(&skill)
	scan.Prompt = prompt
	w.DB.Model(scan).Update("prompt", prompt)

	sj := SkillJob{
		Repo:            scan.Repository,
		ScanID:          scan.ID,
		WorkRoot:        workRoot,
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
	if err != nil {
		if _, ok := errors.AsType[*MaxTurnsReachedError](err); ok && res.Report != "" {
			w.parsePartialSkillReport(&skill, scan, res.Report, emit)
		}
		return res.Report, err
	}

	if res.Report != "" {
		if err := w.parseSkillOutput(&skill, scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	}
	return res.Report, nil
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

func (w *Worker) parseSkillOutput(skill *db.Skill, scan *db.Scan, report string, emit func(Event)) error {
	if skill.SchemaJSON != "" {
		if detail := validateReportSchema(skill.SchemaJSON, report); detail != "" {
			emit(Event{Kind: KindError, Text: "schema: report.json does not validate against schema.json:\n" + detail})
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
	case "dependents":
		return w.parseDependentsOutput(scan, report, emit)
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

	// VIDs hash the code at each sink, so they can only be computed
	// while the scanned checkout is still on disk at workRoot/src.
	srcDir := filepath.Join(w.scanWorkRoot(scan), "src")
	for i := range findings {
		findings[i].VID = w.computeVID(srcDir, findings[i].Locations)
	}

	worst := ""
	created, observed := 0, 0
	seenThisScan := map[string]bool{}
	for i := range findings {
		f := &findings[i]
		if db.SeverityAtLeast(f.Severity, worst) || worst == "" {
			worst = f.Severity
		}
		f.LastSeenScanID = scan.ID
		f.LastSeenCommit = scan.Commit
		f.SeenCount = 1
		seenThisScan[f.Fingerprint] = true

		var existing db.Finding
		err := w.DB.Where("repository_id = ? AND fingerprint = ?", scan.RepositoryID, f.Fingerprint).
			Order("id").First(&existing).Error
		if err == nil {
			if uerr := w.reobserveFinding(&existing, f, scan); uerr != nil {
				return uerr
			}
			observed++
			continue
		}
		if cerr := w.DB.Create(f).Error; cerr != nil {
			return fmt.Errorf("save finding: %w", cerr)
		}
		created++
		if w.OnFindingCreated != nil {
			w.OnFindingCreated(scan, f)
		}
	}

	missed := w.markNotObserved(scan, seenThisScan)

	emit(Event{Kind: KindText, Text: fmt.Sprintf("parsed %d finding(s): %d new, %d re-observed, %d not-observed",
		len(findings), created, observed, missed)})

	if db.SeverityAtLeast(worst, skill.FailOn) {
		return &FailOnThresholdError{Worst: worst, Threshold: skill.FailOn}
	}
	return nil
}

// reobserveFinding handles the dedup branch in parseFindingsOutput:
// bump the seen-count, refresh fields that may drift between scans
// (location, VID, references), and write an `observed` history row.
// Reference and history failures are logged but not fatal; the finding
// row write itself does propagate so a real DB error stops the scan.
func (w *Worker) reobserveFinding(existing, f *db.Finding, scan *db.Scan) error {
	updates := map[string]any{
		"last_seen_scan_id":   scan.ID,
		"last_seen_commit":    scan.Commit,
		"seen_count":          existing.SeenCount + 1,
		"missed_count":        0,
		"last_missed_scan_id": 0,
		"location":            f.Location,
		"locations":           f.Locations,
	}
	// Refresh the VID so it tracks the code as it drifts, but never
	// wipe a stored one just because this run could not compute (vid
	// binary missing, location gone).
	if f.VID != "" {
		updates["vid"] = f.VID
	}
	if err := w.DB.Model(&db.Finding{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update finding %d: %w", existing.ID, err)
	}
	if err := w.upsertFindingReferences(existing.ID, f.References); err != nil {
		w.Log.Warn("upsert finding references", "finding", existing.ID, "scan", scan.ID, "err", err)
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
		for _, e := range strings.Split(s, "\n") {
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
	closed := []db.FindingLifecycle{
		db.FindingFixed, db.FindingPublished, db.FindingRejected, db.FindingDuplicate,
	}
	sameSkill := w.DB.Model(&db.Scan{}).Select("id").
		Where("repository_id = ? AND skill_name = ?", scan.RepositoryID, scan.SkillName)
	var prior []db.Finding
	w.DB.Where("repository_id = ? AND sub_path = ?", scan.RepositoryID, scan.SubPath).
		Where("scan_id IN (?)", sameSkill).
		Where("scan_id <> ?", scan.ID).
		Where("status NOT IN ?", closed).
		Find(&prior)

	missed := 0
	for _, f := range prior {
		if seen[f.Fingerprint] {
			continue
		}
		if uerr := w.DB.Model(&db.Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
			"missed_count":        f.MissedCount + 1,
			"last_missed_scan_id": scan.ID,
		}).Error; uerr != nil {
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
		missed++
	}
	return missed
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
	paths := skills.SplitPatterns(skill.Paths)
	ignorePaths := skills.SplitPatterns(skill.IgnorePaths)
	src := filepath.Join(workRoot, "src")
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	excluded := 0
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
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

// stageSkill writes the skill's files into dst so claude-code discovers them
// at ./.claude/skills/{name}. Only SKILL.md and schema.json are reconstructed
// from the DB; supplementary files (scripts/, references/, assets/) are
// copied from SourcePath when the skill was loaded from disk.
//
// schema.json is also written to workRoot so the `./schema.json` path every
// SKILL.md references resolves without the model having to glob for it (#221).
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
	if skill.SourcePath != "" && skill.Source != "ui" {
		if err := copyAux(skill.SourcePath, dst); err != nil {
			return fmt.Errorf("copy aux files: %w", err)
		}
	}
	return nil
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
	b, err := json.MarshalIndent(ctx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workRoot, "context.json"), b, filePerm)
}

// copyAux walks src looking for any files other than SKILL.md and schema.json
// (which are staged from the DB row) and copies them into dst at the same
// relative path. This preserves scripts/ and references/ for skills that
// bundle them.
func copyAux(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." || rel == "SKILL.md" || rel == "schema.json" {
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, dirPerm)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode())
	})
}
