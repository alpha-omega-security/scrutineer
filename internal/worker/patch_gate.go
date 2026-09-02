package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// patchReport mirrors the patch skill's report.json shape. Only the fields
// the gate needs; rationale, files_changed, tests_added, notes stay in the
// raw Scan.Report and are surfaced by the web layer.
type patchReport struct {
	Patch      string `json:"patch"`
	BaseCommit string `json:"base_commit"`
	Error      string `json:"error"`
}

// parsePatchOutput runs the applicability gate over a patch skill's diff and,
// on pass, appends an immutable RemediationAttempt and updates the
// Finding.SuggestedFix projection through WriteFindingField. A gate failure is
// not a scan error: the scan completed and the diff remains in Scan.Report.
func (w *Worker) parsePatchOutput(ctx context.Context, scan *db.Scan, report string, emit func(Event)) error {
	var rep patchReport
	if err := json.Unmarshal([]byte(report), &rep); err != nil {
		return fmt.Errorf("parse patch: %w", err)
	}
	if rep.Error != "" {
		emit(Event{Kind: KindText, Text: "patch: skill refused: " + rep.Error})
		return nil
	}
	if strings.TrimSpace(rep.Patch) == "" {
		emit(Event{Kind: KindText, Text: "patch: empty diff, nothing to gate"})
		return nil
	}
	if scan.FindingID == nil {
		emit(Event{Kind: KindText, Text: "patch: scan is not finding-scoped, leaving suggested_fix unset"})
		return nil
	}
	if strings.TrimSpace(rep.BaseCommit) == "" {
		emit(Event{Kind: KindText, Text: "patch: gate rejected: base_commit is required for reproducible re-attack"})
		return nil
	}
	scanCommit := strings.TrimSpace(scan.Commit)
	if scanCommit == "" || strings.TrimSpace(rep.BaseCommit) != scanCommit {
		emit(Event{Kind: KindText, Text: fmt.Sprintf(
			"patch: gate rejected: base_commit %q does not match scan commit %q", rep.BaseCommit, scanCommit)})
		return nil
	}

	var f db.Finding
	if err := w.DB.First(&f, *scan.FindingID).Error; err != nil {
		return fmt.Errorf("load finding %d: %w", *scan.FindingID, err)
	}

	repo := scan.Repository
	if repo.ID == 0 {
		if err := w.DB.First(&repo, scan.RepositoryID).Error; err != nil {
			return fmt.Errorf("load repository %d: %w", scan.RepositoryID, err)
		}
	}
	reason, err := w.gatePatch(ctx, repo, scanCommit, f.Location, rep.Patch)
	if err != nil {
		return err
	}
	if reason != "" {
		emit(Event{Kind: KindText, Text: "patch: gate rejected: " + reason})
		return nil
	}

	attempt, err := w.recordRemediationAttempt(scan, f.ID, rep)
	if err != nil {
		return err
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf(
		"patch: gate passed, recorded remediation attempt %d for finding %d", attempt.Attempt, f.ID)})
	return nil
}

func (w *Worker) recordRemediationAttempt(scan *db.Scan, findingID uint, rep patchReport) (db.RemediationAttempt, error) {
	var attempt db.RemediationAttempt
	err := w.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Where("patch_scan_id = ?", scan.ID).Limit(1).Find(&attempt)
		if result.Error != nil {
			return fmt.Errorf("check existing remediation attempt: %w", result.Error)
		}
		if result.RowsAffected > 0 {
			return nil
		}

		// Acquire the finding's write lock before allocating its next number so
		// concurrent patch scans cannot both claim the same attempt.
		if err := tx.Model(&db.Finding{}).Where("id = ?", findingID).
			UpdateColumn("updated_at", time.Now()).Error; err != nil {
			return fmt.Errorf("lock finding for remediation attempt: %w", err)
		}
		var latest int
		if err := tx.Model(&db.RemediationAttempt{}).Where("finding_id = ?", findingID).
			Select("COALESCE(MAX(attempt), 0)").Scan(&latest).Error; err != nil {
			return fmt.Errorf("allocate remediation attempt: %w", err)
		}
		attempt = db.RemediationAttempt{
			FindingID:   findingID,
			PatchScanID: scan.ID,
			Attempt:     latest + 1,
			Patch:       rep.Patch,
			BaseCommit:  rep.BaseCommit,
			CreatedAt:   time.Now(),
		}
		if err := tx.Create(&attempt).Error; err != nil {
			return fmt.Errorf("record remediation attempt: %w", err)
		}
		if err := db.WriteFindingField(tx, findingID, "suggested_fix", rep.Patch, db.SourceModel, "patch"); err != nil {
			return fmt.Errorf("write suggested_fix: %w", err)
		}
		if err := db.WriteFindingField(tx, findingID, "suggested_fix_commit", rep.BaseCommit, db.SourceModel, "patch"); err != nil {
			return fmt.Errorf("write suggested_fix_commit: %w", err)
		}
		return nil
	})
	return attempt, err
}

// stagePatchGateSrc creates a host-owned copy that has never been exposed to
// the scan runner. Git must not inspect the runner's checkout after a skill
// returns because the runner can rewrite .git/config and make Git execute a
// filter, hook, or monitor as the host user. Remote repositories come from the
// persistent clone cache under its per-URL lock; local repositories are cloned
// with independent Git metadata so linked-worktree pointers cannot lead back to
// the operator's real index.
func (w *Worker) stagePatchGateSrc(repo db.Repository) (string, func(), error) {
	tmp, err := os.MkdirTemp("", "scrutineer-gate-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	if repo.IsLocal() {
		if err := cloneLocalPatchGateSrc(repo.LocalPath(), filepath.Join(tmp, "src")); err != nil {
			cleanup()
			return "", nil, err
		}
	} else {
		mu := w.cacheMutex(repo.URL)
		mu.Lock()
		err = CopyTree(
			filepath.Join(RepoCacheRoot(w.DataDir, repo.URL), "src"),
			filepath.Join(tmp, "src"),
		)
		mu.Unlock()
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("copy repository cache: %w", err)
		}
	}
	return filepath.Join(tmp, "src"), cleanup, nil
}

// cloneLocalPatchGateSrc uses the normal Git transport instead of the local
// hard-link optimization. Besides avoiding shared objects, this dereferences a
// linked worktree's .git file into independent metadata under dst.
func cloneLocalPatchGateSrc(localPath, dst string) error {
	cmd := exec.Command("git", "clone", "--quiet", "--no-local", "--", localPath, dst)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("clone local source: %w: %s", err, firstLine(string(out)))
	}
	return nil
}

// gatePatch validates a diff only against the scan's commit in a fresh checkout
// the runner never touched. It returns a one-line rejection reason, if any.
func (w *Worker) gatePatch(
	ctx context.Context,
	repo db.Repository,
	commit, location, diff string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !repo.IsLocal() {
		if err := w.EnsureCommit(ctx, repo.URL, commit); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", ctxErr
			}
			return "ensure scan commit: " + firstLine(err.Error()), nil
		}
	}
	srcDir, cleanup, err := w.stagePatchGateSrc(repo)
	if err != nil {
		return "stage pristine checkout: " + firstLine(err.Error()), nil
	}
	defer cleanup()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return gatePatchTree(srcDir, commit, location, diff), nil
}

// gatePatchTree returns "" when the diff is acceptable, otherwise a one-line
// reason. The caller must supply a host-owned tree. Checks: diff parses; the
// tree resets to the scan's commit; every target file exists; the diff touches
// a file named in location; git apply --check accepts it.
func gatePatchTree(srcDir, commit, location, diff string) string {
	files, err := parseUnifiedDiff(diff)
	if err != nil {
		return "diff does not parse: " + err.Error()
	}
	if len(files) == 0 {
		return "diff has no file headers"
	}
	if out, err := resetPatchGateTree(srcDir, commit); err != nil {
		return "reset to scan commit: " + firstLine(out)
	}

	for _, df := range files {
		if df.NewFile {
			continue
		}
		if _, err := os.Stat(filepath.Join(srcDir, df.Path)); err != nil {
			return "diff targets missing file: " + df.Path
		}
	}

	if reason := checkLocationFile(files, location); reason != "" {
		return reason
	}

	if out, err := gitApplyCheck(srcDir, diff); err != nil {
		return "git apply --check: " + firstLine(out)
	}

	return ""
}

// checkLocationFile returns "" when the diff touches at least one file named
// in location, otherwise a one-line reason. It matches on file, not line: a
// fix often lands in a shared helper far from the flagged sink, so requiring a
// hunk to overlap the exact line wrongly rejects correct choke-point patches.
// git apply --check still guarantees the diff applies.
func checkLocationFile(files []diffFile, location string) string {
	want := locationPaths(location)
	if want == nil {
		return ""
	}
	for _, df := range files {
		if slices.Contains(want, df.Path) {
			return ""
		}
	}
	return "no patched file matches location " + location
}

type diffFile struct {
	Path    string
	NewFile bool
}

var hunkRE = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@`)

const maxDiffLineBytes = 4 << 20

// parseUnifiedDiff extracts target file paths from a unified diff, rejecting
// paths that escape the workspace and malformed hunk headers. It is
// deliberately minimal: enough to drive the gate, not a general diff library.
func parseUnifiedDiff(diff string) ([]diffFile, error) {
	var files []diffFile
	sawFrom := false
	newFile := false

	sc := bufio.NewScanner(strings.NewReader(diff))
	sc.Buffer(nil, maxDiffLineBytes)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "--- "):
			sawFrom = true
			newFile = strings.TrimPrefix(line, "--- ") == "/dev/null"
		case strings.HasPrefix(line, "+++ "):
			if !sawFrom {
				return nil, fmt.Errorf("+++ without preceding ---")
			}
			sawFrom = false
			to := strings.TrimPrefix(line, "+++ ")
			if i := strings.IndexByte(to, '\t'); i >= 0 {
				to = to[:i]
			}
			path := strings.TrimPrefix(to, "b/")
			if to == "/dev/null" {
				path = ""
			}
			if path != "" && !filepath.IsLocal(path) {
				return nil, fmt.Errorf("diff target escapes workspace: %q", path)
			}
			files = append(files, diffFile{Path: path, NewFile: newFile})
			newFile = false
		case strings.HasPrefix(line, "@@ "):
			if len(files) == 0 {
				return nil, fmt.Errorf("hunk header before any file header")
			}
			if !hunkRE.MatchString(line) {
				return nil, fmt.Errorf("bad hunk header: %q", line)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

// locPathRE matches a "path:N" reference inside a Finding.Location. The path
// class excludes the comma, parenthesis and trailing range that surround it in
// composite locations, so "logentry.go:106-135)" yields just "logentry.go".
var locPathRE = regexp.MustCompile(`([^\s,:()]+):\d+`)

// locationPaths returns the file paths a Finding.Location names. A location
// may list several files with line ranges and a "(data path: a -> b)" trace,
// e.g. "pkg/a.go:10-20, pkg/b.go:5 (data path: pkg/c.go -> pkg/d.go:30)"; we
// pull out every "path:line" reference. A location carrying no such reference
// is treated as a single bare path. Returns nil for an empty location.
func locationPaths(location string) []string {
	var paths []string
	for _, m := range locPathRE.FindAllStringSubmatch(location, -1) {
		paths = append(paths, m[1])
	}
	if paths == nil {
		if loc := strings.TrimSpace(location); loc != "" {
			paths = append(paths, loc)
		}
	}
	return paths
}

func resetPatchGateTree(srcDir, commit string) (string, error) {
	// The caller supplies a fresh host-owned copy. Keep reset and clean so every
	// applicability check starts from the commit the scan saw even if the shared
	// cache has advanced; neither command runs in the runner's checkout.
	for _, args := range [][]string{{"reset", "-q", "--hard", commit}, {"clean", "-qfd"}} {
		if out, err := exec.Command("git", append([]string{"-C", srcDir}, args...)...).CombinedOutput(); err != nil {
			return string(out), err
		}
	}
	return "", nil
}

func gitApplyCheck(srcDir, diff string) (string, error) {
	cmd := exec.Command("git", "-C", srcDir, "apply", "--check", "-")
	cmd.Stdin = strings.NewReader(diff)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
