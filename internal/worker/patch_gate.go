package worker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

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
// on pass, writes Finding.SuggestedFix and Finding.SuggestedFixCommit via
// WriteFindingField so the change is recorded in FindingHistory. A gate
// failure is not a scan error: the scan completed and the diff is in
// Scan.Report; we just decline to promote it onto the finding.
func (w *Worker) parsePatchOutput(scan *db.Scan, report string, emit func(Event)) error {
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

	var f db.Finding
	if err := w.DB.First(&f, *scan.FindingID).Error; err != nil {
		return fmt.Errorf("load finding %d: %w", *scan.FindingID, err)
	}

	srcDir := filepath.Join(w.scanWorkRoot(scan), "src")
	if reason := gatePatch(srcDir, f.Location, rep.Patch); reason != "" {
		emit(Event{Kind: KindText, Text: "patch: gate rejected: " + reason})
		return nil
	}

	if err := db.WriteFindingField(w.DB, f.ID, "suggested_fix", rep.Patch, db.SourceModel, "patch"); err != nil {
		return fmt.Errorf("write suggested_fix: %w", err)
	}
	if err := db.WriteFindingField(w.DB, f.ID, "suggested_fix_commit", rep.BaseCommit, db.SourceModel, "patch"); err != nil {
		return fmt.Errorf("write suggested_fix_commit: %w", err)
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("patch: gate passed, wrote suggested_fix on finding %d", f.ID)})
	return nil
}

// gatePatch returns "" when the diff is acceptable, otherwise a one-line
// reason. Checks: diff parses; every target file exists under srcDir; the
// diff touches a file named in location; git apply --check accepts it.
func gatePatch(srcDir, location, diff string) string {
	files, err := parseUnifiedDiff(diff)
	if err != nil {
		return "diff does not parse: " + err.Error()
	}
	if len(files) == 0 {
		return "diff has no file headers"
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

func gitApplyCheck(srcDir, diff string) (string, error) {
	// The patch skill captures its diff with `git diff HEAD` and leaves the
	// edits applied in srcDir; it never reverts. Re-applying an already-applied
	// diff always fails, so reset the per-scan copy to HEAD first. reset --hard
	// clears the skill's `git add -N` index entries; clean -fd drops any new
	// files it created so a /dev/null hunk can recreate them.
	for _, args := range [][]string{{"reset", "-q", "--hard", "HEAD"}, {"clean", "-qfd"}} {
		if out, err := exec.Command("git", append([]string{"-C", srcDir}, args...)...).CombinedOutput(); err != nil {
			return string(out), err
		}
	}
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
