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
	"strconv"
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

	srcDir := filepath.Join(w.workRoot(scan.ID), "src")
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
// reason. Checks: diff parses; every target file exists under srcDir; at
// least one hunk overlaps the line in location; git apply --check accepts it.
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

	if reason := checkLocationOverlap(files, location); reason != "" {
		return reason
	}

	if out, err := gitApplyCheck(srcDir, diff); err != nil {
		return "git apply --check: " + firstLine(out)
	}

	return ""
}

func checkLocationOverlap(files []diffFile, location string) string {
	locPath, start, end, ok := parseLocation(location)
	if !ok {
		return ""
	}
	for _, df := range files {
		if df.Path != locPath {
			continue
		}
		if start == 0 {
			return ""
		}
		for _, h := range df.Hunks {
			if h.OldStart <= end && h.OldStart+h.OldCount-1 >= start {
				return ""
			}
		}
	}
	if start == 0 {
		return "no hunk touches " + locPath
	}
	return fmt.Sprintf("no hunk overlaps %s:%d", locPath, start)
}

type diffFile struct {
	Path    string
	NewFile bool
	Hunks   []diffHunk
}

type diffHunk struct {
	OldStart int
	OldCount int
}

var hunkRE = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@`)

const maxDiffLineBytes = 4 << 20

// parseUnifiedDiff extracts target file paths and old-side hunk ranges from
// a unified diff. It is deliberately minimal: enough to drive the gate, not
// a general diff library.
func parseUnifiedDiff(diff string) ([]diffFile, error) {
	var files []diffFile
	var cur *diffFile
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
			cur = &files[len(files)-1]
			newFile = false
		case strings.HasPrefix(line, "@@ "):
			if cur == nil {
				return nil, fmt.Errorf("hunk header before any file header")
			}
			m := hunkRE.FindStringSubmatch(line)
			if m == nil {
				return nil, fmt.Errorf("bad hunk header: %q", line)
			}
			start, _ := strconv.Atoi(m[1])
			count := 1
			if m[2] != "" {
				count, _ = strconv.Atoi(m[2])
			}
			cur.Hunks = append(cur.Hunks, diffHunk{OldStart: start, OldCount: count})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

// parseLocation accepts "path/to/file.ext:N", "path/to/file.ext:N-M", or a
// bare path. Returns ok=false for anything else (empty, multiple colons that
// don't end in a line spec); callers treat that as "no overlap check".
func parseLocation(loc string) (path string, start, end int, ok bool) {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return "", 0, 0, false
	}
	i := strings.LastIndexByte(loc, ':')
	if i < 0 {
		return loc, 0, 0, true
	}
	spec := loc[i+1:]
	if lo, hi, found := strings.Cut(spec, "-"); found {
		a, errA := strconv.Atoi(lo)
		b, errB := strconv.Atoi(hi)
		if errA == nil && errB == nil && a > 0 && b >= a {
			return loc[:i], a, b, true
		}
	} else if n, err := strconv.Atoi(spec); err == nil && n > 0 {
		return loc[:i], n, n, true
	}
	return loc, 0, 0, true
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
