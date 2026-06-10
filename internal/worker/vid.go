package worker

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const vidTimeout = 30 * time.Second

// vidLocRE matches a finding location ("file.rb:12", "file.rb:12-34",
// "file.js:42:7") and captures the path and the first line number.
// Ranges and columns collapse to the opening line, mirroring how the
// web code browser links resolve the same strings.
var vidLocRE = regexp.MustCompile(`^(.*?):(\d+)(?:-\d+)?(?::\d+(?:-\d+)?)?$`)

// vidSinks turns a finding's newline-joined Locations into the
// file:line arguments the vid CLI expects, keeping only entries that
// resolve to a real file inside srcDir. Model output is untrusted, so
// paths that escape the checkout are dropped rather than read; the
// checkout may contain hostile symlinks, so containment is checked on
// the symlink-resolved path, not the lexical one.
func vidSinks(srcDir, locations string) []string {
	root, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for loc := range strings.SplitSeq(locations, "\n") {
		loc = strings.TrimPrefix(strings.TrimSpace(loc), "./")
		m := vidLocRE.FindStringSubmatch(loc)
		if m == nil {
			continue
		}
		path, line := m[1], m[2]
		if path == "" || !filepath.IsLocal(path) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(filepath.Join(srcDir, path))
		if err != nil || !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			continue
		}
		if fi, err := os.Stat(resolved); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		sink := path + ":" + line
		if seen[sink] {
			continue
		}
		seen[sink] = true
		out = append(out, sink)
	}
	return out
}

// computeVID shells out to the vid CLI (github.com/andrew/VID) to hash
// the code at the finding's sink locations into a portable identifier.
// Returns "" when no location resolves to a file in srcDir, the binary
// is missing, or the run fails; callers treat an empty VID as
// not-computed rather than an error, since the finding itself is still
// valid without one.
func (w *Worker) computeVID(srcDir, locations string) string {
	sinks := vidSinks(srcDir, locations)
	if len(sinks) == 0 {
		return ""
	}
	cmdName := w.VIDCommand
	if cmdName == "" {
		cmdName = "vid"
	}
	bin, err := exec.LookPath(cmdName)
	if err != nil {
		w.vidMissingOnce.Do(func() {
			w.Log.Warn("vid binary not found, findings will not get VIDs", "command", cmdName)
		})
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), vidTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, sinks...)
	cmd.Dir = srcDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		w.Log.Warn("compute vid", "sinks", strings.Join(sinks, " "), "err", err, "stderr", strings.TrimSpace(stderr.String()))
		return ""
	}
	v := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(v, "VID-") {
		return ""
	}
	return v
}
