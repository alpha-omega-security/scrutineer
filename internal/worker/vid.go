package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	vidTimeout       = 30 * time.Second
	vidStageDirMode  = 0o700
	vidStageFileMode = 0o600
)

// vidLocRE matches a finding location ("file.rb:12", "file.rb:12-34",
// "file.js:42:7") and captures the path and the first line number.
// Ranges and columns collapse to the opening line, mirroring how the
// web code browser links resolve the same strings.
var vidLocRE = regexp.MustCompile(`^(.*?):(\d+)(?:-\d+)?(?::\d+(?:-\d+)?)?$`)

// vidSinks turns a finding's newline-joined Locations into the
// file:line arguments the vid CLI expects, keeping only entries that
// resolve to a real file inside srcDir. Model output is untrusted, so paths
// that escape the checkout are dropped rather than read. The descriptor-rooted
// lookup confines hostile symlinks even if a runner changes them concurrently.
func vidSinks(srcDir, locations string) []string {
	root := openSourceRoot(srcDir)
	if root == nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	return vidSinksFromRoot(root, locations)
}

func vidSinksFromRoot(root *os.Root, locations string) []string {
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
		f, err := root.Open(path)
		if err != nil {
			continue
		}
		info, statErr := f.Stat()
		_ = f.Close()
		if statErr != nil || !info.Mode().IsRegular() {
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
	sourceRoot := openSourceRoot(srcDir)
	if sourceRoot == nil {
		return ""
	}
	defer func() { _ = sourceRoot.Close() }()
	sinks := vidSinksFromRoot(sourceRoot, locations)
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
	stageDir, err := os.MkdirTemp("", "scrutineer-vid-")
	if err != nil {
		return ""
	}
	defer func() { _ = os.RemoveAll(stageDir) }()
	stageRoot, err := os.OpenRoot(stageDir)
	if err != nil {
		return ""
	}
	defer func() { _ = stageRoot.Close() }()
	staged := map[string]bool{}
	for _, sink := range sinks {
		match := vidLocRE.FindStringSubmatch(sink)
		if match == nil {
			return ""
		}
		path := match[1]
		if staged[path] {
			continue
		}
		if err := stageVIDFile(sourceRoot, stageRoot, path); err != nil {
			return ""
		}
		staged[path] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), vidTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append([]string{"--"}, sinks...)...)
	cmd.Dir = stageDir
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

func stageVIDFile(sourceRoot, stageRoot *os.Root, path string) error {
	in, err := sourceRoot.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return os.ErrInvalid
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := stageRoot.MkdirAll(dir, vidStageDirMode); err != nil {
			return err
		}
	}
	out, err := stageRoot.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, vidStageFileMode)
	if errors.Is(err, fs.ErrExist) {
		// The staging directory is private and fresh, so an entry that already
		// exists is this file under another spelling of its path: two sinks
		// that differ only in case on a case-insensitive filesystem name the
		// same source file, and its copy is already in place.
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
