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
	// vidStageMaxBytes bounds the total bytes copied from the scan-writable
	// workspace into host staging. A hostile scan can place a sparse file
	// in /work/src and name it as a sink; the host copy would otherwise
	// materialise its full logical size.
	vidStageMaxBytes = 64 << 20
)

var errVIDStageBudget = errors.New("vid staging byte budget exceeded")

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
		f, err := openSourceFile(root, path)
		if err != nil {
			continue
		}
		_ = f.Close()
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
	remaining := int64(vidStageMaxBytes)
	for _, sink := range sinks {
		match := vidLocRE.FindStringSubmatch(sink)
		if match == nil {
			return ""
		}
		path := match[1]
		if staged[path] {
			continue
		}
		if err := stageVIDFile(sourceRoot, stageRoot, path, &remaining); err != nil {
			if errors.Is(err, errVIDStageBudget) {
				w.Log.Warn("compute vid: staging byte budget exceeded", "sinks", strings.Join(sinks, " "))
			}
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

func stageVIDFile(sourceRoot, stageRoot *os.Root, path string, remaining *int64) error {
	in, err := openSourceFile(sourceRoot, path)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
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
	n, err := io.Copy(out, io.LimitReader(in, *remaining+1))
	if err != nil {
		_ = out.Close()
		return err
	}
	if n > *remaining {
		_ = out.Close()
		return errVIDStageBudget
	}
	*remaining -= n
	return out.Close()
}
