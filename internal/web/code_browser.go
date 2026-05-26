package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// maxBrowserBytes caps the size of a single file rendered in the code
// browser; larger files render as a "too large" notice.
const maxBrowserBytes = 2 << 20

var commitRE = regexp.MustCompile(`^[0-9a-f]{4,40}$`)

// repoBlob reads one file via `git show <commit>:<path>` from the worker's
// repo-cache, so historical commits resolve even after rescans move HEAD.
func (s *Server) repoBlob(w http.ResponseWriter, r *http.Request) {
	id64, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad repository id", http.StatusBadRequest)
		return
	}
	commit := r.PathValue("commit")
	if !commitRE.MatchString(commit) {
		http.Error(w, "bad commit", http.StatusBadRequest)
		return
	}
	relPath := r.PathValue("path")
	cleanPath, ok := sanitizeBlobPath(relPath)
	if !ok {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}

	var repo db.Repository
	if err := s.DB.First(&repo, uint(id64)).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	cacheSrc := filepath.Join(worker.RepoCacheRoot(s.Worker.DataDir, repo.URL), "src")
	if _, err := os.Stat(filepath.Join(cacheSrc, ".git")); err != nil {
		s.render(w, r, "code_browser.html", map[string]any{
			"Repo":      repo,
			"Commit":    commit,
			"Path":      cleanPath,
			"Highlight": parseHighlight(r.URL.Query().Get("line")),
			"Missing":   true,
		})
		return
	}

	if err := s.Worker.EnsureCommit(r.Context(), repo.URL, commit); err != nil {
		s.render(w, r, "code_browser.html", map[string]any{
			"Repo":      repo,
			"Commit":    commit,
			"Path":      cleanPath,
			"Highlight": parseHighlight(r.URL.Query().Get("line")),
			"Error":     err.Error(),
		})
		return
	}

	content, binary, truncated, err := gitShowBlob(r.Context(), cacheSrc, commit, cleanPath)
	if err != nil {
		s.render(w, r, "code_browser.html", map[string]any{
			"Repo":      repo,
			"Commit":    commit,
			"Path":      cleanPath,
			"Highlight": parseHighlight(r.URL.Query().Get("line")),
			"Error":     err.Error(),
		})
		return
	}

	s.render(w, r, "code_browser.html", map[string]any{
		"Repo":      repo,
		"Commit":    commit,
		"Path":      cleanPath,
		"Highlight": parseHighlight(r.URL.Query().Get("line")),
		"Binary":    binary,
		"Truncated": truncated,
		"Content":   content,
		"Language":  highlightLang(cleanPath),
	})
}

// sanitizeBlobPath rejects absolute paths, traversal segments and NUL bytes,
// and returns the slash-form path safe to feed `git show <commit>:<path>`.
func sanitizeBlobPath(p string) (string, bool) {
	if p == "" || strings.ContainsRune(p, 0) || strings.HasPrefix(p, "/") {
		return "", false
	}
	p = strings.TrimPrefix(p, "./")
	if slices.Contains(strings.Split(p, "/"), "..") {
		return "", false
	}
	clean := path.Clean(p)
	if clean == "." || clean == "" {
		return "", false
	}
	return clean, true
}

// gitShowBlob runs `git show <commit>:<path>` and returns
// (content, isBinary, truncated, err). The read is capped at
// maxBrowserBytes+1 so the extra byte distinguishes "at the cap"
// from "truncated".
func gitShowBlob(ctx context.Context, repoDir, commit, blobPath string) (string, bool, bool, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "show", commit+":"+blobPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", false, false, err
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", false, false, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(stdout, maxBrowserBytes+1))
	if len(raw) > maxBrowserBytes {
		// Drain so git doesn't block on a full pipe before Wait.
		_, _ = io.Copy(io.Discard, stdout)
	}
	if waitErr := cmd.Wait(); waitErr != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return "", false, false, errors.New(msg)
	}
	if readErr != nil {
		return "", false, false, readErr
	}
	truncated := false
	if len(raw) > maxBrowserBytes {
		raw = raw[:maxBrowserBytes]
		truncated = true
	}
	if bytes.IndexByte(raw, 0) != -1 {
		return "", true, truncated, nil
	}
	return string(raw), false, truncated, nil
}

// parseHighlight decodes `line=N` or `line=N-M` into an inclusive range.
// Returns (0, 0) when missing or malformed.
func parseHighlight(raw string) [2]int {
	if raw == "" {
		return [2]int{0, 0}
	}
	if a, b, ok := strings.Cut(raw, "-"); ok {
		x, e1 := strconv.Atoi(a)
		y, e2 := strconv.Atoi(b)
		if e1 != nil || e2 != nil || x <= 0 || y < x {
			return [2]int{0, 0}
		}
		return [2]int{x, y}
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return [2]int{0, 0}
	}
	return [2]int{n, n}
}

// highlightLang returns the highlight.js language hint for path,
// or "" to let the library auto-detect.
func highlightLang(p string) string {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".go":
		return "go"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".rs":
		return "rust"
	case ".php":
		return "php"
	case ".c", ".h":
		return "c"
	case ".cc", ".cpp", ".cxx", ".hpp":
		return "cpp"
	case ".cs":
		return "csharp"
	case ".sh", ".bash":
		return "bash"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".xml", ".html":
		return "xml"
	case ".css":
		return "css"
	case ".sql":
		return "sql"
	case ".md":
		return "markdown"
	case ".toml":
		return "toml"
	}
	return ""
}
