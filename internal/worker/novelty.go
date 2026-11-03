package worker

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
)

const (
	revalidateSkillName  = "revalidate"
	noveltyLogMaxCommits = 20
	noveltyLogMaxBytes   = 64 * 1024
	// noveltyLogReadCap bounds how much git log --patch output the host
	// buffers before truncateNoveltyLog trims it for display. git() uses
	// CombinedOutput, which would otherwise retain the whole patch stream
	// of a large single file across up to noveltyLogMaxCommits revisions.
	noveltyLogReadCap       = 4 * noveltyLogMaxBytes
	noveltyUnavailableNoGit = "repository history is unavailable"
)

type skillContextNovelty struct {
	State         db.FindingNovelty `json:"state"`
	ScannedCommit string            `json:"scanned_commit,omitempty"`
	CheckedCommit string            `json:"checked_commit,omitempty"`
	FindingFile   string            `json:"finding_file,omitempty"`
	FileChanged   bool              `json:"file_changed"`
	CommitLog     string            `json:"commit_log,omitempty"`
	LogTruncated  bool              `json:"log_truncated,omitempty"`
	NotCheckedWhy string            `json:"not_checked_reason,omitempty"`
}

func (w *Worker) noveltyContext(
	ctx context.Context,
	workRoot string,
	scan *db.Scan,
	skill *db.Skill,
) (*skillContextNovelty, error) {
	if skill.Name != revalidateSkillName || scan.FindingID == nil {
		return nil, nil
	}

	var finding db.Finding
	if err := w.DB.First(&finding, *scan.FindingID).Error; err != nil {
		return nil, fmt.Errorf("load finding for novelty check: %w", err)
	}
	if finding.Status.Closed() {
		return nil, nil
	}

	novelty := checkFindingNovelty(ctx, filepath.Join(workRoot, "src"), &finding, scan.Commit)
	updates := map[string]any{"novelty": novelty.State}
	if novelty.State != db.FindingNoveltyNotChecked {
		now := w.now().UTC()
		updates["novelty_checked_commit"] = novelty.CheckedCommit
		updates["novelty_checked_at"] = &now
	}
	if err := w.DB.Model(&db.Finding{}).Where("id = ?", finding.ID).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("persist finding novelty: %w", err)
	}
	return novelty, nil
}

// prepareNoveltyHistory deepens the persistent clone cache before PrepareSrc
// snapshots it into the per-scan workspace. Fetch failures remain best-effort:
// checkFindingNovelty will mark the comparison not_checked if the historical
// commit is still unavailable.
func (w *Worker) prepareNoveltyHistory(ctx context.Context, scan *db.Scan, skill *db.Skill) {
	if skill.Name != revalidateSkillName || scan.FindingID == nil {
		return
	}
	var finding db.Finding
	if err := w.DB.Select("commit").First(&finding, *scan.FindingID).Error; err != nil {
		return
	}
	commit := strings.TrimSpace(finding.Commit)
	if !validGitOID(commit) {
		return
	}
	if err := w.EnsureCommit(ctx, scan.Repository.URL, commit); err != nil && w.Log != nil {
		w.Log.Warn("novelty history unavailable", "repo", scan.RepositoryID, "commit", commit, "err", err)
	}
}

func checkFindingNovelty(
	ctx context.Context,
	src string,
	finding *db.Finding,
	headCommit string,
) *skillContextNovelty {
	result := &skillContextNovelty{
		State:         db.FindingNoveltyNotChecked,
		ScannedCommit: strings.TrimSpace(finding.Commit),
		CheckedCommit: strings.TrimSpace(headCommit),
	}
	result.FindingFile = findingnorm.FindingPath(finding.SubPath, finding.Location)
	if result.FindingFile == "" {
		result.NotCheckedWhy = "finding location is not a repository-relative file"
		return result
	}
	if !validGitOID(result.ScannedCommit) || !validGitOID(result.CheckedCommit) {
		result.NotCheckedWhy = "scanned or checked commit is unavailable"
		return result
	}
	if !commitReachable(ctx, src, result.CheckedCommit) {
		result.NotCheckedWhy = noveltyUnavailableNoGit
		return result
	}
	if !commitReachable(ctx, src, result.ScannedCommit) {
		result.NotCheckedWhy = "scanned commit is unavailable from repository history"
		return result
	}
	if _, err := git(ctx, "-C", src, "merge-base", "--is-ancestor", result.ScannedCommit, result.CheckedCommit); err != nil {
		result.NotCheckedWhy = "scanned commit is not an ancestor of checked HEAD"
		return result
	}

	// FindingFile comes from a finding location, which an imported report
	// controls. git treats the pathspec after -- as a glob by default, so
	// a location of "*" or ":(glob)**" would widen a one-file history check
	// to the whole repository. --literal-pathspecs matches the path
	// verbatim, and unlike a :(literal) prefix it is not itself read as part
	// of the filename when GIT_LITERAL_PATHSPECS is set in the host env.
	revisionRange := result.ScannedCommit + ".." + result.CheckedCommit
	countOutput, err := git(ctx, "-C", src, "--literal-pathspecs", "rev-list", "--count", revisionRange, "--", result.FindingFile)
	if err != nil {
		result.NotCheckedWhy = "git history check failed"
		return result
	}
	commitCount, err := strconv.Atoi(strings.TrimSpace(countOutput))
	if err != nil {
		result.NotCheckedWhy = "git history check failed"
		return result
	}
	logOutput, outputTruncated, err := gitLimited(ctx, noveltyLogReadCap, "-C", src, "--literal-pathspecs", "log",
		fmt.Sprintf("--max-count=%d", noveltyLogMaxCommits),
		"--format=commit %H%nAuthorDate: %aI%nSubject: %s",
		"--patch", revisionRange, "--", result.FindingFile)
	if err != nil {
		result.NotCheckedWhy = "git history check failed"
		return result
	}
	if strings.TrimSpace(logOutput) == "" {
		result.State = db.FindingNoveltyUnfixed
		return result
	}

	result.State = db.FindingNoveltyUnclear
	result.FileChanged = true
	var bytesTruncated bool
	result.CommitLog, bytesTruncated = truncateNoveltyLog(logOutput)
	result.LogTruncated = bytesTruncated || outputTruncated || commitCount > noveltyLogMaxCommits
	return result
}

func validGitOID(value string) bool {
	if len(value) < 7 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// gitLimited runs a local git command keeping at most maxBytes of its stdout.
// Output beyond the cap is discarded rather than refused, so git completes
// without an EPIPE and the exit status still reflects the command. Reports
// whether output was discarded.
func gitLimited(ctx context.Context, maxBytes int, args ...string) (string, bool, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	w := &cappedWriter{limit: maxBytes}
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = gitWaitDelay
	if err := cmd.Run(); err != nil {
		return "", false, fmt.Errorf("git: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return w.buf.String(), w.truncated, nil
}

type cappedWriter struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	room := w.limit - w.buf.Len()
	if room <= 0 {
		w.truncated = w.truncated || len(p) > 0
		return len(p), nil
	}
	if len(p) > room {
		w.truncated = true
		w.buf.Write(p[:room])
		return len(p), nil
	}
	return w.buf.Write(p)
}

func truncateNoveltyLog(logOutput string) (string, bool) {
	if len(logOutput) <= noveltyLogMaxBytes {
		return logOutput, false
	}
	const marker = "\n[truncated]\n"
	prefix := logOutput[:noveltyLogMaxBytes-len(marker)]
	if newline := strings.LastIndexByte(prefix, '\n'); newline >= 0 {
		prefix = prefix[:newline]
	}
	return strings.ToValidUTF8(prefix, "") + marker, true
}
