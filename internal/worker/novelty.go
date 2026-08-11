package worker

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
)

const (
	revalidateSkillName     = "revalidate"
	noveltyLogMaxCommits    = 20
	noveltyLogMaxBytes      = 64 * 1024
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

	revisionRange := result.ScannedCommit + ".." + result.CheckedCommit
	countOutput, err := git(ctx, "-C", src, "rev-list", "--count", revisionRange, "--", result.FindingFile)
	if err != nil {
		result.NotCheckedWhy = "git history check failed"
		return result
	}
	commitCount, err := strconv.Atoi(strings.TrimSpace(countOutput))
	if err != nil {
		result.NotCheckedWhy = "git history check failed"
		return result
	}
	logOutput, err := git(ctx, "-C", src, "log",
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
	result.LogTruncated = bytesTruncated || commitCount > noveltyLogMaxCommits
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
