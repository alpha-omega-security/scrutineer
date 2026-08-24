package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
)

// repoWideProjectionKinds are skill output kinds whose result describes the
// whole repository regardless of which sub-folder was requested: the sub-project
// map itself, registry data (packages, advisories, dependencies), repository
// metadata, disclosure maintainers, posture, and the repo-scoped finding dedup.
// A sub-path scan of one of these must never hard-scope. Pruning the workspace
// to the sub-folder would make the skill re-project the whole repository from a
// partial view, and the matching parser then replaces the repo-level set with
// that fragment — parseSubprojectsOutput and parseDependenciesOutput
// delete-and-replace per repository, and parseMaintainersOutput replaces the
// repository's maintainer associations — so a single scoped run would wipe every
// sibling's rows. These skills also read local files or query by repository URL
// rather than building anything, so hard scope's isolation buys them nothing.
//
// Any new output kind whose parser writes repository-level rows must be added
// here; TestRepoWideProjectionKinds_everyOutputKindClassified fails if a kind in
// skills.OutputKinds is left unclassified, so a new repo-wide parser cannot
// silently default to hard-scopable. The opt-out is the primary guard;
// parseSubprojectsOutput and parseMaintainersOutput add a second, write-side
// guard that no-ops a scoped run. parseDependenciesOutput is deliberately
// opt-out only — Dependency has no per-subproject partition, so a blunt
// scoped-skip would also drop legitimate whole-tree refreshes — so if the
// dependencies skill is ever made sub-path-aware it must gain that partition
// (or a write-side guard) first, or a scoped run will wipe the repo's other
// dependencies; see the note on parseDependenciesOutput.
var repoWideProjectionKinds = map[string]bool{
	"subprojects":   true,
	"dependencies":  true,
	"packages":      true,
	"advisories":    true,
	"maintainers":   true,
	"repo_metadata": true,
	"repo_overview": true,
	"posture":       true,
	"finding_dedup": true,
}

// scanScopeHard reports whether this scan should be hard-scoped: its workspace
// pruned down to SubPath so the agent, its build, and its findings are confined
// to a single sub-package. Only a sub-path scan is ever hard — a root scan has
// nothing to prune. Finding-scoped runs (verify/patch/disclose) stay soft
// because they need the whole checkout and its .git to diff, apply, and
// validate a fix; diff rescans stay soft too, since pruning the siblings would
// make them show up as deletions against the full-tree baseline and poison the
// diff. Repo-wide projection skills (repoWideProjectionKinds) stay soft as well:
// their result covers the whole repository irrespective of the requested
// sub-folder, and hard-scoping one would let its wholesale-replace parser
// destroy every other sub-package's rows. Otherwise the per-scan ScopeMode wins,
// falling back to the instance default (Worker.SubprojectScope); an unset
// default is soft, so a programmatically-constructed worker keeps the
// pre-monorepo whole-tree behaviour until the operator opts into hard scoping.
func (w *Worker) scanScopeHard(scan *db.Scan, outputKind string) bool {
	if scan.SubPath == "" || scan.FindingID != nil || scan.RescanMode == "diff" || repoWideProjectionKinds[outputKind] {
		return false
	}
	mode := scan.ScopeMode
	if mode == "" {
		mode = w.SubprojectScope
	}
	return mode == "hard"
}

// prepareSkillSource applies every source-tree transformation after checkout
// and before the skill workspace is rendered. Keeping the ordering here is
// important: remediation patches apply to the same filtered tree the skill
// inspects, after diff and focus-area inputs have been resolved.
func (w *Worker) prepareSkillSource(ctx context.Context, workRoot string, scan *db.Scan, skill *db.Skill, emit func(Event)) (bool, error) {
	// Hard scope stays outside PrepareSrc so local and remote repositories use
	// identical semantics and the soft fallback can re-stage the whole tree.
	hardScope := w.scanScopeHard(scan, skill.OutputKind)
	if hardScope {
		if err := pruneToSubPath(filepath.Join(workRoot, "src"), scan.SubPath); err != nil {
			return false, fmt.Errorf("hard-scope sub_path: %w", err)
		}
	}
	if err := w.prepareDiffRescan(ctx, scan, workRoot, emit); err != nil {
		return false, err
	}
	focusArea, err := scanFocusArea(scan)
	if err != nil {
		return false, err
	}
	if err := applyRepositoryPathFilters(workRoot, skill, scan.Repository.ScanConfig, emit); err != nil {
		return false, fmt.Errorf("apply path filters: %w", err)
	}
	if focusArea != nil {
		if err := applyFocusAreaPathFilter(workRoot, *focusArea, emit); err != nil {
			return false, fmt.Errorf("apply focus-area path filter: %w", err)
		}
	}
	if err := w.prepareRemediationWorkspace(workRoot, scan, skill); err != nil {
		return false, fmt.Errorf("stage remediation inputs: %w", err)
	}
	return hardScope, nil
}

// pruneToSubPath removes everything under srcDir except the given sub-path and
// the repository's top-level .git, so a hard-scoped subproject scan physically
// sees only that sub-package. Keeping .git means git-based skills still work
// (rooted at ./src); `git status` will report the pruned siblings as deleted,
// which is expected under hard scope. The sub-path stays at its original
// location (./src/<subPath>) so every downstream consumer — profile detection,
// context.json scan_subpath, finding-location reconstruction — is unchanged
// between hard and soft. Returns an error if subPath does not exist.
func pruneToSubPath(srcDir, subPath string) error {
	clean, err := CleanSubPath(subPath)
	if err != nil {
		return err
	}
	if clean == "" {
		return nil
	}
	full := filepath.Join(srcDir, filepath.FromSlash(clean))
	if _, err := os.Stat(full); err != nil {
		return fmt.Errorf("sub_path %q not found in repository: %w", clean, err)
	}
	// Walk the keep-path one level at a time, deleting siblings that are not
	// the next component (and, at the repo root, not .git).
	parts := strings.Split(clean, "/")
	cur := srcDir
	for i, part := range parts {
		entries, err := os.ReadDir(cur)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Name() == part {
				continue
			}
			if i == 0 && e.Name() == ".git" {
				continue
			}
			if err := os.RemoveAll(filepath.Join(cur, e.Name())); err != nil {
				return err
			}
		}
		cur = filepath.Join(cur, part)
	}
	return nil
}

// depResolutionMarkers are lowercased substrings that identify a package
// manager failing to resolve dependencies, across the ecosystems scrutineer
// profiles cover.
var depResolutionMarkers = []string{
	// bundler / rubygems
	"could not find compatible versions",
	"bundler could not",
	"could not find gem",
	"unable to find a spec",
	// npm / yarn / pnpm
	"eresolve",
	"unable to resolve dependency tree",
	"no matching version found",
	// pip / poetry / uv
	"could not find a version that satisfies",
	"resolutionimpossible",
	"no matching distribution",
	// cargo
	"failed to select a version",
	"no matching package named",
	// go modules
	"no required module provides package",
	"missing go.sum entry",
	// opam / dune
	"no solution found, exiting",
	"the following dependencies couldn't be met",
	"is not a valid versioned package name",
	// composer / maven / generic
	"your requirements could not be resolved",
	"could not resolve dependencies",
	"failed to resolve dependencies",
	"unable to resolve dependencies",
}

// reStageWholeTree re-populates workRoot/src with the entire clone (undoing a
// hard-scope prune) and re-applies path filters, so a widened re-run sees the
// whole repository. Used by the automatic soft fallback in doSkill.
func (w *Worker) reStageWholeTree(ctx context.Context, scan *db.Scan, skill *db.Skill, workRoot string, emit func(Event)) error {
	if scan.Repository.IsLocal() {
		if err := prepareLocalSrc(scan.Repository.LocalPath(), workRoot, emit); err != nil {
			return err
		}
	} else if _, err := w.PrepareSrc(ctx, scan.Repository.URL, scan.Ref, workRoot, emit); err != nil {
		return err
	}
	return applyRepositoryPathFilters(workRoot, skill, scan.Repository.ScanConfig, emit)
}

// isDependencyResolutionFailure reports whether text looks like a package
// manager failing to resolve dependencies — the signal that a hard-scoped
// sub-package could not build in isolation, typically because it needs a
// sibling package that is unpublished or not at the required version, so the
// scan should widen to the whole tree. Deliberately narrow: an ordinary
// compile/build/test error is a real finding, not a scoping artifact, and must
// not trigger the fallback.
//
// This is a substring match over the agent's streamed narration by necessity,
// not laziness: the harness discards raw tool results (see harness claude.go's
// "user" role case), so a package manager's stderr only reaches us if the model
// re-narrates it. The known cost: an audit whose own source quotes one of these
// markers (a package manager, or error-handling that mirrors these strings)
// could trip a spurious whole-tree re-run. That is cost-only and confined to
// hard-scoped sub-package scans, so it is accepted rather than papered over with
// a heuristic that risks missing a real resolver failure — the false negative is
// worse than the redundant run.
func isDependencyResolutionFailure(text string) bool {
	if text == "" {
		return false
	}
	low := strings.ToLower(text)
	for _, m := range depResolutionMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}
