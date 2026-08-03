package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
)

// scanScopeHard reports whether this scan should be hard-scoped: its workspace
// pruned down to SubPath so the agent, its build, and its findings are confined
// to a single sub-package. Only a sub-path scan is ever hard — a root scan has
// nothing to prune. Finding-scoped runs (verify/patch/disclose) stay soft
// because they need the whole checkout and its .git to diff, apply, and
// validate a fix. Otherwise the per-scan ScopeMode wins, falling back to the
// instance default (Worker.SubprojectScope); an unset default is soft, so a
// programmatically-constructed worker keeps the pre-monorepo whole-tree
// behaviour until the operator opts into hard scoping.
func (w *Worker) scanScopeHard(scan *db.Scan) bool {
	if scan.SubPath == "" || scan.FindingID != nil {
		return false
	}
	mode := scan.ScopeMode
	if mode == "" {
		mode = w.SubprojectScope
	}
	return mode == "hard"
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
