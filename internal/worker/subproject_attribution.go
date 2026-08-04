package worker

import (
	"strings"

	"scrutineer/internal/db"
)

// normalizePkgName folds a manifest or registry package name to a match key:
// lowercased, trimmed, with '_' folded to '-' (PyPI treats them the same).
// Deliberately conservative — over-normalising risks linking the wrong
// sub-package.
func normalizePkgName(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
}

func uintPtrEq(a, b *uint) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// reconcileSubprojectLinks re-attributes a repository's published packages and
// advisories to the sub-package they belong to, matched by manifest name. It
// is the join the flat repository→packages/advisories model lacks: a monorepo
// like rails/rails gets one Package row per gem, and this points each at the
// Subproject whose manifest name (or, failing that, directory basename)
// matches. Idempotent and cheap; the caller re-runs it (gated on
// Worker.MonorepoAttribution) after any packages/advisories/subprojects
// change. A package or advisory that matches no subproject is set back to
// repo-level (SubprojectID NULL), so removing a subproject — or turning a
// monorepo back into a single-package repo — self-heals.
func (w *Worker) reconcileSubprojectLinks(repoID uint) error {
	var subs []db.Subproject
	if err := w.DB.Where("repository_id = ?", repoID).Find(&subs).Error; err != nil {
		return err
	}
	// Index by manifest name first; add a directory-basename fallback only
	// where a manifest name did not already claim the key, so an explicit name
	// always wins over a coincidental directory match. Size for both keys.
	const keysPerSubproject = 2
	byName := make(map[string]uint, len(subs)*keysPerSubproject)
	for _, s := range subs {
		if s.Name != "" {
			byName[normalizePkgName(s.Name)] = s.ID
		}
	}
	for _, s := range subs {
		seg := s.Path
		if i := strings.LastIndex(seg, "/"); i >= 0 {
			seg = seg[i+1:]
		}
		key := normalizePkgName(seg)
		if key == "" {
			continue
		}
		if _, ok := byName[key]; !ok {
			byName[key] = s.ID
		}
	}

	var pkgs []db.Package
	if err := w.DB.Where("repository_id = ?", repoID).Find(&pkgs).Error; err != nil {
		return err
	}
	for i := range pkgs {
		p := &pkgs[i]
		var sid *uint
		if id, ok := byName[normalizePkgName(p.Name)]; ok {
			v := id
			sid = &v
		}
		if uintPtrEq(p.SubprojectID, sid) {
			continue
		}
		if err := w.DB.Model(&db.Package{}).Where("id = ?", p.ID).
			Updates(map[string]any{"subproject_id": sid}).Error; err != nil {
			return err
		}
	}

	var advs []db.Advisory
	if err := w.DB.Where("repository_id = ?", repoID).Find(&advs).Error; err != nil {
		return err
	}
	for i := range advs {
		a := &advs[i]
		var sid *uint
		for _, name := range strings.Split(a.Packages, ",") {
			if id, ok := byName[normalizePkgName(name)]; ok {
				v := id
				sid = &v
				break
			}
		}
		if uintPtrEq(a.SubprojectID, sid) {
			continue
		}
		if err := w.DB.Model(&db.Advisory{}).Where("id = ?", a.ID).
			Updates(map[string]any{"subproject_id": sid}).Error; err != nil {
			return err
		}
	}
	return nil
}

// reconcileSubprojectLinksIfEnabled runs reconcileSubprojectLinks when
// per-subproject attribution is enabled, logging (not failing the scan) on
// error. Called from the packages/advisories/subprojects parsers so a change
// to any of the three re-derives the links.
func (w *Worker) reconcileSubprojectLinksIfEnabled(repoID uint) {
	if !w.MonorepoAttribution {
		return
	}
	if err := w.reconcileSubprojectLinks(repoID); err != nil {
		w.Log.Warn("reconcile subproject links", "repo", repoID, "err", err)
	}
}
