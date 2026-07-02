package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"scrutineer/internal/db"
)

// dependentCacheRoot returns the shared on-disk path scrutineer reuses
// across exposure scans of the same dependent URL. Keyed by sha256 of the
// URL so different URLs cannot collide and the path is filesystem-safe.
// The directory survives wrap()'s per-scan workspace cleanup, so the
// second exposure scan on the same dependent only fetches the delta.
func dependentCacheRoot(dataDir, url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(dataDir, "dependent-cache", hex.EncodeToString(sum[:]))
}

// cacheMutex returns the per-URL mutex used to serialise fetch+copy on
// the dependent cache. Lazily created on first use.
func (w *Worker) cacheMutex(url string) *sync.Mutex {
	v, _ := w.cacheMu.LoadOrStore(url, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// prepareDependentSrc updates the shared dependent cache for url under a
// per-URL lock, then copies it into workRoot/src so the skill operates
// on its own tree. The cache survives across scans; the per-scan copy
// is whatever the skill leaves behind. Returns the HEAD commit of the
// freshly-synced cache.
func (w *Worker) prepareDependentSrc(ctx context.Context, url, ref, workRoot string, emit func(Event)) (string, error) {
	mu := w.cacheMutex(url)
	mu.Lock()
	defer mu.Unlock()

	cacheRoot := dependentCacheRoot(w.DataDir, url)
	if err := os.MkdirAll(cacheRoot, dirPerm); err != nil {
		return "", err
	}
	cacheSrc, err := ensureClone(ctx, db.Repository{URL: url}, cacheRoot, false, ref, emit)
	if err != nil {
		return "", err
	}
	commit := gitHead(cacheSrc)
	dst := filepath.Join(workRoot, "src")
	if err := os.RemoveAll(dst); err != nil {
		return "", err
	}
	if err := copyTree(cacheSrc, dst); err != nil {
		return "", fmt.Errorf("copy dependent cache: %w", err)
	}
	return commit, nil
}

// copyTree recursively copies src to dst, preserving permissions but not
// ownership or timestamps. Symlinks are recreated; everything else is
// copied byte-for-byte. Fast enough for git trees up to a few hundred MB.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case info.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			return copyFile(path, target, info.Mode().Perm())
		}
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// doExposure runs the exposure skill for one (finding, dependent) pair.
// The scan's Repository stays the library being audited; ./src in the
// workspace is a fresh copy of the shared dependent cache, so the
// skill cannot pollute the cache and concurrent scans against the same
// dependent serialise on a per-URL lock around the fetch. The skill
// returns one product_status verdict that is upserted into
// finding_dependents.
func (w *Worker) doExposure(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	if scan.FindingID == nil || scan.DependentID == nil {
		return "", fmt.Errorf("exposure scan %d missing finding_id or dependent_id", scan.ID)
	}
	if scan.SkillID == nil {
		return "", fmt.Errorf("exposure scan %d has no skill id", scan.ID)
	}
	var dep db.Dependent
	if err := w.DB.First(&dep, *scan.DependentID).Error; err != nil {
		return "", fmt.Errorf("load dependent %d: %w", *scan.DependentID, err)
	}
	if dep.RepositoryURL == "" {
		w.upsertExposure(scan, dep.ID, db.ExposureUnderInvestigation, "", "dependent has no repository URL", "")
		emit(Event{Kind: KindText, Text: "dependent has no repository URL; marked under_investigation"})
		return "", nil
	}
	var skill db.Skill
	if err := w.DB.First(&skill, *scan.SkillID).Error; err != nil {
		return "", fmt.Errorf("load skill %d: %w", *scan.SkillID, err)
	}
	scan.SkillName = skill.Name
	scan.SkillVersion = skill.Version
	w.DB.Model(scan).Updates(map[string]any{
		"skill_name":    skill.Name,
		"skill_version": skill.Version,
	})

	workRoot := w.scanWorkRoot(scan)
	if err := validateSkillPaths(skill.Name, skill.OutputFile); err != nil {
		return "", err
	}
	if err := os.MkdirAll(workRoot, dirPerm); err != nil {
		return "", err
	}
	cacheCommit, err := w.prepareDependentSrc(ctx, dep.RepositoryURL, scan.Ref, workRoot, emit)
	if err != nil {
		if _, ok := errors.AsType[*RepoUnreachableError](err); ok {
			w.upsertExposure(scan, dep.ID, db.ExposureUnderInvestigation, "", "dependent repository unreachable", "")
			emit(Event{Kind: KindError, Text: err.Error()})
			return "", nil
		}
		return "", err
	}
	scan.Commit = cacheCommit

	if err := applyPathFilters(workRoot, &skill, emit); err != nil {
		return "", fmt.Errorf("apply path filters: %w", err)
	}

	skillDir := w.Runner.SkillDir(workRoot, skill.Name)
	if err := stageContext(workRoot, w.APIBase, w.ForkOrg, w.metadataDir(), scan, &scan.Repository); err != nil {
		return "", fmt.Errorf("stage context: %w", err)
	}
	if err := stageSkill(&skill, workRoot, skillDir); err != nil {
		return "", fmt.Errorf("stage skill: %w", err)
	}

	depRepo := db.Repository{URL: dep.RepositoryURL, Name: dep.Name}
	prompt := buildLoggedPrompt(&skill)
	scan.Prompt = prompt
	w.DB.Model(scan).Update("prompt", prompt)

	sj := SkillJob{
		Repo:            depRepo,
		ScanID:          scan.ID,
		WorkRoot:        workRoot,
		Model:           scan.Model,
		Effort:          scan.Effort,
		Name:            skill.Name,
		SkillDir:        skillDir,
		OutputFile:      skill.OutputFile,
		Ref:             scan.Ref,
		MaxTurns:        w.resolveMaxTurns(skill.MaxTurns),
		AllowedTools:    skill.AllowedTools,
		SrcReady:        true,
		Profile:         scan.Profile,
		RequiresProfile: skill.RequiresProfile,
	}
	w.applyResume(scan, &sj, emit)
	res, err := w.Runner.RunSkill(ctx, sj, emit)
	w.applySkillResult(scan, res)
	if err != nil {
		if _, ok := errors.AsType[*MaxTurnsReachedError](err); ok && res.Report != "" {
			// Same best-effort parse-the-partial pattern as doSkill: keep
			// propagating the original err but surface parse failures so a
			// silently-malformed exposure report doesn't vanish.
			if perr := w.parseExposureOutput(&skill, scan, dep.ID, res.Report, emit); perr != nil {
				w.Log.Warn("parse partial exposure output after max turns", "scan", scan.ID, "dependent", dep.ID, "err", perr)
			}
		}
		return res.Report, err
	}
	if res.Report != "" {
		if perr := w.parseExposureOutput(&skill, scan, dep.ID, res.Report, emit); perr != nil {
			return res.Report, perr
		}
	} else {
		w.upsertExposure(scan, dep.ID, db.ExposureUnderInvestigation, "", "skill produced no report", res.Commit)
	}
	return res.Report, nil
}

// parseExposureOutput reads the one-shot verdict produced by the exposure
// skill and upserts a finding_dependents row. Unknown status values fall
// back to under_investigation; invalid justification labels are dropped.
func (w *Worker) parseExposureOutput(skill *db.Skill, scan *db.Scan, depID uint, report string, emit func(Event)) error {
	if skill.SchemaJSON != "" {
		if detail := ValidateReportSchema(skill.SchemaJSON, report); detail != "" {
			emit(Event{Kind: KindError, Text: "schema: report.json does not validate against schema.json:\n" + detail})
			if w.SchemaStrict {
				return &SchemaValidationError{Skill: skill.Name, Detail: detail}
			}
		}
	}
	var r struct {
		Status        string `json:"status"`
		Justification string `json:"justification"`
		Rationale     string `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(report), &r); err != nil {
		return fmt.Errorf("parse exposure report: %w", err)
	}
	if !db.ValidExposureStatus(r.Status) {
		r.Status = db.ExposureUnderInvestigation
	}
	if r.Status != db.ExposureKnownNotAffected || !db.ValidExposureJustification(r.Justification) {
		r.Justification = ""
	}
	w.upsertExposure(scan, depID, r.Status, r.Justification, r.Rationale, scan.Commit)
	emit(Event{Kind: KindText, Text: fmt.Sprintf("recorded exposure: %s", r.Status)})
	return nil
}

func (w *Worker) upsertExposure(scan *db.Scan, depID uint, status, justification, rationale, commit string) {
	row := db.FindingDependent{
		FindingID:     *scan.FindingID,
		DependentID:   depID,
		Status:        status,
		Justification: justification,
		Rationale:     rationale,
		ScanID:        &scan.ID,
		ScanCommit:    commit,
	}
	var existing db.FindingDependent
	err := w.DB.Where("finding_id = ? AND dependent_id = ?", row.FindingID, row.DependentID).First(&existing).Error
	if err != nil {
		_ = w.DB.Create(&row).Error
		return
	}
	w.DB.Model(&existing).Updates(map[string]any{
		"status":        row.Status,
		"justification": row.Justification,
		"rationale":     row.Rationale,
		"scan_id":       row.ScanID,
		"scan_commit":   row.ScanCommit,
	})
}
