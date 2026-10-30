package worker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/ossscanner"
)

const (
	ossScannerDir        = "oss_scanner"
	ossScannerThreatFile = "threat_model.md"
	ossScannerDockerfile = "Dockerfile"
	// ossScannerRefresh bounds how often the registry clone is fetched, since
	// every verify scan consults it.
	ossScannerRefresh = time.Hour
	// ossScannerCacheDir keeps the registry clone apart from the default-branch
	// clone a repository scan of the same URL fetches and resets to its own ref.
	ossScannerCacheDir = "oss-scanner-registry"
)

// ossScannerRegistryRoot returns the registry checkout, or "" when the lookup
// is disabled. The cache clone is read in place, so the caller must keep it
// locked until it has finished reading and then call release.
func (w *Worker) ossScannerRegistryRoot(ctx context.Context, emit func(Event)) (root string, release func(), err error) {
	release = func() {}
	url := w.OSSScannerRegistry
	if url == "" {
		return "", release, nil
	}
	if w.PrepareOSSScannerRegistry != nil {
		root, err = w.PrepareOSSScannerRegistry(ctx, url, emit)
		return root, release, err
	}
	mu := w.cacheMutex(url)
	mu.Lock()
	defer func() {
		if err != nil {
			mu.Unlock()
		}
	}()
	cacheRoot := filepath.Join(RepoCacheRoot(w.DataDir, url), ossScannerCacheDir)
	src := filepath.Join(cacheRoot, "src")
	if fetched, ok := w.ossScannerFetched.Load(url); ok && time.Since(fetched.(time.Time)) < ossScannerRefresh {
		if _, statErr := os.Stat(filepath.Join(src, ".git")); statErr == nil {
			return src, mu.Unlock, nil
		}
	}
	if err = os.MkdirAll(cacheRoot, dirPerm); err != nil {
		return "", release, err
	}
	dir, err := ensureCloneWithOptions(ctx, db.Repository{URL: url}, cacheRoot, false, "", false, emit)
	if err != nil {
		return "", release, err
	}
	w.ossScannerFetched.Store(url, time.Now())
	return dir, mu.Unlock, nil
}

// attachOSSScanner stages the OSS Scanner files and records them in the
// context document, rewriting context.json when anything was found.
func (w *Worker) attachOSSScanner(
	ctx context.Context, workRoot, skillDir string, scan *db.Scan, skill *db.Skill, document *skillContext, emit func(Event),
) {
	staged := w.stageOSSScanner(ctx, workRoot, scan, skill, emit)
	if staged == nil {
		return
	}
	document.Scrutineer.OSSScanner = staged
	if err := writeSkillContext(workRoot, skillDir, *document); err != nil {
		w.ossScannerWarn(emit, "could not record enrolment in context.json", err)
	}
}

func (w *Worker) ossScannerWarn(emit func(Event), what string, err error) {
	emit(Event{Kind: KindText, Text: fmt.Sprintf("oss-scanner: %s (%v); continuing without it", what, err)})
	if w.Log != nil {
		w.Log.Warn("oss-scanner", slog.String("what", what), slog.Any("err", err))
	}
}

// stageOSSScanner looks the scanned repository up in the OSS Scanner registry
// and copies the maintainer threat model and Dockerfile into
// workRoot/oss_scanner/ for the threat-model and verify skills. It never fails
// the scan and returns nil when nothing applies. An empty OSSScannerRegistry
// disables it entirely, including the repository's own .oss-scanner/ files.
func (w *Worker) stageOSSScanner(
	ctx context.Context, workRoot string, scan *db.Scan, skill *db.Skill, emit func(Event),
) *skillContextOSSScanner {
	if w.OSSScannerRegistry == "" {
		return nil
	}
	if skill.Name != threatModelSkillName && skill.Name != verifySkillName {
		return nil
	}
	registryRoot := ""
	if !scan.Repository.IsLocal() {
		root, release, err := w.ossScannerRegistryRoot(ctx, emit)
		defer release()
		if err != nil {
			w.ossScannerWarn(emit, "registry unavailable", err)
		} else {
			registryRoot = root
		}
	}
	srcRoot := filepath.Join(workRoot, "src")
	enrollment, err := ossscanner.Resolve(registryRoot, srcRoot, scan.Repository.URL)
	if err != nil {
		w.ossScannerWarn(emit, "lookup failed", err)
		return nil
	}
	if enrollment == nil {
		return nil
	}
	out := &skillContextOSSScanner{Enrollment: *enrollment}
	if enrollment.Registry {
		out.RegistryURL = w.OSSScannerRegistry
	}
	out.ThreatModelFile = w.copyOSSScannerFile(workRoot, registryRoot, srcRoot, enrollment.ThreatModel, ossScannerThreatFile, emit)
	out.DockerfileFile = w.copyOSSScannerFile(workRoot, registryRoot, srcRoot, enrollment.Dockerfile, ossScannerDockerfile, emit)
	emit(Event{Kind: KindText, Text: ossScannerSummary(enrollment)})
	return out
}

// copyOSSScannerFile returns the workspace-relative path of the staged copy,
// or "" when src is nil or the copy failed.
func (w *Worker) copyOSSScannerFile(
	workRoot, registryRoot, srcRoot string, src *ossscanner.Source, name string, emit func(Event),
) string {
	if src == nil {
		return ""
	}
	data, err := ossscanner.ReadSource(registryRoot, srcRoot, src)
	if err != nil {
		w.ossScannerWarn(emit, "skipping "+src.Path, err)
		return ""
	}
	rel := path.Join(ossScannerDir, name)
	if err := replaceWorkspaceFile(workRoot, filepath.FromSlash(rel), data); err != nil {
		w.ossScannerWarn(emit, "could not stage "+src.Path, err)
		return ""
	}
	return rel
}

func ossScannerSummary(e *ossscanner.Enrollment) string {
	if !e.Registry {
		return "oss-scanner: .oss-scanner files found in repository"
	}
	msg := fmt.Sprintf("oss-scanner: enrolled as %s (registry)", e.Project)
	if e.ThreatModel != nil {
		msg += fmt.Sprintf("; threat model from %s %s", e.ThreatModel.Origin, e.ThreatModel.Path)
	}
	if e.Dockerfile != nil {
		msg += fmt.Sprintf("; Dockerfile from %s %s", e.Dockerfile.Origin, e.Dockerfile.Path)
	}
	return msg
}
